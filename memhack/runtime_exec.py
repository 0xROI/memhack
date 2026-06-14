"""
memhack.runtime_exec
─────────────────────
Executes the sanitizer-instrumented binary with a battery of crafted inputs
so that ASan / UBSan / TSan actually fire at runtime.

Strategy
────────
1.  Seed corpus  – known crash-inducing patterns (long strings, format chars,
    negative numbers, null bytes, shell metacharacters, …)
2.  Argument fuzzing  – feeds seeds as argv[1], argv[2], …
3.  Stdin fuzzing     – pipes seeds into the binary's stdin
4.  Environment probe – passes seeds in common env vars (USER, HOME, PATH, …)
5.  File input probe  – writes seed to a temp file; passes filename as argv[1]

Each invocation is run with a short timeout.  Sanitizer output on stderr is
captured and parsed into structured findings.

Sanitizer env vars set
──────────────────────
  ASAN_OPTIONS  halt_on_error=0   → don't abort on first error; collect all
                detect_leaks=1    → also enable LeakSanitizer
  UBSAN_OPTIONS print_stacktrace=1
  ASAN_SYMBOLIZER_PATH           → use llvm-symbolizer if present
"""

import os
import re
import shutil
import subprocess
import tempfile
import itertools
from pathlib import Path
from typing import List, Dict, Optional

from memhack.utils import colour, Colour


# ── Sanitizer environment ─────────────────────────────────────────────────────

def _san_env() -> dict:
    env = os.environ.copy()
    env["ASAN_OPTIONS"]  = (
        "halt_on_error=0:"
        "detect_leaks=1:"
        "print_stats=0:"
        "log_path=stderr:"
        "exitcode=0"          # don't let non-zero exit mask output
    )
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=0:exitcode=0"
    env["TSAN_OPTIONS"]  = "halt_on_error=0:exitcode=0"

    # Use llvm-symbolizer for readable stack traces if available
    sym = shutil.which("llvm-symbolizer") or shutil.which("llvm-symbolizer-14")
    if sym:
        env["ASAN_SYMBOLIZER_PATH"] = sym

    return env


# ── Input seed corpus ─────────────────────────────────────────────────────────

def _build_seeds() -> List[bytes]:
    seeds = []

    # Buffer overflow candidates
    for length in (64, 128, 256, 512, 1024, 4096):
        seeds.append(b"A" * length)
        seeds.append(b"B" * length + b"\x00")

    # Format string payloads
    for fmt in ("%s", "%n", "%x", "%p", "%.1000d",
                "%s%s%s%s%s%s%s%s%s%s",
                "%99999d", "AAAA%08x.%08x.%08x.%08x"):
        seeds.append(fmt.encode())

    # Integer / sign edge cases
    for val in ("0", "-1", "2147483647", "2147483648",
                "-2147483648", "4294967295", "9999999999",
                "0x41414141", "NaN", "inf"):
        seeds.append(val.encode())

    # Shell metacharacters (command injection)
    for cmd in ("; id", "| id", "` id`", "$(id)",
                "; cat /etc/passwd", "&& id", "\n/bin/sh"):
        seeds.append(cmd.encode())

    # Null / special bytes
    seeds.append(b"\x00" * 8)
    seeds.append(b"\xff" * 32)
    seeds.append(b"\x41" * 32 + b"\x00\x00\x00\x00" + b"\x42" * 32)

    # Path traversal
    seeds.append(b"../../../etc/passwd")
    seeds.append(b"/dev/stdin")

    return seeds


# ── Sanitizer output parser ───────────────────────────────────────────────────

# Each pattern: (regex, severity, title, cwe)
_SAN_PATTERNS = [
    (r"heap-buffer-overflow",           "CRITICAL", "Heap buffer overflow",               "CWE-122"),
    (r"stack-buffer-overflow",          "CRITICAL", "Stack buffer overflow",               "CWE-121"),
    (r"global-buffer-overflow",         "CRITICAL", "Global buffer overflow",              "CWE-120"),
    (r"heap-use-after-free",            "CRITICAL", "Use-after-free",                      "CWE-416"),
    (r"heap-double-free|double-free",   "HIGH",     "Double-free",                         "CWE-415"),
    (r"use-after-return",               "HIGH",     "Use-after-return",                    "CWE-562"),
    (r"use-after-scope",                "HIGH",     "Use-after-scope",                     "CWE-562"),
    (r"stack-use-after-return",         "HIGH",     "Stack use-after-return",              "CWE-562"),
    (r"null-deref|null pointer",        "HIGH",     "Null pointer dereference",            "CWE-476"),
    (r"signed integer overflow",        "MEDIUM",   "Signed integer overflow",             "CWE-190"),
    (r"unsigned integer overflow",      "MEDIUM",   "Unsigned integer overflow",           "CWE-190"),
    (r"shift-out-of-bounds",            "MEDIUM",   "Shift out of bounds",                 "CWE-758"),
    (r"out-of-bounds",                  "HIGH",     "Out-of-bounds access",                "CWE-125"),
    (r"division-by-zero",               "MEDIUM",   "Division by zero",                    "CWE-369"),
    (r"invalid-bool-value",             "LOW",      "Invalid boolean value (UBSan)",       "CWE-758"),
    (r"misaligned-address",             "MEDIUM",   "Misaligned memory access",            "CWE-704"),
    (r"data race",                      "HIGH",     "Data race (TSan)",                    "CWE-362"),
    (r"detected memory leaks",          "MEDIUM",   "Memory leak (LeakSanitizer)",         "CWE-401"),
    (r"attempting.*free.*not.*malloc",  "HIGH",     "Free of non-heap memory",             "CWE-590"),
    (r"alloc-dealloc-mismatch",         "HIGH",     "Allocator/deallocator mismatch",      "CWE-762"),
]


def _extract_location(block: str) -> tuple:
    """Extract (file, line) from a sanitizer stack trace block."""
    # ASan format: #0 0xADDR in function /path/to/file.c:LINE:COL
    m = re.search(r"#0 .+? in \S+ (.+?\.(?:c|cpp|cc|cxx)):(\d+)", block)
    if m:
        return m.group(1), int(m.group(2))
    # UBSan format: /path/file.c:LINE:COL: runtime error: ...
    m = re.search(r"([^\s:]+\.(?:c|cpp|cc|cxx)):(\d+):\d+: runtime error", block)
    if m:
        return m.group(1), int(m.group(2))
    return "", 0


def _parse_sanitizer_stderr(stderr: str, input_repr: str) -> List[dict]:
    """Turn raw sanitizer stderr into structured finding dicts."""
    findings = []
    seen_titles = set()

    # Split on sanitizer "==" separator lines to get individual reports
    blocks = re.split(r"={10,}", stderr)

    for block in blocks:
        for pattern, severity, title, cwe in _SAN_PATTERNS:
            if re.search(pattern, block, re.IGNORECASE) and title not in seen_titles:
                seen_titles.add(title)
                file_path, line_no = _extract_location(block)

                # Grab the ERROR summary line for description
                summary_m = re.search(r"ERROR: \S+: (.+)", block)
                summary = summary_m.group(1).strip()[:200] if summary_m else title

                # Grab first few stack frames
                frames = re.findall(r"#\d+ .+", block)[:4]
                trace  = "\n".join(frames)

                findings.append({
                    "severity":    severity,
                    "title":       f"[Runtime] {title}",
                    "cwe":         cwe,
                    "description": (
                        f"{summary}\n"
                        f"Triggered by input: {input_repr}\n"
                        f"Stack trace:\n{trace}"
                    ),
                    "file":        file_path,
                    "line":        line_no,
                    "code":        "",
                    "mitigation":  _mitigation(title),
                    "source":      "runtime",
                })
    return findings


_MITIGATIONS = {
    "Heap buffer overflow":           "Use bounds-checked APIs; validate size before memcpy/strcpy.",
    "Stack buffer overflow":          "Increase buffer size or use dynamic allocation; replace gets/strcpy.",
    "Global buffer overflow":         "Audit global array accesses; add bounds checks.",
    "Use-after-free":                 "Set pointer to NULL after free(); use smart pointers in C++.",
    "Double-free":                    "Set pointer to NULL after free(); audit ownership.",
    "Null pointer dereference":       "Check return value of malloc/fopen before dereferencing.",
    "Signed integer overflow":        "Use strtol() with range checks; consider __builtin_add_overflow().",
    "Unsigned integer overflow":      "Add explicit range checks before arithmetic.",
    "Out-of-bounds access":           "Validate index against array length before access.",
    "Division by zero":               "Check divisor != 0 before division.",
    "Data race (TSan)":               "Add appropriate mutex/lock around shared variable access.",
    "Memory leak (LeakSanitizer)":    "Ensure every malloc() has a matching free() on all code paths.",
    "Misaligned memory access":       "Use memcpy() instead of pointer casts for unaligned reads.",
}


def _mitigation(title: str) -> str:
    for key, mit in _MITIGATIONS.items():
        if key.lower() in title.lower():
            return mit
    return "Review flagged runtime behaviour and apply defensive coding practices."


# ── Single binary execution ───────────────────────────────────────────────────

def _run_once(
    binary: str,
    argv_extra: List[str],
    stdin_data: Optional[bytes],
    env: dict,
    timeout: int,
    label: str,
    verbose: bool,
) -> List[dict]:
    """Run binary once; return list of sanitizer findings."""
    cmd = [binary] + argv_extra
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        if verbose:
            print(colour(f"    [timeout] {label}", Colour.WHITE))
        return []
    except Exception as e:
        if verbose:
            print(colour(f"    [error] {label}: {e}", Colour.WHITE))
        return []

    stderr = proc.stderr.decode(errors="replace")
    if not stderr.strip():
        return []

    input_repr = repr((argv_extra, stdin_data[:32] if stdin_data else None))[:80]
    findings = _parse_sanitizer_stderr(stderr, input_repr)

    if findings and verbose:
        for f in findings:
            print(colour(f"    [!] {f['severity']} – {f['title']}", Colour.YELLOW))

    return findings


# ── Public entry point ────────────────────────────────────────────────────────

def perform_runtime_execution(
    binary_path: str,
    timeout_per_run: int = 5,
    max_runs: int = 60,
    verbose: bool = False,
) -> dict:
    """
    Execute the sanitizer-instrumented binary with a crafted seed corpus.

    Parameters
    ----------
    binary_path      : path to the compiled binary
    timeout_per_run  : seconds per individual execution (default 5)
    max_runs         : cap total number of executions (default 60)

    Returns
    -------
    dict with:
        runs_total    – how many executions were attempted
        runs_crashed  – how many produced sanitizer output
        findings      – deduplicated list of runtime finding dicts
        skipped       – bool (True if binary not found / not executable)
    """
    result = {
        "runs_total":   0,
        "runs_crashed": 0,
        "findings":     [],
        "skipped":      False,
    }

    binary = Path(binary_path)
    if not binary.exists():
        print(colour(f"  [!] Binary not found: {binary_path}", Colour.YELLOW))
        result["skipped"] = True
        return result

    # Windows executables won't run on Linux and vice-versa — guard this
    if not os.access(str(binary), os.X_OK):
        print(colour("  [!] Binary is not executable on this platform – skipping runtime stage.", Colour.YELLOW))
        result["skipped"] = True
        return result

    env    = _san_env()
    seeds  = _build_seeds()
    all_findings: List[dict] = []
    seen_titles = set()

    print(colour(f"  Corpus size: {len(seeds)} seeds   max_runs={max_runs}", Colour.WHITE))

    runs = 0

    # ── Phase 1: argv fuzzing ─────────────────────────────────────────────
    print(colour("  [1/4] argv fuzzing…", Colour.WHITE))
    for seed in seeds:
        if runs >= max_runs:
            break
        s = seed.decode(errors="replace")
        for argv in ([s], [s, s], ["memhack", s]):
            if runs >= max_runs:
                break
            label = f"argv={repr(s[:20])}"
            hits = _run_once(str(binary), argv, None, env, timeout_per_run, label, verbose)
            runs += 1
            if hits:
                result["runs_crashed"] += 1
            for h in hits:
                if h["title"] not in seen_titles:
                    seen_titles.add(h["title"])
                    all_findings.append(h)

    # ── Phase 2: stdin fuzzing ────────────────────────────────────────────
    print(colour("  [2/4] stdin fuzzing…", Colour.WHITE))
    for seed in seeds:
        if runs >= max_runs:
            break
        label = f"stdin={repr(seed[:20])}"
        hits = _run_once(str(binary), [], seed, env, timeout_per_run, label, verbose)
        runs += 1
        if hits:
            result["runs_crashed"] += 1
        for h in hits:
            if h["title"] not in seen_titles:
                seen_titles.add(h["title"])
                all_findings.append(h)

    # ── Phase 3: file input probe ─────────────────────────────────────────
    print(colour("  [3/4] file-input probe…", Colour.WHITE))
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tf:
        tmp_path = tf.name
    try:
        for seed in seeds[:10]:          # limit – writing files is slow
            if runs >= max_runs:
                break
            Path(tmp_path).write_bytes(seed)
            label = f"file={repr(seed[:20])}"
            hits = _run_once(str(binary), [tmp_path], None, env,
                             timeout_per_run, label, verbose)
            runs += 1
            if hits:
                result["runs_crashed"] += 1
            for h in hits:
                if h["title"] not in seen_titles:
                    seen_titles.add(h["title"])
                    all_findings.append(h)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    # ── Phase 4: environment variable probe ───────────────────────────────
    print(colour("  [4/4] environment-variable probe…", Colour.WHITE))
    vuln_env_vars = ["USER", "HOME", "PATH", "SHELL", "TERM", "LANG"]
    for seed in seeds[:8]:
        if runs >= max_runs:
            break
        probe_env = env.copy()
        s = seed.decode(errors="replace")
        for var in vuln_env_vars:
            probe_env[var] = s
        label = f"env={repr(s[:20])}"
        hits = _run_once(str(binary), [], None, probe_env,
                         timeout_per_run, label, verbose)
        runs += 1
        if hits:
            result["runs_crashed"] += 1
        for h in hits:
            if h["title"] not in seen_titles:
                seen_titles.add(h["title"])
                all_findings.append(h)

    result["runs_total"] = runs
    result["findings"]   = all_findings

    # ── Summary ───────────────────────────────────────────────────────────
    n = len(all_findings)
    if n:
        print(colour(
            f"  [!] Runtime: {runs} run(s), {result['runs_crashed']} crash(es), "
            f"{n} unique finding(s)",
            Colour.YELLOW,
        ))
    else:
        print(colour(
            f"  [✓] Runtime: {runs} run(s), 0 sanitizer triggers",
            Colour.GREEN,
        ))

    return result
