"""
memhack.verifier
─────────────────
Verification Engine – turns static "candidate bugs" into confirmed findings.

Strategy per finding type
─────────────────────────
  Buffer overflow / gets / strcpy / strcat
      → Run binary with escalating-length string inputs.
        If ASan fires "stack-buffer-overflow" or "heap-buffer-overflow" → CONFIRMED.

  Format string (printf with non-literal fmt)
      → Run binary with "%x.%x.%x", "%n", "%.9999d".
        Stack leak or crash → CONFIRMED.

  malloc no-check
      → Run binary with huge size argument (triggering OOM → NULL deref).
        SIGSEGV / "null-deref" → CONFIRMED.

  system / popen / exec  (command injection)
      → Run binary with "; id" / "$(id)".
        If output contains "uid=" → CONFIRMED.

  Symbolic/taint findings (already verified by angr/dynamic)
      → Mark as CONFIRMED by source.

Each verification attempt records:
    status      CONFIRMED | LIKELY | UNVERIFIED | SKIPPED
    evidence    – relevant snippet from sanitizer/crash output
    trigger     – the exact input that caused the finding
    crash_type  – parsed ASan error type if applicable
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional, Dict, Any, List

from memhack.utils import colour, Colour

# ── Sanitizer environment (same as runtime_exec) ─────────────────────────────

def _san_env() -> dict:
    env = os.environ.copy()
    env["ASAN_OPTIONS"]  = (
        "halt_on_error=0:detect_leaks=0:"
        "print_stats=0:log_path=stderr:exitcode=0"
    )
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=0:exitcode=0"
    sym = shutil.which("llvm-symbolizer") or shutil.which("llvm-symbolizer-14")
    if sym:
        env["ASAN_SYMBOLIZER_PATH"] = sym
    return env


# ── Run helper ────────────────────────────────────────────────────────────────

def _run(binary: str, argv_extra: List[str] = None,
         stdin_data: bytes = None, timeout: int = 5) -> Dict[str, Any]:
    """Execute binary and return {rc, stdout, stderr, combined, timed_out}."""
    cmd = [binary] + (argv_extra or [])
    try:
        r = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            env=_san_env(),
        )
        combined = (r.stdout + r.stderr).decode("latin-1", errors="replace")
        return {
            "rc": r.returncode,
            "stdout": r.stdout.decode("latin-1", errors="replace"),
            "stderr": r.stderr.decode("latin-1", errors="replace"),
            "combined": combined,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": "", "combined": "TIMEOUT", "timed_out": True}
    except FileNotFoundError:
        return {"rc": -2, "stdout": "", "stderr": "", "combined": "BINARY_NOT_FOUND", "timed_out": False}


# ── ASan output parser ────────────────────────────────────────────────────────

_ASAN_CRASH_PATTERNS = [
    (r"heap-buffer-overflow",   "heap-buffer-overflow"),
    (r"stack-buffer-overflow",  "stack-buffer-overflow"),
    (r"heap-use-after-free",    "heap-use-after-free"),
    (r"double-free",            "double-free"),
    (r"null-deref|SEGV on.*address 0x0", "null-deref"),
    (r"undefined behaviour|runtime error", "undefined-behaviour"),
    (r"data race",              "data-race"),
    (r"AddressSanitizer:",      "asan-generic"),
    (r"SIGSEGV|Segmentation fault", "sigsegv"),
]


def _parse_crash(combined: str) -> Optional[str]:
    """Return the crash type string if a crash is detected in combined output."""
    for pattern, crash_type in _ASAN_CRASH_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return crash_type
    return None


def _extract_evidence(combined: str, max_chars: int = 600) -> str:
    """Return the most relevant snippet of sanitizer/crash output."""
    lines = combined.splitlines()
    # Look for ASan summary start
    for i, line in enumerate(lines):
        if any(k in line for k in ("ERROR: AddressSanitizer", "runtime error",
                                    "SIGSEGV", "Sanitizer", "heap-buffer")):
            snippet = "\n".join(lines[i:i+20])
            return snippet[:max_chars]
    return combined[:max_chars]


# ── Verification strategies ───────────────────────────────────────────────────

def _verify_buffer_overflow(binary: str, finding: dict, timeout: int) -> dict:
    """Try escalating-length inputs as argv[1] and via stdin."""
    sizes = [65, 100, 128, 200, 256, 512, 1024, 2048, 4096]
    for size in sizes:
        payload = "A" * size
        # argv
        res = _run(binary, argv_extra=[payload], timeout=timeout)
        crash = _parse_crash(res["combined"])
        if crash:
            return {
                "status": "CONFIRMED",
                "crash_type": crash,
                "trigger": f"argv[1] = 'A'*{size}",
                "evidence": _extract_evidence(res["combined"]),
            }
        # stdin
        res = _run(binary, stdin_data=payload.encode(), timeout=timeout)
        crash = _parse_crash(res["combined"])
        if crash:
            return {
                "status": "CONFIRMED",
                "crash_type": crash,
                "trigger": f"stdin = 'A'*{size}",
                "evidence": _extract_evidence(res["combined"]),
            }

    # Check if the static finding is from a clearly dangerous func (gets/strcpy)
    title = finding.get("title", "").lower()
    if any(f in title for f in ("gets()", "strcpy()", "strcat()")):
        return {
            "status": "LIKELY",
            "crash_type": "not-triggered-in-this-run",
            "trigger": "N/A – binary may need different entry point",
            "evidence": "Static analysis confirms use of unbounded function. Binary did not crash with simple argv/stdin vectors – may require specific program flow.",
        }

    return {
        "status": "UNVERIFIED",
        "crash_type": None,
        "trigger": None,
        "evidence": "No crash triggered with standard overflow payloads.",
    }


def _verify_format_string(binary: str, finding: dict, timeout: int) -> dict:
    """Try format string payloads as argv[1] and via stdin."""
    payloads = [
        "%x.%x.%x.%x",
        "AAAA.%08x.%08x.%08x",
        "%.9999d",
        "%s%s%s%s",
        "%n",
        "%100$x",
    ]
    for payload in payloads:
        for mode in ["argv", "stdin"]:
            if mode == "argv":
                res = _run(binary, argv_extra=[payload], timeout=timeout)
            else:
                res = _run(binary, stdin_data=payload.encode(), timeout=timeout)

            crash = _parse_crash(res["combined"])
            # Format string may also just leak stack values (non-crash)
            has_leak = bool(re.search(r"0x[0-9a-f]{4,}", res["stdout"]))

            if crash:
                return {
                    "status": "CONFIRMED",
                    "crash_type": crash,
                    "trigger": f"{mode} = {repr(payload)}",
                    "evidence": _extract_evidence(res["combined"]),
                }
            if has_leak and payload.startswith("%x"):
                return {
                    "status": "CONFIRMED",
                    "crash_type": "stack-info-leak",
                    "trigger": f"{mode} = {repr(payload)}",
                    "evidence": f"Stack values leaked: {res['stdout'][:300]}",
                }

    return {
        "status": "LIKELY",
        "crash_type": None,
        "trigger": None,
        "evidence": "Format string pattern detected statically. Binary accepted payloads without immediate crash – may need deeper call path.",
    }


def _verify_malloc_no_check(binary: str, finding: dict, timeout: int) -> dict:
    """Trigger OOM by requesting a huge allocation."""
    huge_sizes = ["9999999999", "999999999999", "18446744073709551615"]
    for size in huge_sizes:
        res = _run(binary, argv_extra=[size], timeout=timeout)
        crash = _parse_crash(res["combined"])
        if crash:
            return {
                "status": "CONFIRMED",
                "crash_type": crash,
                "trigger": f"argv[1] = {size} (huge malloc → NULL deref)",
                "evidence": _extract_evidence(res["combined"]),
            }

    return {
        "status": "LIKELY",
        "crash_type": None,
        "trigger": None,
        "evidence": "malloc() return value not checked (static). OOM scenario requires actual memory pressure.",
    }


def _verify_command_injection(binary: str, finding: dict, timeout: int) -> dict:
    """Try shell metacharacters as argv[1] and stdin."""
    payloads = ["; id", "$(id)", "`id`", "| id", "&& id", "; echo PWNED"]
    for payload in payloads:
        for mode in ["argv", "stdin"]:
            if mode == "argv":
                res = _run(binary, argv_extra=[payload], timeout=timeout)
            else:
                res = _run(binary, stdin_data=(payload + "\n").encode(), timeout=timeout)

            if re.search(r"uid=\d+", res["combined"]) or "PWNED" in res["combined"]:
                return {
                    "status": "CONFIRMED",
                    "crash_type": "command-injection",
                    "trigger": f"{mode} = {repr(payload)}",
                    "evidence": f"Command output: {res['stdout'][:300]}",
                }
            crash = _parse_crash(res["combined"])
            if crash:
                return {
                    "status": "CONFIRMED",
                    "crash_type": crash,
                    "trigger": f"{mode} = {repr(payload)}",
                    "evidence": _extract_evidence(res["combined"]),
                }

    return {
        "status": "LIKELY",
        "crash_type": None,
        "trigger": None,
        "evidence": "system()/popen() detected statically. Injection success depends on how the argument reaches the call.",
    }


# ── Already-verified sources (runtime/symbolic/taint) ────────────────────────

def _mark_already_confirmed(finding: dict) -> dict:
    src = finding.get("source", "")
    if src in ("runtime", "sanitizer"):
        return {
            "status": "CONFIRMED",
            "crash_type": "confirmed-by-sanitizer",
            "trigger": "Runtime execution with ASan",
            "evidence": finding.get("description", ""),
        }
    if src == "symbolic":
        return {
            "status": "CONFIRMED",
            "crash_type": "confirmed-by-symbolic-execution",
            "trigger": finding.get("description", ""),
            "evidence": "angr symbolic execution found a concrete path to this sink.",
        }
    if src == "taint":
        return {
            "status": "CONFIRMED",
            "crash_type": "confirmed-by-taint-analysis",
            "trigger": "stdin → sink taint flow",
            "evidence": finding.get("description", ""),
        }
    return None


# ── CWE → strategy dispatch ───────────────────────────────────────────────────

_CWE_STRATEGY = {
    "CWE-120": _verify_buffer_overflow,
    "CWE-121": _verify_buffer_overflow,
    "CWE-122": _verify_buffer_overflow,
    "CWE-134": _verify_format_string,
    "CWE-476": _verify_malloc_no_check,
    "CWE-789": _verify_malloc_no_check,
    "CWE-78":  _verify_command_injection,
}


def _verify_one(finding: dict, binary: Optional[str], timeout: int) -> dict:
    """Verify a single finding. Returns verification result dict."""
    # Already confirmed by a dynamic source
    already = _mark_already_confirmed(finding)
    if already:
        return already

    # No binary → can't do dynamic verification
    if not binary:
        return {
            "status": "UNVERIFIED",
            "crash_type": None,
            "trigger": None,
            "evidence": "No instrumented binary available – static finding only.",
        }

    cwe = finding.get("cwe", "")
    title_lower = finding.get("title", "").lower()

    # Pick strategy
    strategy = _CWE_STRATEGY.get(cwe)
    if strategy is None:
        if "format string" in title_lower:
            strategy = _verify_format_string
        elif "command injection" in title_lower or "system" in title_lower or "popen" in title_lower:
            strategy = _verify_command_injection
        elif "overflow" in title_lower or "gets" in title_lower or "strcpy" in title_lower:
            strategy = _verify_buffer_overflow

    if strategy:
        return strategy(binary, finding, timeout)

    return {
        "status": "UNVERIFIED",
        "crash_type": None,
        "trigger": None,
        "evidence": f"No verification strategy for {cwe}. Manual review required.",
    }


# ── Public entry point ────────────────────────────────────────────────────────

def perform_verification(
    findings: list,
    binary: Optional[str] = None,
    timeout_per_check: int = 5,
    verbose: bool = False,
) -> list:
    """
    Run verification against every finding.
    Attaches 'verification' dict to each finding in-place.

    verification keys:
        status      CONFIRMED | LIKELY | UNVERIFIED | SKIPPED
        crash_type  string or None
        trigger     exact input that caused the result, or None
        evidence    relevant output snippet
    """
    confirmed = 0
    likely    = 0
    unverified= 0

    for finding in findings:
        fid  = finding.get("id", "?")
        sev  = finding.get("severity", "")
        title= finding.get("title", "")

        if verbose:
            print(colour(f"    [{fid}] Verifying: {title[:60]}", Colour.WHITE))

        result = _verify_one(finding, binary, timeout_per_check)
        finding["verification"] = result

        status = result["status"]
        if status == "CONFIRMED":
            confirmed += 1
            if verbose:
                ctype = result.get("crash_type", "")
                print(colour(f"      → CONFIRMED ({ctype})", Colour.RED))
        elif status == "LIKELY":
            likely += 1
            if verbose:
                print(colour(f"      → LIKELY (needs manual confirmation)", Colour.YELLOW))
        else:
            unverified += 1
            if verbose:
                print(colour(f"      → UNVERIFIED", Colour.WHITE))

    total = len(findings)
    print(colour(
        f"\n  Verification: {confirmed} confirmed, {likely} likely, "
        f"{unverified} unverified  (of {total} total)",
        Colour.CYAN,
    ))

    return findings
