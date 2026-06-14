"""
memhack.vuln_detect
────────────────────
Aggregates findings from:
  • parse_source  (static dangerous-call / format-string / malloc checks)
  • compile_sanitize (compiler warnings, sanitizer output)
  • symbolic_exec (unconstrained paths, sink reaches)
  • taint_analysis (stdin → sink flows)

Produces a unified list of Finding objects with:
  id, severity, cwe, title, description, file, line, code, mitigation, source
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from memhack.utils import colour, Colour
from memhack.verifier import perform_verification
from memhack.poc_generator import generate_all_pocs

# ── Severity ordering ─────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _sev_colour(sev: str) -> Colour:
    return {
        "CRITICAL": Colour.RED,
        "HIGH":     Colour.RED,
        "MEDIUM":   Colour.YELLOW,
        "LOW":      Colour.CYAN,
        "INFO":     Colour.WHITE,
    }.get(sev, Colour.WHITE)


# ── Mitigation database ───────────────────────────────────────────────────────

MITIGATIONS: Dict[str, str] = {
    "gets":     "Replace with fgets(buf, sizeof(buf), stdin). gets() is removed from C11.",
    "strcpy":   "Replace with strlcpy() or snprintf(dst, sizeof(dst), \"%s\", src).",
    "strcat":   "Replace with strlcat() or strncat(dst, src, sizeof(dst)-strlen(dst)-1).",
    "sprintf":  "Replace with snprintf(dst, sizeof(dst), fmt, ...) and validate return value.",
    "vsprintf": "Replace with vsnprintf().",
    "scanf":    "Add field-width specifier, e.g. scanf(\"%255s\", buf).",
    "sscanf":   "Add field-width specifier and check return value.",
    "printf":   "Never pass user input as the format string. Use printf(\"%s\", user_input).",
    "fprintf":  "Never pass user input as the format string. Use fprintf(f, \"%s\", user_input).",
    "snprintf": "Ensure format string is a compile-time literal, not user-controlled.",
    "system":   "Avoid system(). Use execv() with a fixed path and sanitised argument list.",
    "popen":    "Validate and sanitize the command string; prefer execv() with explicit args.",
    "execl":    "Use absolute paths; never interpolate user input into arguments.",
    "execv":    "Use absolute paths; never interpolate user input into arguments.",
    "execvp":   "Use absolute paths; never interpolate user input into arguments.",
    "atoi":     "Use strtol() with errno checking and range validation.",
    "atol":     "Use strtol() with errno checking and range validation.",
    "malloc":   "Always check malloc() return value for NULL before use.",
    "realloc":  "Assign realloc() to a temporary pointer; free original on failure.",
    "free":     "Set pointer to NULL after free() to prevent use-after-free / double-free.",
    "mktemp":   "Use mkstemp() instead; it creates the file atomically.",
    "tmpnam":   "Use mkstemp() instead.",
    "rand":     "Use getrandom(), /dev/urandom, or a CSPRNG for security-sensitive values.",
    "strncpy":  "Manually NUL-terminate: buf[sizeof(buf)-1] = '\\0'; after strncpy().",
    "strncat":  "Third argument should be sizeof(dst)-strlen(dst)-1, not sizeof(src).",
    "memcpy":   "Verify the size argument does not exceed the destination buffer.",
    "memmove":  "Verify the size argument does not exceed the destination buffer.",
    # Generic
    "buffer_overflow":      "Use bounds-checked functions; enable -D_FORTIFY_SOURCE=2 and stack canaries.",
    "format_string":        "Always use a literal format string; never pass user data as the fmt argument.",
    "malloc_no_check":      "Check malloc/calloc/realloc return value against NULL before dereferencing.",
    "unconstrained_pc":     "Add stack canaries (-fstack-protector-all), ASLR, and NX. Audit all buffer operations.",
    "taint_flow":           "Validate and sanitize all user-controlled input before passing to sensitive functions.",
    "compiler_warning":     "Resolve all compiler warnings; treat them as errors (-Werror) in CI.",
    "sanitizer_finding":    "Run the sanitizer-instrumented binary against a broad set of inputs / a fuzzer.",
}


def _mitigation(key: str) -> str:
    return MITIGATIONS.get(key, "Review the flagged code and apply defensive coding practices.")


# ── Individual finding constructor ────────────────────────────────────────────

_finding_id = 0


def _make_finding(
    severity: str,
    title: str,
    description: str,
    cwe: str = "",
    file: str = "",
    line: int = 0,
    code: str = "",
    mitigation: str = "",
    source: str = "static",
) -> dict:
    global _finding_id
    _finding_id += 1
    return {
        "id":          f"MH-{_finding_id:04d}",
        "severity":    severity,
        "cwe":         cwe,
        "title":       title,
        "description": description,
        "file":        file,
        "line":        line,
        "code":        code,
        "mitigation":  mitigation,
        "source":      source,
    }


# ── Sanitizer output parser ───────────────────────────────────────────────────

_ASAN_PATTERNS = [
    (r"heap-buffer-overflow",    "CRITICAL", "Heap buffer overflow detected by ASan",     "CWE-122"),
    (r"stack-buffer-overflow",   "CRITICAL", "Stack buffer overflow detected by ASan",    "CWE-121"),
    (r"heap-use-after-free",     "CRITICAL", "Use-after-free detected by ASan",           "CWE-416"),
    (r"double-free",             "HIGH",     "Double-free detected by ASan",              "CWE-415"),
    (r"null-deref",              "HIGH",     "Null pointer dereference detected by ASan", "CWE-476"),
    (r"undefined.*behaviour|ubsan", "MEDIUM","Undefined behaviour detected by UBSan",     "CWE-758"),
    (r"signed integer overflow", "MEDIUM",   "Signed integer overflow (UBSan)",           "CWE-190"),
    (r"data race",               "HIGH",     "Data race detected by TSan",                "CWE-362"),
]


def _parse_sanitizer_output(san_output: str) -> List[dict]:
    findings = []
    for pattern, sev, title, cwe in _ASAN_PATTERNS:
        if re.search(pattern, san_output, re.IGNORECASE):
            # Extract file/line from ASan stack trace if present
            m = re.search(r"#0 .+ in \S+ (.+):(\d+)", san_output)
            f, ln = (m.group(1), int(m.group(2))) if m else ("", 0)
            findings.append(_make_finding(
                severity=sev, title=title, cwe=cwe,
                description=f"Runtime sanitizer detected: {title}.",
                file=f, line=ln,
                mitigation=_mitigation("sanitizer_finding"),
                source="sanitizer",
            ))
    return findings


# ── Compiler warning parser ───────────────────────────────────────────────────

_WARN_MAP = [
    (r"implicit.*declaration",  "MEDIUM", "Implicit function declaration",  "CWE-628"),
    (r"format.*not a string",   "HIGH",   "Format string is not a literal", "CWE-134"),
    (r"return.*address.*local", "HIGH",   "Returning address of local var", "CWE-562"),
    (r"use.*uninitialized",     "HIGH",   "Use of uninitialized variable",  "CWE-457"),
    (r"maybe.*uninitialized",   "MEDIUM", "Possibly uninitialized variable","CWE-457"),
    (r"signed.*unsigned",       "MEDIUM", "Signed/unsigned comparison",     "CWE-195"),
    (r"integer overflow",       "MEDIUM", "Integer overflow in expression",  "CWE-190"),
    (r"array.*subscript",       "HIGH",   "Out-of-bounds array subscript",  "CWE-129"),
]


def _parse_compiler_warnings(warnings: List[str]) -> List[dict]:
    findings = []
    seen = set()
    for w in warnings:
        for pattern, sev, title, cwe in _WARN_MAP:
            if re.search(pattern, w, re.IGNORECASE) and title not in seen:
                seen.add(title)
                # Extract file:line from warning text
                m = re.match(r"([^:]+):(\d+):", w)
                f, ln = (m.group(1), int(m.group(2))) if m else ("", 0)
                findings.append(_make_finding(
                    severity=sev, title=title, cwe=cwe,
                    description=w.strip()[:200],
                    file=f, line=ln,
                    mitigation=_mitigation("compiler_warning"),
                    source="compiler",
                ))
    return findings


# ── Static parse findings ─────────────────────────────────────────────────────

def _from_parse_result(parse_result: dict) -> List[dict]:
    findings = []
    for file_info in parse_result.get("files", []):
        fname = file_info.get("file", "")

        # Dangerous function calls
        for dc in file_info.get("dangerous_calls", []):
            findings.append(_make_finding(
                severity=dc["severity"],
                title=f"Dangerous function: {dc['function']}()",
                description=dc["desc"],
                cwe=dc["cwe"],
                file=fname,
                line=dc["line"],
                code=dc.get("code", ""),
                mitigation=_mitigation(dc["function"]),
                source="static",
            ))

        # Format string with variable format arg
        for fi in file_info.get("format_issues", []):
            findings.append(_make_finding(
                severity="HIGH",
                title=f"Possible format string vulnerability in {fi['function']}()",
                description=(
                    f"{fi['function']}() called with non-literal format argument '{fi['format_arg']}'. "
                    "If user-controlled this is a format string vulnerability (CWE-134)."
                ),
                cwe="CWE-134",
                file=fname,
                line=fi["line"],
                code=fi.get("code", ""),
                mitigation=_mitigation("format_string"),
                source="static",
            ))

        # malloc without NULL check
        for mn in file_info.get("malloc_no_check", []):
            findings.append(_make_finding(
                severity="MEDIUM",
                title="Unchecked malloc() return value",
                description="Allocation result not checked for NULL; dereferencing will segfault.",
                cwe="CWE-476",
                file=fname,
                line=mn["line"],
                code=mn.get("code", ""),
                mitigation=_mitigation("malloc_no_check"),
                source="static",
            ))

    return findings


# ── Symbolic execution findings ───────────────────────────────────────────────

def _from_symbolic(symbolic_result: dict) -> List[dict]:
    findings = []
    for desc in symbolic_result.get("unconstrained_paths", []):
        findings.append(_make_finding(
            severity="CRITICAL",
            title="Controllable instruction pointer (potential RCE)",
            description=(
                f"angr found an execution path where the instruction pointer becomes "
                f"user-controlled: {desc}. This strongly indicates a buffer overflow "
                f"or similar memory corruption that enables control-flow hijacking."
            ),
            cwe="CWE-121",
            mitigation=_mitigation("unconstrained_pc"),
            source="symbolic",
        ))
    for reach in symbolic_result.get("dangerous_reaches", []):
        findings.append(_make_finding(
            severity="HIGH",
            title=f"Reachable dangerous sink: {reach['sink']}()",
            description=(
                f"Symbolic execution found a concrete path to {reach['sink']}() "
                f"at {reach['address']}. Example triggering stdin: {reach['example_input']}"
            ),
            cwe="CWE-120",
            mitigation=_mitigation(reach["sink"]),
            source="symbolic",
        ))
    return findings


# ── Taint analysis findings ───────────────────────────────────────────────────

def _from_taint(taint_result: dict) -> List[dict]:
    findings = []
    for flow in taint_result.get("flows", []):
        findings.append(_make_finding(
            severity="HIGH",
            title=f"Tainted user input reaches {flow['sink']}()",
            description=(
                f"User-controlled stdin data flows into {flow['sink']}() "
                f"argument[{flow['arg_index']}] — {flow['desc']}."
            ),
            cwe="CWE-20",
            mitigation=_mitigation("taint_flow"),
            source="taint",
        ))
    return findings


# ── Deduplication ─────────────────────────────────────────────────────────────

def _dedup(findings: List[dict]) -> List[dict]:
    """Remove near-duplicate findings (same title + file + line)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f["title"], f.get("file", ""), f.get("line", 0))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ── Public entry point ────────────────────────────────────────────────────────

def _from_runtime(runtime_result: dict) -> List[dict]:
    """Lift runtime_exec findings into the unified finding format."""
    findings = []
    for f in runtime_result.get("findings", []):
        findings.append(_make_finding(
            severity=f.get("severity", "HIGH"),
            title=f.get("title", "Runtime sanitizer finding"),
            description=f.get("description", ""),
            cwe=f.get("cwe", ""),
            file=f.get("file", ""),
            line=f.get("line", 0),
            code=f.get("code", ""),
            mitigation=f.get("mitigation", _mitigation("sanitizer_finding")),
            source="runtime",
        ))
    return findings


def perform_vulnerability_detection(
    folder_path,
    parse_result:    Optional[dict] = None,
    compile_result:  Optional[dict] = None,
    runtime_result:  Optional[dict] = None,
    symbolic_result: Optional[dict] = None,
    taint_result:    Optional[dict] = None,
    binary:          Optional[str] = None,
    verbose: bool = False,
) -> dict:
    """
    Aggregate all analysis results into a unified findings list.
    Run verification engine & generate PoC artifacts.

    Returns
    -------
    dict with:
        findings  – sorted list of finding dicts with verification + PoC
        stats     – severity breakdown
    """
    global _finding_id
    _finding_id = 0   # reset counter per run

    all_findings: List[dict] = []

    # 1. Static parse
    if parse_result:
        sf = _from_parse_result(parse_result)
        all_findings.extend(sf)
        if verbose:
            print(colour(f"  Static analysis: {len(sf)} finding(s)", Colour.WHITE))

    # 2. Compiler warnings
    if compile_result:
        wf = _parse_compiler_warnings(compile_result.get("warnings", []))
        all_findings.extend(wf)
        san_out = compile_result.get("sanitizer_output", "")
        if san_out:
            sf2 = _parse_sanitizer_output(san_out)
            all_findings.extend(sf2)
        if verbose:
            print(colour(f"  Compiler/sanitizer: {len(wf)} finding(s)", Colour.WHITE))

    # 3. Runtime sanitizer findings
    if runtime_result and not runtime_result.get("skipped"):
        rf = _from_runtime(runtime_result)
        all_findings.extend(rf)
        if verbose:
            runs = runtime_result.get("runs_total", 0)
            crashes = runtime_result.get("runs_crashed", 0)
            print(colour(
                f"  Runtime ({runs} runs, {crashes} crashes): {len(rf)} finding(s)",
                Colour.WHITE,
            ))

    # 4. Symbolic execution
    if symbolic_result and not symbolic_result.get("skipped"):
        symf = _from_symbolic(symbolic_result)
        all_findings.extend(symf)
        if verbose:
            print(colour(f"  Symbolic exec: {len(symf)} finding(s)", Colour.WHITE))

    # 5. Taint analysis
    if taint_result and not taint_result.get("skipped"):
        tf = _from_taint(taint_result)
        all_findings.extend(tf)
        if verbose:
            print(colour(f"  Taint analysis: {len(tf)} finding(s)", Colour.WHITE))

    # Deduplicate and sort by severity
    all_findings = _dedup(all_findings)
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    # Stats
    stats: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in all_findings:
        stats[f["severity"]] = stats.get(f["severity"], 0) + 1

    # Print summary
    print(colour(f"\n  {'─'*50}", Colour.WHITE))
    print(colour(f"  VULNERABILITY SUMMARY  ({len(all_findings)} total)", Colour.CYAN))
    print(colour(f"  {'─'*50}", Colour.WHITE))
    for sev in SEVERITY_ORDER:
        cnt = stats[sev]
        if cnt:
            bar = "█" * min(cnt, 30)
            print(f"  {colour(f'{sev:<10}', _sev_colour(sev))} {bar} {cnt}")
    print(colour(f"  {'─'*50}\n", Colour.WHITE))

    # ── 7. Verification Engine ────────────────────────────────────────────
    print(colour("\n  [VERIFICATION ENGINE]", Colour.CYAN))
    print(colour(f"  {'─'*50}", Colour.WHITE))
    all_findings = perform_verification(
        all_findings,
        binary=binary,
        timeout_per_check=5,
        verbose=verbose,
    )

    # ── 8. PoC Generation ─────────────────────────────────────────────────
    print(colour("\n  [POC GENERATION]", Colour.CYAN))
    print(colour(f"  {'─'*50}", Colour.WHITE))
    all_findings = generate_all_pocs(all_findings)
    print(colour(f"  ✓ Generated PoC artifacts for {len(all_findings)} finding(s)", Colour.GREEN))
    print(colour(f"  {'─'*50}\n", Colour.WHITE))

    return {"findings": all_findings, "stats": stats}
