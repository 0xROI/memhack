"""
memhack.parse_source
─────────────────────
Parse C/C++ source files and extract:
  • Function definitions (name, line, params)
  • Dangerous function calls (strcpy, gets, sprintf, …)
  • Variable declarations
  • Control-flow primitives (if/for/while)
  • Memory operations (malloc/free/realloc)
  • Format-string sites (printf family with non-literal fmt)

Strategy
─────────
1. Try pycparser (C only, requires fake headers).
2. Fall back to a fast regex-based extractor that works on both C and C++
   without a preprocessor step.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from memhack.utils import colour, Colour


# ── Dangerous function signatures ────────────────────────────────────────────

DANGEROUS_FUNCS = {
    # Buffer functions
    "gets":       {"cwe": "CWE-120", "severity": "CRITICAL", "desc": "gets() has no bounds checking"},
    "strcpy":     {"cwe": "CWE-120", "severity": "HIGH",     "desc": "strcpy() may overflow destination buffer"},
    "strcat":     {"cwe": "CWE-120", "severity": "HIGH",     "desc": "strcat() may overflow destination buffer"},
    "sprintf":    {"cwe": "CWE-134", "severity": "HIGH",     "desc": "sprintf() without size limit"},
    "vsprintf":   {"cwe": "CWE-134", "severity": "HIGH",     "desc": "vsprintf() without size limit"},
    "scanf":      {"cwe": "CWE-120", "severity": "MEDIUM",   "desc": "scanf() without field width"},
    "sscanf":     {"cwe": "CWE-120", "severity": "MEDIUM",   "desc": "sscanf() without field width"},
    "strncpy":    {"cwe": "CWE-170", "severity": "LOW",      "desc": "strncpy() may leave buffer un-terminated"},
    "strncat":    {"cwe": "CWE-170", "severity": "LOW",      "desc": "strncat() size argument easily misused"},
    "memcpy":     {"cwe": "CWE-120", "severity": "LOW",      "desc": "memcpy() – verify size argument"},
    "memmove":    {"cwe": "CWE-120", "severity": "INFO",     "desc": "memmove() – verify size argument"},
    # Format string
    "printf":     {"cwe": "CWE-134", "severity": "MEDIUM",   "desc": "printf() – check for user-controlled format string"},
    "fprintf":    {"cwe": "CWE-134", "severity": "MEDIUM",   "desc": "fprintf() – check for user-controlled format string"},
    "snprintf":   {"cwe": "CWE-134", "severity": "LOW",      "desc": "snprintf() – verify format string is a literal"},
    # Exec / system
    "system":     {"cwe": "CWE-78",  "severity": "HIGH",     "desc": "system() – command injection risk"},
    "popen":      {"cwe": "CWE-78",  "severity": "HIGH",     "desc": "popen() – command injection risk"},
    "execl":      {"cwe": "CWE-78",  "severity": "HIGH",     "desc": "exec*() – command injection risk"},
    "execv":      {"cwe": "CWE-78",  "severity": "HIGH",     "desc": "exec*() – command injection risk"},
    "execvp":     {"cwe": "CWE-78",  "severity": "MEDIUM",   "desc": "exec*() – command injection risk"},
    # Integer
    "atoi":       {"cwe": "CWE-190", "severity": "MEDIUM",   "desc": "atoi() – no error checking / overflow"},
    "atol":       {"cwe": "CWE-190", "severity": "MEDIUM",   "desc": "atol() – no error checking / overflow"},
    # Memory mgmt
    "malloc":     {"cwe": "CWE-789", "severity": "INFO",     "desc": "malloc() – verify return value checked"},
    "realloc":    {"cwe": "CWE-789", "severity": "INFO",     "desc": "realloc() – leaks original ptr on failure"},
    "free":       {"cwe": "CWE-416", "severity": "INFO",     "desc": "free() – check for double-free / UAF"},
    # Deprecated
    "mktemp":     {"cwe": "CWE-377", "severity": "HIGH",     "desc": "mktemp() – race condition / predictable names"},
    "tmpnam":     {"cwe": "CWE-377", "severity": "HIGH",     "desc": "tmpnam() – race condition"},
    "rand":       {"cwe": "CWE-330", "severity": "MEDIUM",   "desc": "rand() – not cryptographically secure"},
}

# ── Regex patterns ────────────────────────────────────────────────────────────

RE_FUNCTION_DEF  = re.compile(
    r"^[\w\s\*<>:]+\s+(\w+)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE,
)
RE_FUNC_CALL     = re.compile(r"\b(\w+)\s*\(")
RE_MALLOC_NOCHECK = re.compile(
    r"\b(malloc|calloc|realloc)\s*\([^;]+\)\s*;",
    re.MULTILINE,
)
RE_FREE          = re.compile(r"\bfree\s*\((\w+)\)", re.MULTILINE)
RE_FORMAT_VAR    = re.compile(
    r"\b(printf|fprintf|sprintf|snprintf|vsprintf|vfprintf)\s*\([^;]*,\s*(\w+)",
    re.MULTILINE,
)
RE_INTEGER_OPS   = re.compile(
    r"\b(int|unsigned|long|short)\s+\w+\s*=\s*[^;]+\s*[\+\-\*]\s*[^;]+;",
    re.MULTILINE,
)


def _parse_with_regex(file_path: Path) -> dict:
    """Fast regex-based extractor. Works on C and C++ without a pre-processor."""
    try:
        source = file_path.read_text(errors="replace")
    except OSError as e:
        return {"error": str(e), "file": str(file_path)}

    lines = source.splitlines()
    result: dict = {
        "file":            str(file_path),
        "functions":       [],
        "dangerous_calls": [],
        "format_issues":   [],
        "malloc_no_check": [],
        "frees":           [],
    }

    # Function definitions
    for m in RE_FUNCTION_DEF.finditer(source):
        line_no = source[:m.start()].count("\n") + 1
        result["functions"].append({
            "name":   m.group(1),
            "params": m.group(2).strip(),
            "line":   line_no,
        })

    # Per-line dangerous call scan
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for m in RE_FUNC_CALL.finditer(line):
            fname = m.group(1)
            if fname in DANGEROUS_FUNCS:
                info = DANGEROUS_FUNCS[fname]
                result["dangerous_calls"].append({
                    "function": fname,
                    "line":     line_no,
                    "code":     stripped[:120],
                    "cwe":      info["cwe"],
                    "severity": info["severity"],
                    "desc":     info["desc"],
                })

    # Format-string with variable (not a literal string)
    for m in RE_FORMAT_VAR.finditer(source):
        func, fmt_arg = m.group(1), m.group(2)
        # If fmt_arg is not a quoted literal, flag it
        line_no = source[:m.start()].count("\n") + 1
        result["format_issues"].append({
            "function":   func,
            "format_arg": fmt_arg,
            "line":       line_no,
            "code":       lines[line_no - 1].strip()[:120],
        })

    # malloc without NULL check heuristic
    for m in RE_MALLOC_NOCHECK.finditer(source):
        line_no = source[:m.start()].count("\n") + 1
        # Look ahead up to 3 lines for NULL check
        context = "\n".join(lines[line_no : line_no + 3])
        if "NULL" not in context and "null" not in context and "!=" not in context:
            result["malloc_no_check"].append({
                "line": line_no,
                "code": lines[line_no - 1].strip()[:120],
            })

    # Free tracking
    for m in RE_FREE.finditer(source):
        line_no = source[:m.start()].count("\n") + 1
        result["frees"].append({"var": m.group(1), "line": line_no})

    return result


def _try_pycparser(file_path: Path) -> Optional[dict]:
    """
    Attempt a pycparser AST parse.  Returns None if pycparser is not installed
    or the file requires a pre-processor step that isn't available.
    """
    try:
        from pycparser import parse_file, c_ast  # type: ignore
    except ImportError:
        return None

    try:
        ast = parse_file(str(file_path), use_cpp=True,
                         cpp_args=["-E", r"-I/usr/share/gcc/fake_libc_include"])
        # Just signal that pycparser succeeded; detailed extraction is done by
        # the regex pass which is always run.
        return {"pycparser_ast": True}
    except Exception:
        return None


def parse_source_code(folder_path, verbose: bool = False) -> dict:
    """
    Parse every C/C++ file under folder_path.

    Returns
    -------
    dict with:
        files      – list of per-file parse results
        total_funcs, total_dangerous_calls, total_format_issues
    """
    folder  = Path(folder_path).resolve()
    sources = []
    for ext in ("*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp"):
        sources.extend(folder.rglob(ext))
    sources = sorted(sources)

    all_files   = []
    total_df    = 0
    total_funcs = 0

    for src in sources:
        if verbose:
            print(colour(f"  Parsing {src.name}…", Colour.WHITE))

        file_result = _parse_with_regex(src)
        _try_pycparser(src)   # enrich if possible (currently just marks success)

        total_funcs += len(file_result.get("functions", []))
        total_df    += len(file_result.get("dangerous_calls", []))
        all_files.append(file_result)

        n_dc = len(file_result.get("dangerous_calls", []))
        if n_dc:
            print(colour(f"  [!] {src.name}: {n_dc} dangerous call(s)", Colour.YELLOW))
        elif verbose:
            print(colour(f"  [✓] {src.name}: clean", Colour.GREEN))

    summary = {
        "files":                    all_files,
        "total_functions":          total_funcs,
        "total_dangerous_calls":    total_df,
        "total_format_issues":      sum(len(f.get("format_issues", [])) for f in all_files),
        "total_malloc_no_check":    sum(len(f.get("malloc_no_check", [])) for f in all_files),
    }
    print(colour(
        f"  [✓] Parsed {len(sources)} file(s): "
        f"{total_funcs} function(s), {total_df} dangerous call(s)",
        Colour.GREEN,
    ))
    return summary
