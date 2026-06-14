"""
memhack.compile_sanitize
─────────────────────────
Compile C/C++ sources with the chosen sanitizer combination and capture
sanitizer runtime output.

Key fixes vs. original code
────────────────────────────
* All-sanitizer combinations are NOT valid; ASan+MSan conflict, TSan is
  mutually exclusive with most others.  We expose four clean modes.
* Glob patterns can't be passed raw to subprocess; we enumerate files with
  pathlib instead.
* Compilation errors are captured (stderr) and returned rather than crashing.
* Output binary is placed in a well-known temp path we can track.
"""

import os
import re
import subprocess
import tempfile
from enum import Enum, auto
from pathlib import Path
from typing import List, Optional

from memhack.utils import colour, Colour


class SanitizerMode(Enum):
    ASAN  = auto()   # AddressSanitizer + UBSan  (default, widely supported)
    UBSAN = auto()   # UBSan only
    TSAN  = auto()   # ThreadSanitizer (mutually exclusive with ASan)
    NONE  = auto()   # No sanitizer; plain debug build


# Sanitizer flags per mode
_SANITIZER_FLAGS: dict = {
    SanitizerMode.ASAN:  ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"],
    SanitizerMode.UBSAN: ["-fsanitize=undefined"],
    SanitizerMode.TSAN:  ["-fsanitize=thread"],
    SanitizerMode.NONE:  [],
}

# Common hardening / debug flags always added
_BASE_FLAGS = [
    "-g",           # debug symbols (needed for angr / line-number attribution)
    "-O1",          # minimal optimisation so sanitisers work well
    "-Wall",
    "-Wextra",
    "-fstack-protector-all",
    "-D_FORTIFY_SOURCE=2",
]


def _collect_sources(folder: Path) -> List[Path]:
    """Recursively collect .c / .cpp / .cc files."""
    sources = []
    for ext in ("*.c", "*.cpp", "*.cc", "*.cxx"):
        sources.extend(folder.rglob(ext))
    return sorted(sources)


def _choose_compiler(sources: List[Path]) -> str:
    has_cpp = any(s.suffix in {".cpp", ".cc", ".cxx"} for s in sources)
    return "g++" if has_cpp else "gcc"


def compile_and_sanitize(
    folder_path,
    mode: SanitizerMode = SanitizerMode.ASAN,
    extra_flags: List[str] = None,
    extra_includes: List[str] = None,
    output_name: str = "memhack_target",
    verbose: bool = False,
) -> dict:
    """
    Compile all C/C++ sources in *folder_path* with the requested sanitizer.

    Returns
    -------
    dict with keys:
        success (bool)         – True if compilation succeeded
        binary  (str|None)     – path to compiled binary, or None on failure
        warnings (list[str])   – compiler warnings extracted from stderr
        errors   (list[str])   – compiler errors extracted from stderr
        sanitizer_output (str) – any sanitizer diagnostic seen at build time
        command  (list[str])   – the exact compile command used
    """
    folder = Path(folder_path).resolve()
    sources = _collect_sources(folder)

    if not sources:
        return {
            "success": False, "binary": None,
            "warnings": [], "errors": ["No C/C++ source files found"],
            "sanitizer_output": "", "command": [],
        }

    compiler  = _choose_compiler(sources)
    san_flags = _SANITIZER_FLAGS[mode]
    inc_flags = [f"-I{i}" for i in (extra_includes or [])]
    out_dir   = Path(tempfile.gettempdir()) / "memhack_build"
    out_dir.mkdir(parents=True, exist_ok=True)
    binary    = str(out_dir / output_name)

    cmd = (
        [compiler]
        + _BASE_FLAGS
        + san_flags
        + inc_flags
        + (extra_flags or [])
        + ["-o", binary]
        + [str(s) for s in sources]
    )

    if verbose:
        print(colour(f"  $ {' '.join(cmd)}", Colour.WHITE))

    result = {
        "success": False,
        "binary": None,
        "warnings": [],
        "errors": [],
        "sanitizer_output": "",
        "command": cmd,
    }

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        result["errors"].append(f"Compiler '{compiler}' not found. Install gcc/g++.")
        return result
    except subprocess.TimeoutExpired:
        result["errors"].append("Compilation timed out after 120 s.")
        return result

    stderr_lines = proc.stderr.splitlines()

    for line in stderr_lines:
        if re.search(r"error:", line):
            result["errors"].append(line)
        elif re.search(r"warning:", line):
            result["warnings"].append(line)
        # Sanitizer runtime messages start with "==" or "SUMMARY:"
        elif re.search(r"^==\d+==|SUMMARY:", line):
            result["sanitizer_output"] += line + "\n"

    if proc.returncode == 0:
        result["success"] = True
        result["binary"]  = binary
        print(colour(f"  [✓] Compiled → {binary}  (mode={mode.name})", Colour.GREEN))
        if result["warnings"]:
            print(colour(f"  [!] {len(result['warnings'])} warning(s)", Colour.YELLOW))
        if verbose:
            for w in result["warnings"]:
                print(colour(f"      {w}", Colour.YELLOW))
    else:
        print(colour(f"  [✗] Compilation failed ({len(result['errors'])} error(s))", Colour.RED))
        for e in result["errors"][:10]:
            print(colour(f"      {e}", Colour.RED))

    return result
