#!/usr/bin/env python3
"""
memhack - Dynamic C/C++ Vulnerability Analysis Tool
Entry point and CLI orchestrator
"""

import os
import sys
import argparse
from pathlib import Path

from memhack.compile_sanitize import compile_and_sanitize, SanitizerMode
from memhack.parse_source     import parse_source_code
from memhack.runtime_exec     import perform_runtime_execution
from memhack.symbolic_exec    import perform_symbolic_execution
from memhack.taint_analysis   import perform_taint_analysis
from memhack.vuln_detect      import perform_vulnerability_detection
from memhack.report           import generate_report
from memhack.utils            import banner, colour, Colour


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memhack",
        description="Dynamic C/C++ vulnerability analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py /path/to/source
  python main.py /path/to/source --sanitizer asan --output-format html
  python main.py /path/to/source --skip-symbolic --max-runs 100
  python main.py /path/to/source --sanitizer ubsan --output-format json
""",
    )
    p.add_argument("folder", help="Folder containing C/C++ source files")
    p.add_argument(
        "--sanitizer",
        choices=["asan", "ubsan", "tsan", "none"],
        default="asan",
        help="Sanitizer to enable during compilation (default: asan)",
    )
    p.add_argument("--extra-flags",    default="", help="Extra compiler flags (quoted string)")
    p.add_argument("--extra-includes", default="", help="Extra -I include paths (quoted string)")
    p.add_argument(
        "--skip-symbolic", action="store_true",
        help="Skip angr symbolic execution (faster; requires angr when omitted)",
    )
    p.add_argument(
        "--skip-runtime", action="store_true",
        help="Skip runtime execution stage (no sanitizer firing)",
    )
    p.add_argument(
        "--max-runs", type=int, default=60,
        help="Max number of binary executions in runtime stage (default: 60)",
    )
    p.add_argument(
        "--run-timeout", type=int, default=5,
        help="Seconds per individual binary execution (default: 5)",
    )
    p.add_argument(
        "--output-format", choices=["text", "json", "html"], default="html",
        help="Report format (default: html)",
    )
    p.add_argument("--report-dir", default="./reports", help="Directory to write reports")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return p


def validate_folder(folder: str) -> Path:
    p = Path(folder).resolve()
    if not p.exists():
        print(colour(f"[!] Folder does not exist: {p}", Colour.RED)); sys.exit(1)
    if not p.is_dir():
        print(colour(f"[!] Path is not a directory: {p}", Colour.RED)); sys.exit(1)
    sources = list(p.rglob("*.c")) + list(p.rglob("*.cpp")) + list(p.rglob("*.cc"))
    if not sources:
        print(colour(f"[!] No C/C++ source files found in: {p}", Colour.YELLOW)); sys.exit(1)
    print(colour(f"[+] Found {len(sources)} source file(s) in {p}", Colour.GREEN))
    return p


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline  (6 stages)
# ─────────────────────────────────────────────────────────────────────────────

def run_pipeline(args) -> dict:
    folder     = validate_folder(args.folder)
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "folder":   str(folder),
        "compile":  None,
        "parse":    None,
        "runtime":  None,
        "symbolic": None,
        "taint":    None,
        "vulns":    None,
    }

    # ── 1. Compile ────────────────────────────────────────────────────────
    print(colour("\n[1/6] Compiling with sanitizers…", Colour.CYAN))
    mode          = SanitizerMode[args.sanitizer.upper()]
    extra_flags   = args.extra_flags.split()   if args.extra_flags   else []
    extra_includes= args.extra_includes.split()if args.extra_includes else []
    compile_result = compile_and_sanitize(
        folder, mode,
        extra_flags=extra_flags,
        extra_includes=extra_includes,
        verbose=args.verbose,
    )
    results["compile"] = compile_result
    have_binary = bool(compile_result.get("binary"))
    if not have_binary:
        print(colour("[!] Compilation failed – dynamic stages will be skipped.", Colour.YELLOW))

    # ── 2. Static parse ───────────────────────────────────────────────────
    print(colour("\n[2/6] Parsing source code…", Colour.CYAN))
    results["parse"] = parse_source_code(folder, verbose=args.verbose)

    # ── 3. Runtime execution (sanitizers FIRE here) ───────────────────────
    if args.skip_runtime:
        print(colour("\n[3/6] Runtime execution skipped (--skip-runtime).", Colour.YELLOW))
        results["runtime"] = {"skipped": True}
    elif not have_binary:
        print(colour("\n[3/6] Runtime execution skipped (no binary).", Colour.YELLOW))
        results["runtime"] = {"skipped": True, "reason": "no binary"}
    else:
        print(colour("\n[3/6] Runtime execution – firing sanitizers…", Colour.CYAN))
        results["runtime"] = perform_runtime_execution(
            compile_result["binary"],
            timeout_per_run=args.run_timeout,
            max_runs=args.max_runs,
            verbose=args.verbose,
        )

    # ── 4. Symbolic execution ─────────────────────────────────────────────
    if args.skip_symbolic:
        print(colour("\n[4/6] Symbolic execution skipped (--skip-symbolic).", Colour.YELLOW))
        results["symbolic"] = {"skipped": True}
    elif have_binary:
        print(colour("\n[4/6] Running symbolic execution (angr)…", Colour.CYAN))
        results["symbolic"] = perform_symbolic_execution(
            compile_result["binary"], verbose=args.verbose
        )
    else:
        print(colour("\n[4/6] Symbolic execution skipped (no binary).", Colour.YELLOW))
        results["symbolic"] = {"skipped": True}

    # ── 5. Taint analysis ─────────────────────────────────────────────────
    if have_binary and not args.skip_symbolic:
        print(colour("\n[5/6] Running taint analysis…", Colour.CYAN))
        results["taint"] = perform_taint_analysis(
            compile_result["binary"], verbose=args.verbose
        )
    else:
        print(colour("\n[5/6] Taint analysis skipped.", Colour.YELLOW))
        results["taint"] = {"skipped": True}

    # ── 6. Aggregate + report ─────────────────────────────────────────────
    print(colour("\n[6/6] Aggregating findings…", Colour.CYAN))
    results["vulns"] = perform_vulnerability_detection(
        folder,
        parse_result=results["parse"],
        compile_result=compile_result,
        runtime_result=results["runtime"],
        symbolic_result=results["symbolic"],
        taint_result=results["taint"],
        binary=compile_result.get("binary") if have_binary else None,
        verbose=args.verbose,
    )

    print(colour("\n[*] Generating report…", Colour.CYAN))
    report_path = generate_report(
        results, output_dir=report_dir, fmt=args.output_format
    )
    print(colour(f"\n[✓] Report saved to: {report_path}", Colour.GREEN))
    _print_summary(results)
    return results


def _print_summary(results: dict):
    findings = (results.get("vulns") or {}).get("findings", [])
    if not findings:
        print(colour("\n[✓] No vulnerabilities detected.", Colour.GREEN))
        return
    sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev_count[f.get("severity", "INFO")] = sev_count.get(f.get("severity","INFO"), 0) + 1
    print(colour(f"\n[!] {len(findings)} finding(s):", Colour.YELLOW))
    for sev, cnt in sev_count.items():
        if cnt:
            c = {"CRITICAL": Colour.RED, "HIGH": Colour.RED,
                 "MEDIUM": Colour.YELLOW, "LOW": Colour.CYAN,
                 "INFO": Colour.WHITE}[sev]
            print(f"    {colour(sev, c)}: {cnt}")


if __name__ == "__main__":
    banner()
    parser = build_parser()
    args   = parser.parse_args()
    run_pipeline(args)
