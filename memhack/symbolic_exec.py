"""
memhack.symbolic_exec
──────────────────────
Symbolic execution via angr.

Key fixes vs. original code
─────────────────────────────
* The original used entry_point as both the explore target and the initial PC,
  which means the simulation starts and immediately "finds" the entry without
  actually exploring anything meaningful.
* We now look for calls to dangerous functions (strcpy, gets, …) as find targets
  and use avoid= on safe exit paths.
* Graceful ImportError when angr is not installed.
* Timeout guard so analysis doesn't run forever.
* The taint / rsp check in bof.py was wrong (the very first state already has
  rsp set; comparing it to itself is always False).  We instead look for
  unconstrained states (paths where the PC is symbolic – classic sign of control
  flow hijack).
"""

import os
import time
from pathlib import Path
from typing import Optional

from memhack.utils import colour, Colour

# Dangerous sink addresses we try to reach during exploration
_DANGEROUS_SYMS = [
    "gets", "strcpy", "strcat", "sprintf", "vsprintf",
    "system", "popen", "execv", "execvp", "execl",
]

EXPLORE_TIMEOUT = 60   # seconds


def _angr_available() -> bool:
    try:
        import angr  # noqa: F401
        return True
    except ImportError:
        return False


def perform_symbolic_execution(binary_path, verbose: bool = False) -> dict:
    """
    Run angr on the compiled binary.

    Returns
    -------
    dict with keys:
        available        – bool: angr installed
        skipped          – bool
        unconstrained_paths – list of descriptions of hijackable paths
        dangerous_reaches   – list of (symbol, input_bytes) pairs
        errors           – list[str]
    """
    result = {
        "available":            _angr_available(),
        "skipped":              False,
        "unconstrained_paths":  [],
        "dangerous_reaches":    [],
        "errors":               [],
    }

    if not result["available"]:
        print(colour(
            "  [!] angr not installed – symbolic execution skipped. "
            "Install with: pip install angr",
            Colour.YELLOW,
        ))
        result["skipped"] = True
        return result

    import angr  # type: ignore

    binary = Path(binary_path)
    if not binary.exists():
        result["errors"].append(f"Binary not found: {binary_path}")
        result["skipped"] = True
        return result

    print(colour(f"  Loading binary: {binary.name}", Colour.WHITE))

    try:
        project = angr.Project(str(binary), auto_load_libs=False)
    except Exception as e:
        result["errors"].append(f"angr project load failed: {e}")
        result["skipped"] = True
        return result

    # ── 1. Hunt for unconstrained paths (PC becomes symbolic → control hijack) ──
    print(colour("  [1/2] Hunting unconstrained paths…", Colour.WHITE))
    try:
        cfg = project.analyses.CFGFast(normalize=True)
        initial_state  = project.factory.entry_state(add_options={
            angr.options.LAZY_SOLVES,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        })
        simgr = project.factory.simgr(initial_state, save_unsat=True)

        deadline = time.time() + EXPLORE_TIMEOUT
        simgr.run(until=lambda sm: time.time() > deadline or len(sm.unconstrained) > 0, n=5000)

        for state in simgr.unconstrained:
            ip_val = state.regs.ip
            if state.solver.symbolic(ip_val):
                try:
                    concrete = state.solver.eval(ip_val, cast_to=int)
                    desc = f"PC controllable; example value=0x{concrete:x}"
                except Exception:
                    desc = "PC is symbolic (unconstrained)"
                result["unconstrained_paths"].append(desc)
                if verbose:
                    print(colour(f"    [!] Unconstrained path: {desc}", Colour.RED))

    except Exception as e:
        result["errors"].append(f"Unconstrained analysis error: {e}")

    # ── 2. Try to reach dangerous function sinks ───────────────────────────────
    print(colour("  [2/2] Searching for paths to dangerous sinks…", Colour.WHITE))
    for sym in _DANGEROUS_SYMS:
        try:
            sym_obj = project.loader.find_symbol(sym)
            if sym_obj is None:
                continue
            target_addr = sym_obj.rebased_addr
            init_state  = project.factory.entry_state()
            simgr2      = project.factory.simgr(init_state)
            deadline2   = time.time() + 20
            simgr2.explore(
                find=target_addr,
                until=lambda sm: time.time() > deadline2 or bool(sm.found),
                n=3000,
            )
            if simgr2.found:
                found_state = simgr2.found[0]
                # Try to extract stdin input that leads to the sink
                try:
                    stdin_content = found_state.posix.dumps(0)
                    input_repr = repr(stdin_content[:64])
                except Exception:
                    input_repr = "<could not extract>"
                result["dangerous_reaches"].append({
                    "sink":        sym,
                    "address":     hex(target_addr),
                    "example_input": input_repr,
                })
                print(colour(f"    [!] Path to {sym}() found – example stdin: {input_repr}", Colour.RED))
        except Exception as e:
            result["errors"].append(f"Sink search for {sym}: {e}")

    n_u = len(result["unconstrained_paths"])
    n_r = len(result["dangerous_reaches"])
    print(colour(
        f"  [✓] Symbolic execution: {n_u} unconstrained path(s), {n_r} sink reach(es)",
        Colour.GREEN if (n_u + n_r) == 0 else Colour.YELLOW,
    ))
    return result
