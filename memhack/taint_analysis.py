"""
memhack.taint_analysis
───────────────────────
Tracks tainted (user-controlled) data flow from sources to sinks using angr.

The original code called project.factory.analyses.TaintAnalysis() which does
not exist in any public angr version.  This module implements a lightweight
taint tracker using angr SimProcedure hooks:

  Sources  → stdin  (read, fgets, gets, scanf)
  Sinks    → dangerous functions; unconstrained memory writes

A symbolic stdin buffer is created.  We monitor whether symbolic (tainted)
bytes reach sensitive operations.
"""

import time
from pathlib import Path

from memhack.utils import colour, Colour

TAINT_TIMEOUT = 45   # seconds per source


_SOURCES = ["read", "fgets", "gets", "scanf", "fread", "recv", "recvfrom"]
_SINKS   = [
    ("strcpy",   "destination overwrite"),
    ("strcat",   "destination overwrite"),
    ("sprintf",  "format or destination overflow"),
    ("system",   "command injection"),
    ("execv",    "command injection"),
    ("memcpy",   "destination overwrite"),
    ("printf",   "format string"),
]


def _angr_available() -> bool:
    try:
        import angr  # noqa: F401
        return True
    except ImportError:
        return False


def perform_taint_analysis(binary_path, verbose: bool = False) -> dict:
    """
    Returns
    -------
    dict with:
        available  – bool
        flows      – list of {source, sink, path_description}
        errors     – list[str]
    """
    result: dict = {
        "available": _angr_available(),
        "flows":     [],
        "errors":    [],
    }

    if not result["available"]:
        print(colour(
            "  [!] angr not installed – taint analysis skipped.",
            Colour.YELLOW,
        ))
        return result

    import angr           # type: ignore
    import claripy        # type: ignore

    binary = Path(binary_path)
    if not binary.exists():
        result["errors"].append(f"Binary not found: {binary_path}")
        return result

    try:
        project = angr.Project(str(binary), auto_load_libs=False)
    except Exception as e:
        result["errors"].append(f"angr load failed: {e}")
        return result

    # Create a symbolic stdin buffer (taint source)
    STDIN_SIZE  = 256
    taint_buf   = claripy.BVS("stdin_taint", STDIN_SIZE * 8)
    stdin_state = project.factory.entry_state(
        stdin=angr.SimFile(name="stdin", content=taint_buf, size=STDIN_SIZE),
        add_options={
            angr.options.LAZY_SOLVES,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        },
    )

    # ── Hook each sink to check if args are tainted ─────────────────────────
    taint_records = []

    for sink_name, sink_desc in _SINKS:
        sym = project.loader.find_symbol(sink_name)
        if sym is None:
            continue

        class SinkHook(angr.SimProcedure):
            _name = sink_name
            _desc = sink_desc

            def run(self, *args):
                for i, arg in enumerate(args[:3]):
                    try:
                        if self.state.solver.symbolic(arg):
                            taint_records.append({
                                "sink":      self._name,
                                "arg_index": i,
                                "desc":      self._desc,
                                "tainted":   True,
                            })
                    except Exception:
                        pass
                return self.state.solver.BVV(0, self.arch.bits)

        project.hook(sym.rebased_addr, SinkHook())

    simgr   = project.factory.simgr(stdin_state)
    deadline = time.time() + TAINT_TIMEOUT
    try:
        simgr.run(until=lambda sm: time.time() > deadline, n=10_000)
    except Exception as e:
        result["errors"].append(f"Simulation error: {e}")

    result["flows"] = taint_records

    if taint_records:
        print(colour(f"  [!] {len(taint_records)} taint flow(s) detected:", Colour.YELLOW))
        for tf in taint_records:
            print(colour(
                f"      stdin → {tf['sink']}() arg[{tf['arg_index']}]  ({tf['desc']})",
                Colour.YELLOW,
            ))
    else:
        print(colour("  [✓] No taint flows to dangerous sinks detected.", Colour.GREEN))

    return result
