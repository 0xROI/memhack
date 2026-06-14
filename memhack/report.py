"""
memhack.report
───────────────
Generates vulnerability reports in three formats:
  text  – coloured terminal-friendly plain text file
  json  – machine-readable structured output
  html  – self-contained interactive HTML report
"""

import json
import datetime
from pathlib import Path
from typing import Dict

from memhack.utils import colour, Colour

SEVERITY_COLOUR_HTML = {
    "CRITICAL": "#ff4d4d",
    "HIGH":     "#ff8c42",
    "MEDIUM":   "#ffd166",
    "LOW":      "#06d6a0",
    "INFO":     "#8ecae6",
}

SEVERITY_BG_HTML = {
    "CRITICAL": "#2d0000",
    "HIGH":     "#2d1200",
    "MEDIUM":   "#2d2200",
    "LOW":      "#002d1e",
    "INFO":     "#001e2d",
}


# ── Text report ───────────────────────────────────────────────────────────────

def _write_text(results: dict, path: Path) -> Path:
    findings = results.get("vulns", {}).get("findings", [])
    stats    = results.get("vulns", {}).get("stats", {})
    now      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "=" * 70,
        "  MEMHACK – Dynamic C/C++ Vulnerability Analysis Report",
        f"  Generated : {now}",
        f"  Target    : {results.get('folder', 'N/A')}",
        "=" * 70,
        "",
        "SUMMARY",
        "-------",
    ]
    for sev, cnt in stats.items():
        if cnt:
            lines.append(f"  {sev:<10} : {cnt}")
    lines += ["", f"TOTAL: {len(findings)} finding(s)", "", "=" * 70, "FINDINGS", "=" * 70, ""]

    for f in findings:
        lines += [
            f"[{f['id']}] {f['severity']} – {f['title']}",
            f"  CWE        : {f.get('cwe', 'N/A')}",
            f"  Source     : {f.get('source', 'N/A')}",
            f"  File       : {f.get('file', 'N/A')} (line {f.get('line', 0)})",
            f"  Code       : {f.get('code', '')}",
            f"  Description: {f.get('description', '')}",
            f"  Mitigation : {f.get('mitigation', '')}",
            "",
            "-" * 70,
            "",
        ]

    out = path.with_suffix(".txt")
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


# ── JSON report ───────────────────────────────────────────────────────────────

def _write_json(results: dict, path: Path) -> Path:
    out_data = {
        "tool":      "memhack",
        "version":   "1.0.0",
        "generated": datetime.datetime.now().isoformat(),
        "target":    results.get("folder"),
        "stats":     results.get("vulns", {}).get("stats", {}),
        "findings":  results.get("vulns", {}).get("findings", []),
        "compile":   {
            "success":  results.get("compile", {}).get("success"),
            "warnings": len(results.get("compile", {}).get("warnings", [])),
            "errors":   len(results.get("compile", {}).get("errors", [])),
        },
        "parse": {
            "total_functions":       results.get("parse", {}).get("total_functions", 0),
            "total_dangerous_calls": results.get("parse", {}).get("total_dangerous_calls", 0),
        },
    }
    out = path.with_suffix(".json")
    out.write_text(json.dumps(out_data, indent=2), encoding="utf-8")
    return out


# ── HTML report ───────────────────────────────────────────────────────────────

def _finding_card(f: dict) -> str:
    sev      = f.get("severity", "INFO")
    border   = SEVERITY_COLOUR_HTML.get(sev, "#8ecae6")
    bg       = SEVERITY_BG_HTML.get(sev, "#001e2d")
    code     = f.get("code", "").replace("<", "&lt;").replace(">", "&gt;")
    cwe_link = (
        f'<a href="https://cwe.mitre.org/data/definitions/{f["cwe"].replace("CWE-","")}.html" '
        f'target="_blank" style="color:{border}">{f["cwe"]}</a>'
        if f.get("cwe") else "N/A"
    )

    # Verification badge
    verification = f.get("verification", {})
    ver_status = verification.get("status", "UNVERIFIED")
    ver_color = {"CONFIRMED": "#06d6a0", "LIKELY": "#ffd166", "UNVERIFIED": "#888"}.get(ver_status, "#888")

    # PoC info
    poc = f.get("poc", {})
    poc_id = f"poc_{f['id'].replace('-','_')}" if f.get("id") else "poc"

    # Trigger and evidence
    trigger = verification.get("trigger", "N/A")
    evidence = verification.get("evidence", "")
    crash_type = verification.get("crash_type", "")

    mitigation_text = poc.get("mitigation", f.get("mitigation", ""))

    # Build PoC code blocks
    c_code = poc.get("c", "")
    py_code = poc.get("python", "")
    gdb_cmds = poc.get("gdb", "")

    poc_c_html = f'<pre style="background:#000;color:#0f0;padding:10px;border-radius:3px;overflow-x:auto;font-size:0.75em;max-height:300px">{c_code[:2500]}</pre>' if c_code and "/*" in c_code else ""
    poc_py_html = f'<pre style="background:#000;color:#0f0;padding:10px;border-radius:3px;overflow-x:auto;font-size:0.75em;max-height:300px">{py_code[:2500]}</pre>' if py_code and "#!" in py_code else ""
    poc_gdb_html = f'<pre style="background:#000;color:#0f0;padding:10px;border-radius:3px;overflow-x:auto;font-size:0.75em;max-height:300px">{gdb_cmds[:2000]}</pre>' if gdb_cmds and "#" in gdb_cmds else ""

    card_html = f"""
<div class="card" style="border-left:4px solid {border};background:{bg};margin:12px 0;padding:16px;border-radius:6px;font-family:monospace;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <span style="color:{border};font-weight:bold;font-size:0.9em">[{f['id']}] {f['title']}</span>
    <div style="display:flex;gap:8px">
      <span style="background:{border};color:#0d0d0d;padding:2px 10px;border-radius:12px;font-size:0.75em;font-weight:bold">{sev}</span>
      <span style="background:{ver_color};color:#0d0d0d;padding:2px 10px;border-radius:12px;font-size:0.75em;font-weight:bold">✓ {ver_status}</span>
    </div>
  </div>

  <table style="width:100%;border-collapse:collapse;font-size:0.82em;color:#ccc;margin-bottom:12px">
    <tr><td style="width:120px;color:#888;padding:2px 0">CWE</td><td>{cwe_link}</td></tr>
    <tr><td style="color:#888;padding:2px 0">Source</td><td>{f.get('source','')}</td></tr>
    <tr><td style="color:#888;padding:2px 0">File</td><td>{f.get('file','N/A')} : line {f.get('line',0)}</td></tr>
    {f"<tr><td style='color:#888;padding:2px 0'>Code</td><td><code style='background:#111;padding:2px 6px;border-radius:3px'>{code}</code></td></tr>" if code else ""}
    <tr><td style="color:#888;padding:2px 0;vertical-align:top">Description</td><td>{f.get('description','')}</td></tr>
  </table>

  <!-- Verification details -->
  <div style="background:#0a0a0a;padding:10px;border-radius:4px;margin-bottom:12px;border:1px solid #222">
    <div style="color:#06d6a0;font-weight:bold;margin-bottom:6px">📋 Verification</div>
    <table style="width:100%;font-size:0.78em;color:#aaa">
      <tr><td style="color:#666">Status</td><td style="color:{ver_color};font-weight:bold">{ver_status}</td></tr>
      <tr><td style="color:#666">Crash Type</td><td>{crash_type or "N/A"}</td></tr>
      <tr><td style="color:#666;vertical-align:top">Trigger</td><td style="color:#06d6a0">{trigger}</td></tr>
      <tr><td style="color:#666;vertical-align:top">Evidence</td><td><pre style="background:#000;color:#0f0;padding:6px;font-size:0.7em;overflow-x:auto;max-height:200px">{evidence[:500]}</pre></td></tr>
    </table>
  </div>

  <!-- PoC Tabs -->
  <div style="margin-bottom:12px">
    <div id="{poc_id}_tabs" style="display:flex;gap:4px;border-bottom:1px solid #333;margin-bottom:8px;flex-wrap:wrap">
      <button onclick="togglePoc('{poc_id}','c')" style="background:#1a1a1a;color:#06d6a0;border:none;padding:6px 12px;cursor:pointer;border-bottom:2px solid #06d6a0;font-size:0.75em">C Reproducer</button>
      <button onclick="togglePoc('{poc_id}','python')" style="background:#1a1a1a;color:#888;border:none;padding:6px 12px;cursor:pointer;border-bottom:2px solid transparent;font-size:0.75em">Python Harness</button>
      <button onclick="togglePoc('{poc_id}','gdb')" style="background:#1a1a1a;color:#888;border:none;padding:6px 12px;cursor:pointer;border-bottom:2px solid transparent;font-size:0.75em">GDB Session</button>
      <button onclick="togglePoc('{poc_id}','mitigation')" style="background:#1a1a1a;color:#888;border:none;padding:6px 12px;cursor:pointer;border-bottom:2px solid transparent;font-size:0.75em">Mitigation</button>
    </div>

    <div id="{poc_id}_c" style="display:block">
      {poc_c_html}
    </div>
    <div id="{poc_id}_python" style="display:none">
      {poc_py_html}
    </div>
    <div id="{poc_id}_gdb" style="display:none">
      {poc_gdb_html}
    </div>
    <div id="{poc_id}_mitigation" style="display:none;color:#06d6a0;font-size:0.78em;white-space:pre-wrap;background:#0a0a0a;padding:10px;border-radius:3px;max-height:400px;overflow-y:auto">
      {mitigation_text}
    </div>
  </div>
</div>

<script>
function togglePoc(id, tab) {{
    ['c','python','gdb','mitigation'].forEach(t => {{
        document.getElementById(id+'_'+t).style.display = (t===tab) ? 'block' : 'none';
    }});
    // Change button colors
    document.getElementById(id+'_tabs').querySelectorAll('button').forEach(btn => {{
        let btnTab = btn.innerText.toLowerCase().includes('c repro') ? 'c' :
                     btn.innerText.toLowerCase().includes('python') ? 'python' :
                     btn.innerText.toLowerCase().includes('gdb') ? 'gdb' : 'mitigation';
        btn.style.color = (btnTab === tab) ? '#06d6a0' : '#888';
        btn.style.borderBottomColor = (btnTab === tab) ? '#06d6a0' : 'transparent';
    }});
}}
</script>
"""
    return card_html


def _write_html(results: dict, path: Path) -> Path:
    findings = results.get("vulns", {}).get("findings", [])
    stats    = results.get("vulns", {}).get("stats", {})
    now      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    folder   = results.get("folder", "N/A")

    # Stats bar
    total = max(len(findings), 1)
    stat_bars = ""
    for sev, cnt in stats.items():
        if cnt:
            col = SEVERITY_COLOUR_HTML.get(sev, "#8ecae6")
            pct = cnt / total * 100
            stat_bars += f"""
            <div style="display:flex;align-items:center;gap:12px;margin:6px 0">
              <span style="width:80px;color:{col};font-weight:bold;font-size:0.85em">{sev}</span>
              <div style="flex:1;background:#1a1a1a;border-radius:4px;height:18px">
                <div style="width:{pct:.0f}%;background:{col};height:18px;border-radius:4px;min-width:4px"></div>
              </div>
              <span style="width:30px;color:{col};text-align:right">{cnt}</span>
            </div>"""

    # Severity filter buttons
    sevs = ["ALL"] + [s for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] if stats.get(s,0) > 0]
    filter_btns = ""
    for s in sevs:
        col = SEVERITY_COLOUR_HTML.get(s, "#ffffff")
        filter_btns += f"""<button onclick="filterSev('{s}')"
          style="background:{'#1e1e1e' if s!='ALL' else '#2a2a2a'};color:{col};
                 border:1px solid {col};padding:5px 14px;border-radius:14px;
                 cursor:pointer;font-size:0.8em;margin:3px">{s}</button>"""

    # Finding cards
    cards_html = "".join(_finding_card(f) for f in findings) if findings else \
        "<p style='color:#06d6a0;text-align:center;padding:40px'>✓ No vulnerabilities detected</p>"

    # Compile info
    compile_ok   = results.get("compile", {}).get("success", False)
    parse_info   = results.get("parse", {}) or {}
    runtime_info = results.get("runtime", {}) or {}
    sym_info     = results.get("symbolic", {}) or {}
    taint_info   = results.get("taint", {}) or {}

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>memhack Report – {now}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d0d0d;color:#e0e0e0;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}}
  header{{background:#111;border-bottom:1px solid #222;padding:20px 32px;display:flex;justify-content:space-between;align-items:center}}
  .logo{{font-family:monospace;font-size:1.4em;color:#06d6a0;letter-spacing:2px;font-weight:bold}}
  .subtitle{{color:#555;font-size:0.8em;margin-top:4px}}
  .meta{{color:#555;font-size:0.8em;text-align:right}}
  .container{{max-width:1100px;margin:0 auto;padding:24px 20px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:28px}}
  .stat-box{{background:#111;border:1px solid #222;border-radius:8px;padding:18px;text-align:center}}
  .stat-box .num{{font-size:2em;font-weight:bold;color:#06d6a0}}
  .stat-box .lbl{{color:#666;font-size:0.8em;margin-top:4px}}
  .section{{background:#111;border:1px solid #1e1e1e;border-radius:10px;padding:20px;margin-bottom:20px}}
  .section-title{{color:#8ecae6;font-size:1em;font-weight:bold;margin-bottom:14px;letter-spacing:1px;text-transform:uppercase}}
  .filters{{margin-bottom:16px}}
  .pipeline-row{{display:flex;gap:10px;flex-wrap:wrap}}
  .pip{{flex:1;min-width:150px;background:#151515;border-radius:8px;padding:12px;border:1px solid #222;text-align:center;font-size:0.82em}}
  .pip .pip-label{{color:#888;margin-bottom:6px}}
  .ok{{color:#06d6a0}} .fail{{color:#ff4d4d}} .skip{{color:#888}}
  a{{text-decoration:none}}
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">▶ MEMHACK</div>
    <div class="subtitle">Dynamic C/C++ Vulnerability Analysis</div>
  </div>
  <div class="meta">
    <div>{now}</div>
    <div style="margin-top:4px;max-width:300px;word-break:break-all">{folder}</div>
  </div>
</header>

<div class="container">

  <!-- Top stats -->
  <div class="grid" style="margin-top:20px">
    <div class="stat-box"><div class="num">{len(findings)}</div><div class="lbl">Total Findings</div></div>
    <div class="stat-box"><div class="num" style="color:#ff4d4d">{stats.get('CRITICAL',0)+stats.get('HIGH',0)}</div><div class="lbl">Critical / High</div></div>
    <div class="stat-box"><div class="num">{parse_info.get('total_functions',0)}</div><div class="lbl">Functions Analysed</div></div>
    <div class="stat-box"><div class="num">{parse_info.get('total_dangerous_calls',0)}</div><div class="lbl">Dangerous Calls</div></div>
  </div>

  <!-- Pipeline status -->
  <div class="section">
    <div class="section-title">Analysis Pipeline</div>
    <div class="pipeline-row">
      <div class="pip"><div class="pip-label">Compilation</div>
        <div class="{'ok' if compile_ok else 'fail'}">{'✓ Success' if compile_ok else '✗ Failed'}</div></div>
      <div class="pip"><div class="pip-label">Static Parse</div>
        <div class="ok">✓ {len(parse_info.get('files',[]))} file(s)</div></div>
      <div class="pip"><div class="pip-label">Runtime / ASan</div>
        <div class="{'skip' if runtime_info.get('skipped') else 'ok'}">
          {'⊘ Skipped' if runtime_info.get('skipped') else
           f"✓ {runtime_info.get('runs_total',0)} runs · {runtime_info.get('runs_crashed',0)} crash(es)"}</div></div>
      <div class="pip"><div class="pip-label">Symbolic Exec</div>
        <div class="{'skip' if sym_info.get('skipped') else 'ok'}">
          {'⊘ Skipped' if sym_info.get('skipped') else f"✓ {len(sym_info.get('unconstrained_paths',[]))} path(s)"}</div></div>
      <div class="pip"><div class="pip-label">Taint Analysis</div>
        <div class="{'skip' if taint_info.get('skipped') else 'ok'}">
          {'⊘ Skipped' if taint_info.get('skipped') else f"✓ {len(taint_info.get('flows',[]))} flow(s)"}</div></div>
    </div>
  </div>

  <!-- Severity breakdown -->
  <div class="section">
    <div class="section-title">Severity Breakdown</div>
    {stat_bars}
  </div>

  <!-- Findings -->
  <div class="section">
    <div class="section-title">Findings</div>
    <div class="filters">{filter_btns}</div>
    <div id="findings-list">
      {cards_html}
    </div>
  </div>

</div>

<script>
function filterSev(sev) {{
  document.querySelectorAll('.card').forEach(el => {{
    if (sev === 'ALL') {{ el.style.display = ''; return; }}
    el.style.display = el.innerText.includes(sev) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    out = path.with_suffix(".html")
    out.write_text(html, encoding="utf-8")
    return out


# ── Public entry point ────────────────────────────────────────────────────────

def generate_report(results: dict, output_dir: Path, fmt: str = "html") -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = output_dir / f"memhack_report_{ts}"

    writers = {"text": _write_text, "json": _write_json, "html": _write_html}
    writer  = writers.get(fmt, _write_html)
    return writer(results, base)
