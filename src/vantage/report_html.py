"""HTML rendering for vantage reports.

Self-contained, theme-aware (light/dark) HTML for both the red-team findings
report and the OSINT risk assessment. Colours use the validated status palette
(good/warning/serious/critical) — always paired with a text label, never colour
alone — and a single blue ramp for magnitude bars.
"""

from __future__ import annotations

import html

# --- palette (from the dataviz reference instance) -------------------------

_CSS = """
:root {
  color-scheme: light;
  --page:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink-2:#52514e;
  --muted:#898781; --grid:#e1e0d9; --border:rgba(11,11,11,0.10);
  --track:#eceae4; --series-1:#2a78d6;
  --good:#0ca30c; --warning:#fab219; --serious:#ec835a; --critical:#d03b3b;
  --shadow:0 1px 2px rgba(11,11,11,.04),0 8px 24px rgba(11,11,11,.06);
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    color-scheme:dark;
    --page:#0d0d0d; --surface:#1a1a19; --ink:#fff; --ink-2:#c3c2b7;
    --muted:#898781; --grid:#2c2c2a; --border:rgba(255,255,255,0.10);
    --track:#2c2c2a; --series-1:#3987e5;
    --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.4);
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);
  font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.55;
  -webkit-font-smoothing:antialiased;}
.wrap{max-width:880px;margin:0 auto;padding:40px 20px 72px;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;
  box-shadow:var(--shadow);padding:36px 40px;}
header.rpt{display:flex;align-items:flex-start;gap:16px;margin-bottom:8px;}
header.rpt .logo{flex:none;width:40px;height:40px;color:var(--series-1);}
h1{font-size:24px;line-height:1.2;margin:0 0 2px;letter-spacing:-.01em;}
.sub{color:var(--ink-2);font-size:14px;margin:0;}
.meta{color:var(--muted);font-size:12.5px;margin-top:10px;
  display:flex;flex-wrap:wrap;gap:6px 18px;}
.meta b{color:var(--ink-2);font-weight:600;}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
  margin:38px 0 14px;font-weight:600;}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;}
.tile{background:var(--page);border:1px solid var(--border);border-radius:12px;
  padding:14px 16px;}
.tile .n{font-size:26px;font-weight:650;letter-spacing:-.02em;}
.tile .l{font-size:12px;color:var(--muted);margin-top:2px;}
.chip{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;
  padding:3px 9px 3px 8px;border-radius:999px;border:1px solid var(--border);
  white-space:nowrap;}
.chip .dot{width:8px;height:8px;border-radius:50%;flex:none;background:var(--c);}
.chip.sev{color:var(--ink-2);}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:2px;}
th{text-align:left;font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;
  color:var(--muted);font-weight:600;padding:0 12px 8px;border-bottom:1px solid var(--grid);}
td{padding:10px 12px;border-bottom:1px solid var(--grid);vertical-align:top;
  font-variant-numeric:tabular-nums;}
tr:last-child td{border-bottom:none;}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;}
.finding{border:1px solid var(--border);border-left:3px solid var(--c);border-radius:12px;
  padding:16px 18px;margin-bottom:12px;background:var(--page);}
.finding h3{margin:0 0 8px;font-size:15px;display:flex;align-items:center;
  gap:10px;flex-wrap:wrap;}
.finding h3 .cve{font-family:ui-monospace,Menlo,monospace;font-size:13px;color:var(--ink-2);}
.finding .row{font-size:13px;color:var(--ink-2);margin:3px 0;}
.finding a{color:var(--series-1);text-decoration:none;}
.finding a:hover{text-decoration:underline;}
.rank{flex:none;width:22px;height:22px;border-radius:50%;background:var(--track);
  color:var(--ink-2);font-size:12px;font-weight:700;display:grid;place-items:center;}
/* risk hero + gauge */
.hero{display:flex;align-items:center;gap:24px;flex-wrap:wrap;
  padding:22px 24px;border:1px solid var(--border);border-radius:14px;background:var(--page);}
.hero .score{font-size:56px;font-weight:680;letter-spacing:-.03em;line-height:1;color:var(--c);}
.hero .of{font-size:20px;color:var(--muted);font-weight:500;}
.hero .band{margin-top:6px;}
.gauge{flex:1;min-width:240px;}
.gauge .track{position:relative;height:12px;background:var(--track);border-radius:999px;overflow:hidden;}
.gauge .fill{position:absolute;left:0;top:0;bottom:0;background:var(--c);
  border-radius:999px 4px 4px 999px;}
.gauge .ticks{display:flex;justify-content:space-between;margin-top:7px;
  font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums;}
/* factor bars */
.bars{display:flex;flex-direction:column;gap:11px;}
.bar-row{display:grid;grid-template-columns:150px 1fr;gap:14px;align-items:center;}
.bar-row .name{font-size:13px;color:var(--ink-2);text-transform:capitalize;}
.bar-track{position:relative;height:22px;background:var(--track);border-radius:6px;}
.bar-fill{position:absolute;left:0;top:0;bottom:0;background:var(--series-1);
  border-radius:6px 4px 4px 6px;min-width:3px;}
.bar-val{position:absolute;top:0;bottom:0;display:flex;align-items:center;
  padding-left:9px;font-size:12px;font-weight:600;color:#fff;
  font-variant-numeric:tabular-nums;}
.scen{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:9px;}
.scen li{border:1px solid var(--border);border-radius:10px;padding:11px 14px;
  background:var(--page);font-size:13.5px;}
.scen .en{color:var(--muted);font-size:12.5px;margin-top:2px;}
ol.rem{margin:0;padding-left:20px;font-size:13.5px;}
ol.rem li{margin:6px 0;}
footer.rpt{margin-top:32px;padding-top:16px;border-top:1px solid var(--grid);
  color:var(--muted);font-size:12px;}
.note{background:var(--page);border:1px solid var(--border);border-radius:10px;
  padding:10px 14px;font-size:12.5px;color:var(--ink-2);margin-bottom:22px;}
"""

_SHIELD = (
    '<svg class="logo" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" '
    'aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6z"/>'
    '<path d="M9 12l2 2 4-4"/></svg>'
)

# severity (vuln): Low is still a weakness -> neutral, not green
_SEV_COLOR = {
    "Critical": "var(--critical)", "High": "var(--serious)",
    "Medium": "var(--warning)", "Low": "var(--muted)", "None": "var(--muted)",
}
# risk band: Low genuinely means low risk -> green
_BAND_COLOR = {
    "Critical": "var(--critical)", "High": "var(--serious)",
    "Moderate": "var(--warning)", "Low": "var(--good)",
}


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{_e(title)}</title><style>{_CSS}</style></head>"
        f"<body><div class=\"wrap\"><div class=\"card\">{body}</div></div></body></html>"
    )


def _severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0.0:
        return "Low"
    return "None"


def _chip(label: str, color: str) -> str:
    return (f'<span class="chip sev" style="--c:{color}">'
            f'<span class="dot"></span>{_e(label)}</span>')


def render_findings_html(recon_result: dict, analysis: dict) -> str:
    target = analysis.get("target") or recon_result.get("target") or "unknown"
    s = analysis.get("summary", {})
    max_cvss = s.get("max_cvss", 0.0)
    top_sev = _severity(max_cvss)

    b = []
    b.append('<header class="rpt">' + _SHIELD +
             f'<div><h1>Red Team Findings</h1><p class="sub">{_e(target)}</p></div></header>')
    meta = [f'<span><b>Scope:</b> {_e(analysis.get("matched_scope") or "—")}</span>']
    if analysis.get("scanned_at"):
        meta.append(f'<span><b>Scanned:</b> {_e(analysis["scanned_at"])}</span>')
    b.append(f'<div class="meta">{"".join(meta)}</div>')

    b.append('<h2>Summary</h2><div class="tiles">')
    b.append(f'<div class="tile"><div class="n">{s.get("open_services",0)}</div>'
             '<div class="l">Open services</div></div>')
    b.append(f'<div class="tile"><div class="n">{s.get("findings",0)}</div>'
             '<div class="l">Findings</div></div>')
    b.append(f'<div class="tile"><div class="n">{s.get("with_public_exploit",0)}</div>'
             '<div class="l">Public exploit</div></div>')
    b.append('<div class="tile"><div class="n" style="font-size:15px;padding-top:6px">'
             f'{_chip(top_sev, _SEV_COLOR[top_sev])}</div>'
             f'<div class="l">Top severity · CVSS {max_cvss}</div></div>')
    b.append('</div>')

    b.append('<h2>Open services</h2><table><thead><tr>'
             '<th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th>'
             '</tr></thead><tbody>')
    for host in recon_result.get("hosts", []):
        for p in host.get("ports", []):
            if p.get("state") != "open":
                continue
            b.append(
                f'<tr><td class="mono">{_e(host.get("address"))}</td>'
                f'<td class="mono">{_e(p.get("port"))}/{_e(p.get("protocol"))}</td>'
                f'<td>{_e(p.get("service"))}</td><td>{_e(p.get("product"))}</td>'
                f'<td class="mono">{_e(p.get("version"))}</td></tr>')
    b.append('</tbody></table>')

    b.append('<h2>Findings — ranked by exploitability</h2>')
    findings = analysis.get("findings", [])
    if not findings:
        b.append('<div class="note">No known CVEs matched the enumerated services.</div>')
    for i, f in enumerate(findings, 1):
        sev = _severity(f["cvss"])
        color = _SEV_COLOR[sev]
        exploit = "public exploit" if f["exploit_available"] else "no public exploit"
        refs = "".join(
            f'<div class="row">↗ <a href="{_e(r)}">{_e(r)}</a></div>'
            for r in f.get("references", []))
        b.append(
            f'<div class="finding" style="--c:{color}">'
            f'<h3><span class="rank">{i}</span>'
            f'<span class="cve">{_e(f["cve"])}</span> {_e(f["title"])}</h3>'
            f'<div class="row">{_chip(sev, color)} '
            f'<span style="color:var(--muted)">CVSS {f["cvss"]} · {exploit}</span></div>'
            f'<div class="row"><b>Affected:</b> {_e(f["product"])} {_e(f["version"])} '
            f'on {_e(f["host"])}:{_e(f["port"])}/{_e(f["protocol"])} ({_e(f["service"])})</div>'
            f'{refs}</div>')

    b.append('<footer class="rpt">Generated by vantage · enumeration and analysis '
             'only — no exploitation was performed.</footer>')
    return _page(f"Red Team Findings — {target}", "".join(b))


def render_osint_html(assessment: dict) -> str:
    subj = assessment["subject"]
    score = assessment["score"]
    band = assessment["band"]
    color = _BAND_COLOR.get(band, "var(--muted)")

    b = []
    b.append('<header class="rpt">' + _SHIELD +
             f'<div><h1>OSINT Risk Assessment</h1>'
             f'<p class="sub">{_e(subj)} · {_e(assessment["kind"])} subject</p></div></header>')

    # hero + gauge
    b.append(
        f'<div class="hero" style="--c:{color}"><div>'
        f'<span class="score">{score}</span><span class="of"> / 100</span>'
        f'<div class="band">{_chip(band, color)}</div></div>'
        f'<div class="gauge"><div class="track">'
        f'<div class="fill" style="width:{score}%"></div></div>'
        '<div class="ticks"><span>0 Low</span><span>25</span><span>50</span>'
        '<span>75</span><span>100 Critical</span></div></div></div>')

    # factor bars — contribution to risk (weighted points), single blue hue
    b.append('<h2>Factor breakdown</h2><div class="bars">')
    max_pts = 15  # max single-factor contribution (rating 3 × top weight 5)
    for f in assessment["factors"]:
        pts = f["weighted"]
        w = max(3, round(pts / max_pts * 100))
        b.append(
            f'<div class="bar-row"><div class="name">{_e(f["factor"].replace("_"," "))}</div>'
            f'<div class="bar-track" title="{_e(f["rationale"])}">'
            f'<div class="bar-fill" style="width:{w}%"></div>'
            f'<div class="bar-val">{pts} pts · rating {f["rating"]}/3</div></div></div>')
    b.append('</div>')

    scen = assessment.get("scenarios", [])
    b.append('<h2>Attack scenarios</h2>')
    if scen:
        b.append('<ul class="scen">')
        for sn in scen:
            b.append(f'<li><b>{_e(sn["name"])}</b> — {_e(sn["plausibility"])} plausibility'
                     f'<div class="en">enabled by {_e(sn["enabled_by"])}</div></li>')
        b.append('</ul>')
    else:
        b.append('<div class="note">No scenarios mapped.</div>')

    b.append('<h2>Remediation — ranked</h2><ol class="rem">')
    for r in assessment.get("remediation", []):
        b.append(f'<li>{_e(r)}</li>')
    b.append('</ol>')

    b.append('<footer class="rpt">Generated by vantage OSINT module · consent-gated '
             'subject, public-source data only — no breached passwords stored.</footer>')
    return _page(f"OSINT Risk Assessment — {subj}", "".join(b))
