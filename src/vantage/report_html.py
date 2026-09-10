"""HTML rendering for vantage reports.

Self-contained, theme-aware (light/dark) HTML for the red-team findings report
and the OSINT risk assessment. Product chrome (the dark hero band, wordmark,
gradients) is branding; the *data marks* — severity/risk colours and the
magnitude bars/gauge — stay on the validated dataviz status + blue palette, and
severity is always carried by a text label, never colour alone. All external
strings are HTML-escaped.
"""

from __future__ import annotations

import html
import math

# --- design tokens ---------------------------------------------------------

_CSS = """
:root{
  color-scheme:light;
  --page:#eaeef4; --surface:#ffffff; --panel:#f5f7fb;
  --ink:#0b1220; --ink-2:#475569; --muted:#8b97a8;
  --grid:#e7ebf2; --border:rgba(15,23,42,.09); --track:#e9edf4;
  --hero-1:#0b1120; --hero-2:#16233d; --hero-ink:#eef3fb; --hero-ink-2:#9db2d0;
  --accent:#38bdf8; --accent-2:#6366f1; --series-1:#2a78d6;
  --good:#0ca30c; --warning:#f59e0b; --serious:#ec835a; --critical:#d03b3b;
  --shadow:0 1px 2px rgba(15,23,42,.05),0 12px 32px rgba(15,23,42,.10);
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    color-scheme:dark;
    --page:#080b12; --surface:#0f1522; --panel:#151c2b;
    --ink:#f2f6fc; --ink-2:#aab7ca; --muted:#6b7889;
    --grid:#1e2636; --border:rgba(255,255,255,.08); --track:#1c2433;
    --hero-1:#0a0f1c; --hero-2:#141f36; --hero-ink:#eef3fb; --hero-ink-2:#9db2d0;
    --accent:#38bdf8; --accent-2:#818cf8; --series-1:#3987e5;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 16px 40px rgba(0,0,0,.5);
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.55;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;}
.wrap{max-width:900px;margin:0 auto;padding:36px 20px 80px;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:20px;
  box-shadow:var(--shadow);overflow:hidden;}
.body{padding:34px 40px 40px;}
/* hero */
.hero{position:relative;padding:30px 40px 34px;
  background:linear-gradient(135deg,var(--hero-1),var(--hero-2));color:var(--hero-ink);
  overflow:hidden;}
.hero::after{content:"";position:absolute;inset:0;pointer-events:none;
  background-image:radial-gradient(rgba(255,255,255,.06) 1px,transparent 1px);
  background-size:22px 22px;mask-image:linear-gradient(120deg,#000,transparent 70%);
  -webkit-mask-image:linear-gradient(120deg,#000,transparent 70%);}
.hero>*{position:relative;z-index:1;}
.brandrow{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px;}
.wordmark{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:.32em;
  font-size:13px;text-transform:uppercase;}
.wordmark .mk{width:28px;height:28px;flex:none;
  color:var(--accent);filter:drop-shadow(0 0 10px rgba(56,189,248,.45));}
.kind{font-size:11px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;
  padding:5px 12px;border-radius:999px;color:var(--hero-ink);
  background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.16);
  backdrop-filter:blur(4px);}
.hero h1{margin:0;font-size:30px;line-height:1.12;letter-spacing:-.02em;font-weight:750;}
.hero .sub{margin:6px 0 0;color:var(--hero-ink-2);font-size:14.5px;}
.pills{display:flex;flex-wrap:wrap;gap:8px;margin-top:20px;}
.pill{display:inline-flex;align-items:center;gap:7px;font-size:12px;
  color:var(--hero-ink);background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.13);border-radius:8px;padding:5px 11px;}
.pill b{color:var(--hero-ink-2);font-weight:600;}
.pill .mono,.pill code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:12px;letter-spacing:.01em;}
/* sections */
h2{font-size:12px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
  margin:34px 0 15px;font-weight:700;display:flex;align-items:center;gap:10px;}
h2::after{content:"";flex:1;height:1px;background:var(--grid);}
h2:first-child{margin-top:4px;}
/* tiles */
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;}
.tile{position:relative;background:var(--panel);border:1px solid var(--border);
  border-radius:14px;padding:16px 18px;overflow:hidden;}
.tile::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;
  background:var(--c,var(--accent));opacity:.9;}
.tile .n{font-size:28px;font-weight:720;letter-spacing:-.02em;line-height:1;}
.tile .l{font-size:12px;color:var(--muted);margin-top:6px;}
/* severity distribution bar */
.sevbar{display:flex;height:12px;border-radius:999px;overflow:hidden;gap:2px;
  background:var(--track);margin:2px 0 12px;}
.sevbar span{display:block;}
.sevlegend{display:flex;flex-wrap:wrap;gap:8px 16px;}
/* chips */
.chip{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:600;
  padding:4px 11px 4px 9px;border-radius:999px;border:1px solid var(--border);
  white-space:nowrap;background:var(--panel);}
.chip .dot{width:9px;height:9px;border-radius:50%;flex:none;background:var(--c);
  box-shadow:0 0 0 3px color-mix(in srgb,var(--c) 22%,transparent);}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:800;
  letter-spacing:.05em;text-transform:uppercase;padding:4px 10px;border-radius:7px;
  color:#fff;background:var(--c);}
/* table */
table{width:100%;border-collapse:collapse;font-size:13.5px;}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);font-weight:700;padding:0 14px 9px;border-bottom:1px solid var(--grid);}
td{padding:11px 14px;border-bottom:1px solid var(--grid);vertical-align:middle;}
tr:last-child td{border-bottom:none;}
tbody tr:hover{background:var(--panel);}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;
  font-variant-numeric:tabular-nums;}
/* findings */
.finding{position:relative;border:1px solid var(--border);border-radius:14px;
  padding:16px 18px 16px 20px;margin-bottom:12px;background:var(--panel);overflow:hidden;}
.finding::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--c);}
.finding .top{display:flex;align-items:center;gap:11px;flex-wrap:wrap;margin-bottom:9px;}
.finding .rank{flex:none;width:24px;height:24px;border-radius:8px;background:var(--surface);
  border:1px solid var(--border);color:var(--ink-2);font-size:12px;font-weight:800;
  display:grid;place-items:center;}
.finding .cve{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;color:var(--ink-2);
  background:var(--surface);border:1px solid var(--border);padding:2px 8px;border-radius:6px;}
.finding .title{font-size:15px;font-weight:650;flex:1;min-width:200px;}
.finding .meta2{font-size:12.5px;color:var(--muted);margin-left:35px;}
.finding .aff{font-size:13px;color:var(--ink-2);margin:6px 0 0 35px;}
.finding .aff b{color:var(--ink);font-weight:600;}
.finding .ref{font-size:12.5px;margin:6px 0 0 35px;}
.finding a{color:var(--series-1);text-decoration:none;}
.finding a:hover{text-decoration:underline;}
/* OSINT gauge */
.risk{display:flex;align-items:center;gap:30px;flex-wrap:wrap;padding:26px 28px;
  border:1px solid var(--border);border-radius:16px;background:var(--panel);}
.gauge{flex:none;width:180px;height:180px;position:relative;}
.gauge svg{transform:rotate(0deg);display:block;}
.gauge .center{position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center;text-align:center;}
.gauge .num{font-size:46px;font-weight:760;letter-spacing:-.03em;line-height:1;color:var(--c);}
.gauge .den{font-size:13px;color:var(--muted);margin-top:2px;}
.risk .side{flex:1;min-width:220px;}
.risk .side .band{margin-bottom:12px;}
.risk .scale{display:flex;flex-direction:column;gap:7px;margin-top:4px;}
.risk .scale .r{display:flex;align-items:center;gap:10px;font-size:12.5px;color:var(--ink-2);}
.risk .scale .sw{width:26px;height:8px;border-radius:999px;flex:none;background:var(--c);}
.risk .scale .r.on{font-weight:700;color:var(--ink);}
.risk .scale .r.on .sw{box-shadow:0 0 0 3px color-mix(in srgb,var(--c) 25%,transparent);}
/* factor bars */
.bars{display:flex;flex-direction:column;gap:10px;}
.bar-row{display:grid;grid-template-columns:150px 1fr;gap:16px;align-items:center;}
.bar-row .name{font-size:13px;color:var(--ink-2);text-transform:capitalize;}
.bar-track{position:relative;height:24px;background:var(--track);border-radius:7px;overflow:hidden;}
.bar-fill{position:absolute;left:0;top:0;bottom:0;
  background:linear-gradient(90deg,var(--series-1),color-mix(in srgb,var(--series-1) 78%,var(--accent)));
  border-radius:7px 5px 5px 7px;min-width:4px;}
.bar-val{position:absolute;inset:0;display:flex;align-items:center;padding-left:11px;
  font-size:12px;font-weight:700;color:#fff;font-variant-numeric:tabular-nums;
  text-shadow:0 1px 1px rgba(0,0,0,.25);}
/* scenarios + remediation */
.scen{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:10px;}
.scen li{position:relative;border:1px solid var(--border);border-radius:12px;
  padding:13px 15px 13px 16px;background:var(--panel);font-size:13.5px;}
.scen li::before{content:"";position:absolute;left:0;top:12px;bottom:12px;width:3px;
  border-radius:3px;background:var(--accent-2);}
.scen .nm{font-weight:650;}
.scen .plaus{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;
  color:var(--muted);margin-left:8px;}
.scen .en{color:var(--muted);font-size:12.5px;margin-top:3px;}
ol.rem{margin:0;padding:0;list-style:none;counter-reset:r;
  display:flex;flex-direction:column;gap:9px;}
ol.rem li{counter-increment:r;position:relative;padding:11px 15px 11px 46px;font-size:13.5px;
  background:var(--panel);border:1px solid var(--border);border-radius:12px;color:var(--ink-2);}
ol.rem li::before{content:counter(r);position:absolute;left:12px;top:50%;
  transform:translateY(-50%);width:24px;height:24px;border-radius:7px;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;
  font-size:12px;font-weight:800;display:grid;place-items:center;}
.note{background:var(--panel);border:1px dashed var(--border);border-radius:12px;
  padding:12px 15px;font-size:13px;color:var(--ink-2);}
[data-tip]{cursor:help;}
.bar-track[data-tip],.gauge[data-tip]{cursor:default;}
tbody tr[data-tip]{cursor:default;}
.vtip{position:fixed;z-index:60;pointer-events:none;max-width:290px;opacity:0;
  transform:translateY(3px);transition:opacity .12s,transform .12s;
  background:var(--hero-1);color:#eef3fb;font-size:12px;line-height:1.45;
  padding:8px 11px;border-radius:9px;border:1px solid rgba(255,255,255,.14);
  box-shadow:0 8px 26px rgba(0,0,0,.35);}
.vtip.on{opacity:1;transform:translateY(0);}
.vtip b{color:#7dd3fc;font-weight:600;}
footer.rpt{margin-top:34px;padding:16px 40px;border-top:1px solid var(--grid);
  color:var(--muted);font-size:12px;display:flex;align-items:center;gap:8px;
  background:var(--panel);}
footer.rpt .mk{width:15px;height:15px;color:var(--muted);flex:none;}
@media (max-width:560px){
  .hero,.body{padding-left:22px;padding-right:22px;}
  .finding .meta2,.finding .aff,.finding .ref{margin-left:0;}
}
"""

_SHIELD = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6z"/>'
    '<path d="M9 12l2 2 4-4"/></svg>'
)

# Brand favicon — a shield on a dark rounded tile, accent stroke.
_FAVICON = (
    '<link rel="icon" href="data:image/svg+xml,'
    "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
    "%3Crect width='32' height='32' rx='8' fill='%230b1120'/%3E"
    "%3Cpath d='M16 6l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V9z' fill='none' "
    "stroke='%2338bdf8' stroke-width='2' stroke-linejoin='round'/%3E"
    "%3Cpath d='M12.5 15.5l2.3 2.3 4.7-4.7' fill='none' stroke='%2338bdf8' "
    "stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E"
    "%3C/svg%3E\">"
)

_TOOLTIP_JS = """<script>
(function(){
  var tip=document.createElement('div');tip.className='vtip';document.body.appendChild(tip);
  function html(el){return el.getAttribute('data-tip')||'';}
  function at(x,y){var w=tip.offsetWidth,h=tip.offsetHeight,pad=12;
    var L=x+14,T=y+16;if(L+w>innerWidth-pad)L=x-w-14;if(T+h>innerHeight-pad)T=y-h-16;
    tip.style.left=Math.max(pad,L)+'px';tip.style.top=Math.max(pad,T)+'px';}
  function show(e){var t=html(e.currentTarget);if(!t)return;tip.innerHTML=t;
    tip.classList.add('on');at(e.clientX,e.clientY);}
  function move(e){if(tip.classList.contains('on'))at(e.clientX,e.clientY);}
  function hide(){tip.classList.remove('on');}
  document.querySelectorAll('[data-tip]').forEach(function(el){
    el.addEventListener('mouseenter',show);el.addEventListener('mousemove',move);
    el.addEventListener('mouseleave',hide);
    el.setAttribute('tabindex','0');
    el.addEventListener('focus',function(){var t=html(el);if(!t)return;tip.innerHTML=t;
      tip.classList.add('on');var b=el.getBoundingClientRect();at(b.left,b.bottom);});
    el.addEventListener('blur',hide);
  });
})();
</script>"""

_SEV_COLOR = {  # vuln severity — Low is still a weakness → neutral, not green
    "Critical": "var(--critical)", "High": "var(--serious)",
    "Medium": "var(--warning)", "Low": "var(--muted)", "None": "var(--muted)",
}
_BAND_COLOR = {  # risk band — Low genuinely means low risk → green
    "Critical": "var(--critical)", "High": "var(--serious)",
    "Moderate": "var(--warning)", "Low": "var(--good)",
}
_BANDS = [("Low", "0–24"), ("Moderate", "25–49"), ("High", "50–74"),
          ("Critical", "75–100")]


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"{_FAVICON}<title>{_e(title)}</title><style>{_CSS}</style></head>"
        f"<body><div class=\"wrap\"><div class=\"card\">{body}</div></div>"
        f"{_TOOLTIP_JS}</body></html>"
    )


def _hero(kind: str, title: str, subtitle: str, pills: list[str]) -> str:
    pill_html = "".join(f'<span class="pill">{p}</span>' for p in pills)
    return (
        '<div class="hero"><div class="brandrow">'
        f'<span class="wordmark"><span class="mk">{_SHIELD}</span>vantage</span>'
        f'<span class="kind">{_e(kind)}</span></div>'
        f'<h1>{_e(title)}</h1><p class="sub">{_e(subtitle)}</p>'
        f'<div class="pills">{pill_html}</div></div>'
    )


def _footer(text: str) -> str:
    return f'<footer class="rpt"><span class="mk">{_SHIELD}</span>{_e(text)}</footer>'


def _chip(label: str, color: str) -> str:
    return (f'<span class="chip" style="--c:{color}">'
            f'<span class="dot"></span>{_e(label)}</span>')


def _badge(label: str, color: str) -> str:
    return f'<span class="badge" style="--c:{color}">{_e(label)}</span>'


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


# --- red-team findings -----------------------------------------------------

def render_findings_html(recon_result: dict, analysis: dict) -> str:
    target = analysis.get("target") or recon_result.get("target") or "unknown"
    s = analysis.get("summary", {})
    max_cvss = s.get("max_cvss", 0.0)
    top_sev = _severity(max_cvss)
    findings = analysis.get("findings", [])

    pills = [f'<b>target</b> <span class="mono">{_e(target)}</span>',
             f'<b>scope</b> {_e(analysis.get("matched_scope") or "—")}']
    if analysis.get("scanned_at"):
        pills.append(f'<b>scanned</b> <span class="mono">{_e(analysis["scanned_at"])}</span>')

    b = [_hero("Red Team", "Red Team Findings",
               "Service enumeration and CVE analysis — enumeration only.", pills),
         '<div class="body">']

    # summary tiles
    b.append('<h2>Summary</h2><div class="tiles">')
    b.append(f'<div class="tile" style="--c:var(--accent)"><div class="n">'
             f'{s.get("open_services",0)}</div><div class="l">Open services</div></div>')
    b.append(f'<div class="tile" style="--c:var(--accent-2)"><div class="n">'
             f'{s.get("findings",0)}</div><div class="l">Findings</div></div>')
    b.append(f'<div class="tile" style="--c:var(--critical)"><div class="n">'
             f'{s.get("with_public_exploit",0)}</div><div class="l">Public exploit</div></div>')
    b.append(f'<div class="tile" style="--c:{_SEV_COLOR[top_sev]}">'
             f'<div class="n" style="font-size:19px;padding-top:5px">{_badge(top_sev,_SEV_COLOR[top_sev])}</div>'
             f'<div class="l">Top severity · CVSS {max_cvss}</div></div>')
    b.append('</div>')

    # severity distribution
    counts: dict[str, int] = {}
    for f in findings:
        counts[_severity(f["cvss"])] = counts.get(_severity(f["cvss"]), 0) + 1
    order = ["Critical", "High", "Medium", "Low"]
    total = sum(counts.get(k, 0) for k in order) or 1
    if any(counts.values()):
        b.append('<h2>Severity distribution</h2>')
        segs = "".join(
            f'<span style="flex:{counts[k]};background:{_SEV_COLOR[k]}"></span>'
            for k in order if counts.get(k))
        b.append(f'<div class="sevbar">{segs}</div><div class="sevlegend">')
        for k in order:
            if counts.get(k):
                b.append(f'{_chip(f"{k} · {counts[k]}", _SEV_COLOR[k])}')
        b.append('</div>')

    # services table
    b.append('<h2>Open services</h2><table><thead><tr>'
             '<th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th>'
             '</tr></thead><tbody>')
    for host in recon_result.get("hosts", []):
        for p in host.get("ports", []):
            if p.get("state") != "open":
                continue
            prod = " ".join(x for x in (p.get("product"), p.get("version")) if x)
            tip = (f'<b>{_e(p.get("service") or "service")}</b> on port '
                   f'{_e(p.get("port"))}/{_e(p.get("protocol"))} — '
                   f'{_e(prod or "unidentified")}')
            b.append(
                f'<tr data-tip="{tip}"><td class="mono">{_e(host.get("address"))}</td>'
                f'<td class="mono">{_e(p.get("port"))}/{_e(p.get("protocol"))}</td>'
                f'<td>{_e(p.get("service"))}</td><td>{_e(p.get("product"))}</td>'
                f'<td class="mono">{_e(p.get("version"))}</td></tr>')
    b.append('</tbody></table>')

    # findings
    b.append('<h2>Findings — ranked by exploitability</h2>')
    if not findings:
        b.append('<div class="note">No known CVEs matched the enumerated services.</div>')
    for i, f in enumerate(findings, 1):
        sev = _severity(f["cvss"])
        color = _SEV_COLOR[sev]
        exploit = "public exploit available" if f["exploit_available"] else "no public exploit"
        refs = "".join(
            f'<div class="ref">↗ <a href="{_e(r)}">{_e(r)}</a></div>'
            for r in f.get("references", []))
        b.append(
            f'<div class="finding" style="--c:{color}"><div class="top">'
            f'<span class="rank">{i}</span>{_badge(sev, color)}'
            f'<span class="cve">{_e(f["cve"])}</span>'
            f'<span class="title">{_e(f["title"])}</span></div>'
            f'<div class="meta2">CVSS {f["cvss"]} · {exploit}</div>'
            f'<div class="aff"><b>Affected:</b> {_e(f["product"])} {_e(f["version"])} '
            f'on {_e(f["host"])}:{_e(f["port"])}/{_e(f["protocol"])} ({_e(f["service"])})</div>'
            f'{refs}</div>')

    b.append('</div>')
    b.append(_footer("Generated by vantage · enumeration and analysis only — "
                     "no exploitation was performed."))
    return _page(f"Red Team Findings — {target}", "".join(b))


# --- OSINT risk ------------------------------------------------------------

def _gauge_svg(score: int, color: str) -> str:
    """A 270° arc gauge. Track + value arc, rounded caps."""
    r = 74
    cx = cy = 90
    circ = 2 * math.pi * r
    sweep = 0.75 * circ           # 270° visible arc
    frac = max(0.0, min(1.0, score / 100))
    value = frac * sweep
    # rotate so the 270° arc is centred at the top, gap at the bottom
    rot = f"rotate(135 {cx} {cy})"
    return (
        f'<svg width="180" height="180" viewBox="0 0 180 180" aria-hidden="true">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="var(--track)" '
        f'stroke-width="14" stroke-linecap="round" transform="{rot}" '
        f'stroke-dasharray="{sweep:.2f} {circ:.2f}"/>'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
        f'stroke-width="14" stroke-linecap="round" transform="{rot}" '
        f'stroke-dasharray="{value:.2f} {circ:.2f}"/>'
        f'</svg>'
    )


def render_osint_html(assessment: dict) -> str:
    subj = assessment["subject"]
    score = assessment["score"]
    band = assessment["band"]
    color = _BAND_COLOR.get(band, "var(--muted)")

    pills = [f'<b>subject</b> {_e(subj)}',
             f'<b>consent</b> {_e(assessment["kind"])}',
             f'<b>factors</b> <span class="mono">6</span>']

    b = [_hero("OSINT", "Risk Assessment",
               "Social-engineering exposure from a public footprint.", pills),
         '<div class="body">']

    # risk hero: gauge + band scale
    scale_rows = []
    for name, rng in _BANDS:
        on = " on" if name == band else ""
        scale_rows.append(
            f'<div class="r{on}" style="--c:{_BAND_COLOR[name]}">'
            f'<span class="sw"></span><span>{name}</span>'
            f'<span style="color:var(--muted);margin-left:auto" class="mono">{rng}</span></div>')
    gtip = (f'<b>{score}/100 — {_e(band)} risk</b><br>weighted sum '
            f'{assessment.get("raw", 0)} of {assessment.get("max_raw", 60)} '
            'possible exposure points')
    b.append(
        f'<div class="risk" style="--c:{color}">'
        f'<div class="gauge" data-tip="{gtip}">{_gauge_svg(score, color)}'
        f'<div class="center"><div class="num">{score}</div>'
        f'<div class="den">/ 100</div></div></div>'
        f'<div class="side"><div class="band">{_badge(band + " risk", color)}</div>'
        f'<div class="scale">{"".join(scale_rows)}</div></div></div>')

    # factor bars
    b.append('<h2>Factor breakdown</h2><div class="bars">')
    max_pts = 15
    for f in assessment["factors"]:
        pts = f["weighted"]
        w = max(4, round(pts / max_pts * 100))
        tip = (f'<b>{_e(f["factor"].replace("_"," "))}</b> · rating '
               f'{f["rating"]}/3 × weight {f["weight"]} = {pts} pts<br>'
               f'{_e(f["rationale"])}')
        b.append(
            f'<div class="bar-row"><div class="name">{_e(f["factor"].replace("_"," "))}</div>'
            f'<div class="bar-track" data-tip="{tip}">'
            f'<div class="bar-fill" style="width:{w}%"></div>'
            f'<div class="bar-val">{pts} pts · rating {f["rating"]}/3</div></div></div>')
    b.append('</div>')

    # scenarios
    scen = assessment.get("scenarios", [])
    b.append('<h2>Attack scenarios</h2>')
    if scen:
        b.append('<ul class="scen">')
        for sn in scen:
            b.append(f'<li><span class="nm">{_e(sn["name"])}</span>'
                     f'<span class="plaus">{_e(sn["plausibility"])}</span>'
                     f'<div class="en">enabled by {_e(sn["enabled_by"])}</div></li>')
        b.append('</ul>')
    else:
        b.append('<div class="note">No scenarios mapped.</div>')

    # remediation
    b.append('<h2>Remediation — ranked by impact</h2><ol class="rem">')
    for r in assessment.get("remediation", []):
        b.append(f'<li>{_e(r)}</li>')
    b.append('</ol>')

    b.append('</div>')
    b.append(_footer("Generated by vantage OSINT module · consent-gated subject, "
                     "public-source data only — no breached passwords stored."))
    return _page(f"OSINT Risk Assessment — {subj}", "".join(b))
