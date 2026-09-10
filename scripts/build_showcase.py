#!/usr/bin/env python3
"""Build the combined single-page showcase console.

Assembles the real red-team + OSINT report cards (from synthetic data) into one
tabbed, theme-aware HTML console with a live tooltip layer, and writes it to
reports/samples/console.html. Run from the repo root:

    PYTHONPATH=src python scripts/build_showcase.py
"""

from __future__ import annotations

import json
from pathlib import Path

from vantage.agents.vuln import VulnAnalysisAgent
from vantage.osint.assess import OsintAgent
from vantage.osint.persona import Persona
from vantage.report_html import base_css, findings_card, osint_card, tooltip_js

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "samples" / "console.html"

SHIELD = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" '
          'stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 7.6-7 9'
          '-4-1.4-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>')
CHECK = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" '
         'stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>')
SEARCH = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
          'stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/>'
          '<path d="M21 21l-4.3-4.3"/></svg>')
ARROW = ('<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
         'stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/>'
         '<path d="M13 6l6 6-6 6"/></svg>')
MOON = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
        'stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1111.2 3a7 7 0 '
        '009.8 9.8z"/></svg>')
FONTS = ('<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
         'family=IBM+Plex+Mono:wght@400;500;600&display=swap">')

EXTRA = """
:root[data-theme="dark"]{
  color-scheme:dark;
  --page:#080b12; --surface:#0f1522; --panel:#151c2b;
  --ink:#f2f6fc; --ink-2:#aab7ca; --muted:#6b7889;
  --grid:#1e2636; --border:rgba(255,255,255,.08); --track:#1c2433;
  --hero-1:#0a0f1c; --hero-2:#141f36; --accent-2:#818cf8; --series-1:#3987e5;
  --shadow:0 1px 2px rgba(0,0,0,.4),0 16px 40px rgba(0,0,0,.5);
}
.mono,.cve,code,pre,.step,.pill .mono,.wordmark,.kind,td.mono,
.gauge .num,.tile .n,th{font-family:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;}
.wordmark{letter-spacing:.28em;font-weight:600;}
body{background:var(--page);}
.wrap{max-width:960px;margin:0 auto;padding:26px 18px 72px;}
.shell{background:var(--surface);border:1px solid var(--border);border-radius:22px;
  box-shadow:var(--shadow);overflow:hidden;}
.topbar{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:6px;
  padding:11px 16px;background:color-mix(in srgb,var(--hero-1) 94%,transparent);
  border-bottom:1px solid rgba(255,255,255,.08);backdrop-filter:blur(10px);}
.topbar .brand{display:flex;align-items:center;gap:9px;color:var(--hero-ink);font-weight:600;
  letter-spacing:.24em;text-transform:uppercase;font-size:12px;margin-right:10px;
  font-family:'IBM Plex Mono',monospace;}
.topbar .brand svg{width:20px;height:20px;color:var(--accent);
  filter:drop-shadow(0 0 8px rgba(56,189,248,.5));}
.tabs{display:flex;gap:4px;flex:1;flex-wrap:wrap;}
.tab{appearance:none;border:0;background:transparent;color:var(--hero-ink-2);font-size:13px;
  font-weight:600;padding:7px 13px;border-radius:9px;cursor:pointer;font-family:inherit;}
.tab:hover{color:var(--hero-ink);background:rgba(255,255,255,.06);}
.tab[aria-selected="true"]{color:#fff;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  box-shadow:0 3px 12px color-mix(in srgb,var(--accent-2) 34%,transparent);}
.tab:focus-visible{outline:2px solid var(--accent);outline-offset:2px;}
.tglbtn{appearance:none;border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.06);
  color:var(--hero-ink);border-radius:9px;width:34px;height:32px;cursor:pointer;display:grid;
  place-items:center;}
.tglbtn svg{width:16px;height:16px;} .tglbtn:focus-visible{outline:2px solid var(--accent);outline-offset:2px;}
.panel[hidden]{display:none;}
.mods{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
.mod{position:relative;border:1px solid var(--border);border-radius:16px;padding:22px;
  background:var(--panel);overflow:hidden;display:flex;flex-direction:column;}
.mod::before{content:"";position:absolute;left:0;right:0;top:0;height:3px;
  background:linear-gradient(90deg,var(--accent),var(--accent-2));}
.mod .ic{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;margin-bottom:14px;}
.mod .ic svg{width:21px;height:21px;} .mod h3{margin:0 0 6px;font-size:17px;}
.mod p{margin:0 0 16px;font-size:13.5px;color:var(--ink-2);flex:1;}
.mod .steps{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px;}
.mod .step{font-size:11.5px;color:var(--ink-2);background:var(--surface);
  border:1px solid var(--border);border-radius:6px;padding:3px 8px;}
.btn{appearance:none;border:0;align-self:flex-start;font-family:inherit;font-size:13px;
  font-weight:600;padding:9px 15px;border-radius:9px;cursor:pointer;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;
  box-shadow:0 4px 12px color-mix(in srgb,var(--accent-2) 30%,transparent);}
.btn:hover{filter:brightness(1.06);} .btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px;}
.hero h1 .g{background:linear-gradient(90deg,var(--accent),var(--accent-2));
  -webkit-background-clip:text;background-clip:text;color:transparent;}
.safe{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;}
.scard{border:1px solid var(--border);border-radius:13px;padding:15px 17px;background:var(--panel);}
.scard .h{display:flex;align-items:center;gap:9px;font-weight:650;font-size:14px;margin-bottom:5px;}
.scard .h svg{width:17px;height:17px;color:var(--good);} .scard p{margin:0;font-size:12.5px;color:var(--ink-2);}
pre{margin:0;background:var(--hero-1);color:#e6edf7;border-radius:13px;padding:18px 20px;
  overflow-x:auto;font-size:12.5px;line-height:1.7;border:1px solid var(--border);}
pre .c{color:#6b7d99;} pre .k{color:#7dd3fc;}
.delta{display:flex;align-items:center;gap:22px;flex-wrap:wrap;padding:20px 22px;
  border:1px solid var(--border);border-radius:16px;background:var(--panel);}
.dnum{display:flex;align-items:center;gap:14px;font-weight:760;letter-spacing:-.02em;
  font-family:'IBM Plex Mono',monospace;}
.dnum .was{font-size:34px;color:var(--muted);text-decoration:line-through;text-decoration-thickness:2px;}
.dnum svg{color:var(--muted);} .dnum .now{font-size:44px;color:var(--good);}
.dtxt{flex:1;min-width:240px;font-size:13.5px;color:var(--ink-2);} .dtxt b{color:var(--ink);}
@media (max-width:620px){.mods{grid-template-columns:1fr;}}
"""


def build() -> str:
    recon = json.loads((ROOT / "reports/samples/recon-sample.json").read_text())
    analysis = VulnAnalysisAgent.with_static_db().analyze(recon)
    before = OsintAgent().assess(Persona.load(ROOT / "personas/jordan-rivera.yaml"))
    after = OsintAgent().assess(
        Persona.load(ROOT / "personas/jordan-rivera.yaml").with_posture(
            mfa_enabled=True, passwords_unique=True, phone_public=False))

    rt = findings_card(recon, analysis)
    os_before = osint_card(before)
    os_after = osint_card(after)
    d = before["score"] - after["score"]

    overview = f"""
<div class="hero"><div class="wordmark"><span class="mk">{SHIELD}</span>vantage</div>
  <h1>AI-orchestrated <span class="g">security assessment</span> platform</h1>
  <p>A multi-agent red-team framework paired with an OSINT personal-risk module —
     every agent gated to authorized targets, driven from one CLI, reported in clean HTML.</p>
  <div class="pills"><span class="pill">Python · zero-dependency core</span>
    <span class="pill">scope-gated by design</span><span class="pill">theme-aware reports</span></div></div>
<div class="body"><h2>Two modules, one pattern</h2><div class="mods">
  <div class="mod"><div class="ic">{SHIELD}</div><h3>Red Team Framework</h3>
    <p>Enumerate an authorized lab target, map services to known CVEs ranked by
       exploitability, and produce a findings report. Enumeration only — the exploit
       agent stays behind a reviewed human-confirmation gate.</p>
    <div class="steps"><span class="step">recon</span><span class="step">→ vuln analysis</span>
      <span class="step">→ report</span><span class="step">+ ad-enum</span></div>
    <button class="btn" data-go="redteam">Open the findings report →</button></div>
  <div class="mod"><div class="ic">{SEARCH}</div><h3>OSINT Risk Assessment</h3>
    <p>Score a consenting subject's social-engineering exposure from their public
       footprint and breaches: a 0–100 score, mapped attack scenarios, and ranked
       remediation — with a before/after view of the fixes.</p>
    <div class="steps"><span class="step">footprint</span><span class="step">→ breach</span>
      <span class="step">→ score</span><span class="step">→ remediate</span></div>
    <button class="btn" data-go="osint">Open the risk assessment →</button></div></div>
  <h2>Safety is the architecture</h2><div class="safe">
    <div class="scard"><div class="h">{CHECK}Single source of truth</div>
      <p>Every agent resolves its target through <code>scope.yaml</code>. Anything not
         authorized is refused before a packet is sent.</p></div>
    <div class="scard"><div class="h">{CHECK}Human-gated exploitation</div>
      <p>The exploit agent isn't written yet — its guardrails (per-action confirmation,
         lab-only) are documented for review first.</p></div>
    <div class="scard"><div class="h">{CHECK}Synthetic-only samples</div>
      <p>Every report here is generated from a fabricated persona and a synthetic scan —
         no real person's data, no real target.</p></div></div>
  <h2>One CLI</h2>
  <pre><span class="c"># enumerate an authorized lab target, then report</span>
python -m vantage recon <span class="k">192.168.56.101</span> --json | python -m vantage report - --html

<span class="c"># score a subject's OSINT exposure</span>
python -m vantage osint <span class="k">personas/jordan-rivera.yaml</span> --html -o risk.html</pre></div>
"""

    delta = f"""
<div class="body" style="padding-bottom:0"><h2>Before / after remediation</h2>
  <div class="delta"><div class="dnum"><span class="was">{before['score']}</span>{ARROW}
    <span class="now">{after['score']}</span></div>
    <div class="dtxt"><b>−{d} points</b> — High → {after['band']}. Three low-effort fixes
      (MFA, unique passwords, delisting the phone number) account for the entire drop.
      The report below is the automated re-score of the remediated posture.</div></div></div>
"""

    return f"""{FONTS}
<title>Vantage Assessment Console</title>
<style>{base_css()}{EXTRA}</style>
<div class="wrap"><div class="shell">
  <nav class="topbar"><span class="brand"><span>{SHIELD}</span>vantage</span>
    <div class="tabs" role="tablist" aria-label="Reports">
      <button class="tab" role="tab" aria-selected="true" data-panel="overview">Overview</button>
      <button class="tab" role="tab" aria-selected="false" data-panel="redteam">Red Team</button>
      <button class="tab" role="tab" aria-selected="false" data-panel="osint">OSINT</button>
      <button class="tab" role="tab" aria-selected="false" data-panel="remediation">Remediation</button>
    </div>
    <button class="tglbtn" id="themeToggle" aria-label="Toggle light/dark" title="Toggle theme">{MOON}</button>
  </nav>
  <section class="panel" data-name="overview">{overview}</section>
  <section class="panel" data-name="redteam" hidden>{rt}</section>
  <section class="panel" data-name="osint" hidden>{os_before}</section>
  <section class="panel" data-name="remediation" hidden>{delta}{os_after}</section>
</div></div>
<script>
(function(){{
  var tabs=[].slice.call(document.querySelectorAll('.tab'));
  var panels=[].slice.call(document.querySelectorAll('.panel'));
  function show(name){{
    tabs.forEach(function(t){{t.setAttribute('aria-selected', t.dataset.panel===name);}});
    panels.forEach(function(p){{p.hidden = p.dataset.name!==name;}});
    window.scrollTo({{top:0,behavior:'smooth'}});
  }}
  tabs.forEach(function(t,i){{
    t.addEventListener('click',function(){{show(t.dataset.panel);}});
    t.addEventListener('keydown',function(e){{
      if(e.key==='ArrowRight'||e.key==='ArrowLeft'){{
        var n=(i+(e.key==='ArrowRight'?1:tabs.length-1))%tabs.length;
        tabs[n].focus();show(tabs[n].dataset.panel);e.preventDefault();}}
    }});
  }});
  document.querySelectorAll('[data-go]').forEach(function(b){{
    b.addEventListener('click',function(){{show(b.dataset.go);}});
  }});
  var root=document.documentElement, tgl=document.getElementById('themeToggle');
  tgl.addEventListener('click',function(){{
    var dark = root.getAttribute('data-theme')==='dark' ||
      (!root.getAttribute('data-theme') && matchMedia('(prefers-color-scheme: dark)').matches);
    root.setAttribute('data-theme', dark?'light':'dark');
  }});
}})();
</script>
{tooltip_js()}
"""


if __name__ == "__main__":
    OUT.write_text(build())
    print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size} bytes)")
