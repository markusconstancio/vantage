# vantage

AI-orchestrated security assessment platform combining a multi-agent red
team framework with a personal OSINT/social-engineering risk assessment
module.

> **Read [docs/safety-framework.md](docs/safety-framework.md) before running
> anything.** This project only operates against explicitly authorized
> targets, defined in `scope.yaml`.

**Showcase:** open [`reports/samples/index.html`](reports/samples/index.html)
for a one-page tour, or the tabbed
[`reports/samples/console.html`](reports/samples/console.html) — an interactive
console (Overview / Red Team / OSINT / Remediation, live tooltips, light/dark
toggle) built by `python scripts/build_showcase.py`. All from synthetic data.

## What This Is

Two modules under one architecture pattern (orchestrator → specialist
agents → reporting):

### 1. Red Team Agent Framework
A Claude Code–driven orchestrator coordinates four sub-agents:
- **Recon** — enumeration and service discovery
- **Vulnerability analysis** — maps findings to known CVEs, ranks by
  exploitability
- **Exploit** — sandbox/lab-only, requires explicit human confirmation
  before any action
- **Reporting** — consolidates everything into a findings report

Tested against an isolated lab environment (Metasploitable2, a small
Active Directory lab) — never against systems outside `scope.yaml`.

### 2. OSINT / Social Engineering Risk Assessment
Scans a consenting subject's public digital footprint, checks breach
exposure via Have I Been Pwned, maps realistic attack scenarios based on
what's exposed, and produces a 0–100 risk score with a remediation report.

Run only against: the project author, a synthetic persona built for
demonstration, or a real subject with documented, explicitly scoped
consent. Sample reports in this repo use a synthetic persona only.

## Why This Project Exists

Most student security portfolios show either technical exploitation *or*
awareness of the human side of security — rarely both. vantage pairs an
agentic AI orchestration system (recon → analysis → exploit → report) with
a social-engineering risk methodology, to demonstrate both halves of how
real attacks actually happen.

## Safety & Scope

- `scope.yaml` is the single source of truth for authorized targets. No
  agent acts outside it.
- The exploit agent never acts autonomously — every action requires
  explicit confirmation.
- See [docs/safety-framework.md](docs/safety-framework.md) for the full
  policy.

## Status

See [AGENTS.md](AGENTS.md) for the build order and current phase.

- [x] Repo structure + safety framework
- [x] Recon agent
- [x] Vulnerability analysis agent
- [x] Reporting agent (Module 1 MVP)
- [x] Synthetic persona + OSINT manual assessment (Module 2 MVP)
- [x] Active Directory lab enumeration (`ad-enum`)
- [ ] Exploit agent with guardrails — **guardrail design pending review** (no code yet), see [docs/exploit-agent-guardrails.md](docs/exploit-agent-guardrails.md)
- [x] OSINT module automation (`vantage.osint`)
- [x] Before/after remediation demo
- [x] Full documentation pass

## Setup

```bash
pip install -r requirements.txt          # PyYAML (runtime)
# nmap is a system dependency for the recon agent:
sudo apt install nmap                     # on the host that runs recon (e.g. Kali)
```

### Running the recon agent

The recon agent runs from a host on the *same isolated lab network* as the
target (e.g. your Kali box). First add your authorized lab target to
`scope.yaml`:

```yaml
red_team:
  targets:
    - name: metasploitable2
      address: 192.168.56.101   # your isolated host-only lab IP
      type: host
      authorized: true
```

Then:

```bash
# See exactly what would run, without touching the network:
python -m vantage recon 192.168.56.101 --dry-run

# Run the enumeration (target must be authorized in scope.yaml):
python -m vantage recon 192.168.56.101
python -m vantage recon 192.168.56.101 --json > scan-output/meta.json
```

Anything not listed in `scope.yaml` is refused before nmap is ever invoked.
Every run is appended to `logs/audit.log` (git-ignored).

### Full red-team pipeline (recon → analysis → report)

`analyze` and `report` consume saved recon JSON, so they run anywhere:

```bash
# On the lab host, or from saved output:
python -m vantage recon 192.168.56.101 --json > scan-output/meta.json
python -m vantage analyze scan-output/meta.json            # ranked CVE findings (JSON)
python -m vantage report  scan-output/meta.json -o report.md

# Or pipe directly:
python -m vantage recon 192.168.56.101 --json | python -m vantage report -

# Styled, self-contained HTML report (theme-aware, severity-coded):
python -m vantage report scan-output/meta.json --html -o report.html
```

### Active Directory / SMB enumeration

```bash
python -m vantage ad-enum 192.168.56.20        # scope-gated; enumeration only
python -m vantage ad-enum 192.168.56.20 --dry-run
```

Wraps nmap SMB NSE scripts (OS/domain discovery, shares, users, security mode).
No authentication, brute-forcing, or exploitation.

CVE matching uses an offline curated database (`data/cve_db.yaml`) via a
pluggable source — a live NVD/CPE source can be dropped in later. A worked
sample report (from synthetic data) lives in
[`reports/samples/`](reports/samples/metasploitable2-sample.md).

### OSINT module (Module 2)

The methodology is documented in
[docs/osint-methodology.md](docs/osint-methodology.md) (footprint → breach
check → attack-scenario mapping → 0–100 risk score → remediation), applied
only to consent-gated subjects in `scope.yaml`. A worked **manual** assessment
against a fabricated persona is in
[reports/samples/osint-synthetic-persona.md](reports/samples/osint-synthetic-persona.md).
The persona is entirely synthetic —
[personas/synthetic-persona.md](personas/synthetic-persona.md).

The scoring is also **automated** (`vantage.osint`):

```bash
python -m vantage osint personas/jordan-rivera.yaml --markdown              # 73/100 High
python -m vantage osint personas/jordan-rivera.yaml --remediated --markdown # 47/100 Moderate
python -m vantage osint personas/jordan-rivera.yaml --html -o risk.html     # styled report + risk gauge
```

Both modules render **styled, self-contained HTML** (`--html`) — theme-aware
(light/dark), severity-coded, with a risk gauge and factor bars for OSINT.
Sample HTML lives beside the Markdown in
[`reports/samples/`](reports/samples/).

The automated scorer reproduces the manual 73/100 and quantifies remediation —
see the [before/after demo](reports/samples/remediation-demo.md). No breached
passwords are ever stored; a live HIBP breach source drops in behind the same
interface as the offline one.

### Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
