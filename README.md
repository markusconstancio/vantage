# vantage

AI-orchestrated security assessment platform combining a multi-agent red
team framework with a personal OSINT/social-engineering risk assessment
module.

> **Read [docs/safety-framework.md](docs/safety-framework.md) before running
> anything.** This project only operates against explicitly authorized
> targets, defined in `scope.yaml`.

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
- [ ] Vulnerability analysis agent
- [ ] Reporting agent (Module 1 MVP)
- [ ] Synthetic persona + OSINT manual assessment (Module 2 MVP)
- [ ] Active Directory lab
- [ ] Exploit agent with guardrails
- [ ] OSINT module automation
- [ ] Before/after remediation demo
- [ ] Full documentation pass

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

### Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
