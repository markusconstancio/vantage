# AGENTS.md — vantage

This file defines how Claude Code (and any other agent working in this repo)
should operate. Read this before making changes.

## Project Summary

vantage is a two-module security assessment platform:

1. **Red Team Agent Framework** — an orchestrator coordinating recon,
   vulnerability analysis, exploit (sandbox/lab-only), and reporting
   sub-agents against authorized lab targets.
2. **OSINT / Social Engineering Risk Assessment** — footprint scanning,
   breach exposure checks, attack scenario mapping, and a risk score +
   remediation report, run only against the user, a synthetic persona, or a
   subject with documented consent.

## Non-Negotiable Rules (check these before every action)

1. **scope.yaml is the single source of truth.** No agent may act against
   any target (IP, hostname, CTF box, person) not explicitly listed there.
   If scope.yaml doesn't cover something, stop and ask rather than assume.
2. **The exploit agent never acts autonomously.** Every exploitation action
   requires explicit human confirmation in the moment — not a one-time
   approval at the start of a session.
3. **The OSINT module only targets:** the user themself, a synthetic persona
   built for demo purposes, or a real person with documented, scoped
   consent. Never build or run this against an arbitrary real person.
4. **Never commit secrets.** API keys, credentials, and anything in `.env`
   stay out of git. Use `.env.example` for documenting what's needed.
5. **Real findings stay private.** Only synthetic-persona sample reports go
   in the public repo. Real assessment output (even consented) is not
   committed.
6. **No autonomous network scanning outside scope.yaml targets**, even for
   "just testing" — the isolated lab network should make this physically
   impossible, but the code should also refuse to attempt it.

## Agent Roles (development workflow)

- **Architect/Lead** — plans structure, makes design decisions, breaks work
  into phases. Default role for most sessions.
- **Builder** — implements a specific, scoped piece of functionality handed
  off by the Architect.
- **Security Reviewer** — a separate pass reviewing code before it's
  considered done, specifically checking rules 1–6 above are enforced in
  code, not just in docs.
- **Docs agent** — keeps README.md, docs/architecture.md, and inline
  comments current as the project evolves. Documentation is not optional
  polish — it's part of "done."

## In-App Agent Roles (what the software itself does)

- **Recon agent** — enumeration and service discovery against scope.yaml
  targets only.
- **Vuln analysis agent** — maps recon output to known CVEs, ranks by
  exploitability.
- **Exploit agent** — sandbox/lab-only, requires human confirmation per
  action, logs every action taken.
- **Reporting agent** — consolidates red-team findings into a structured
  report.
- **Footprint scan / breach check / risk score modules** — the OSINT
  pipeline, always subject-consent-gated per the rules above.

## Build Order

Follow this order — don't jump ahead to exploit agent or automation before
earlier phases are solid:

1. scope.yaml + safety-framework.md + repo structure (current phase)
2. Recon → vuln analysis → reporting agent, working end-to-end against
   Metasploitable2 (no exploitation yet)
3. OSINT module: manual assessment against a synthetic persona, written up
4. Expand red team module for AD lab enumeration
5. Exploit agent, with guardrails, tested only against lab targets
6. Automate the OSINT module (script the checks, generate risk score)
7. Polish: before/after remediation demo, documentation pass

## When Unsure

If a task would require acting outside scope.yaml, touching a real person's
data without documented consent, or skipping the human-confirmation step on
the exploit agent — stop and ask, don't proceed with an assumption.
