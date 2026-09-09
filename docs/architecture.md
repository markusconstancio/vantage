# Architecture

vantage is two modules sharing one pattern: **orchestrator → specialist agents
→ reporting**. Everything funnels through a single scope gate.

```
                        scope.yaml  (single source of truth)
                              │
                     ┌────────┴────────┐
                     │  vantage.scope  │  require_authorized() — the gate
                     └────────┬────────┘
                              │ (every agent calls this first)
        ┌─────────────────────┼──────────────────────┐
        │                     │                       │
   Red Team module       OSINT module            audit log
   (orchestrator)        (later phase)         logs/audit.log
        │
   ┌────┼─────────────┬───────────────┬──────────────┐
   │    │             │               │              │
 recon  →  vuln analysis  →  reporting        exploit (deferred,
 (now)     (next)            (next)            human-gated, later)
```

## Module 1 — Red Team

- **`vantage.scope`** — loads and validates `scope.yaml`; `require_authorized`
  is the choke point every agent passes through. Supports exact-IP and CIDR
  matching; hostnames match literally (no DNS resolution, to avoid pulling an
  out-of-scope address into scope).
- **`vantage.audit`** — append-only JSON audit log of consequential actions.
- **`vantage.agents.recon`** — `nmap` wrapper. `scan()` gates on scope first,
  runs `-sV -sC` enumeration against a single target, and parses the XML into a
  structured dict. Enumeration only; no exploitation, no discovery sweeps.
- **`vantage.orchestrator`** — coordinates the pipeline. Currently only wires up
  recon; vuln-analysis and reporting stages are stubs. The exploit stage is
  intentionally not implemented (safety-framework.md rule 2).
- **`vantage.cli`** — `python -m vantage recon <target>`.

### Recon output shape

```json
{
  "target": "…",
  "matched_scope": "metasploitable2",
  "scanned_at": "2026-…Z",
  "hosts": [
    {
      "address": "…",
      "state": "up",
      "hostnames": ["…"],
      "ports": [
        {"port": 21, "protocol": "tcp", "state": "open",
         "service": "ftp", "product": "vsftpd", "version": "2.3.4"}
      ]
    }
  ]
}
```

The vuln-analysis agent (next phase) consumes this and maps
`product`/`version` pairs to known CVEs.

## Module 2 — OSINT (later phase)

Footprint scan → breach check (HIBP) → attack-scenario mapping → risk score +
remediation report. Subjects are consent-gated through the same `scope.yaml`
(`osint.subjects`, each with a `kind` of self/synthetic/consented). Not yet
implemented.

## Where it runs

The red-team agents shell out to `nmap` and are meant to run from a testing
host (e.g. Kali) on the same isolated lab network as the targets. This remote
repo environment has no route to any lab, so live scans are run by the operator
locally; the test suite exercises the logic offline against saved sample data.
