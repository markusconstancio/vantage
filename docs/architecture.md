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
 (done)    (done)            (done)            human-gated, later)
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
- **`vantage.agents.vuln`** — maps each open service's product/version to known
  CVEs via a pluggable `CveSource` and ranks findings by exploitability
  (public exploit first, then CVSS). The default `StaticCveSource` reads a
  curated offline database (`data/cve_db.yaml`) using product-substring +
  version-prefix matching; a future NVD/CPE source implementing the same
  `lookup(product, version)` interface drops in without touching the agent.
- **`vantage.agents.reporting`** — consolidates recon + findings into a
  structured Markdown report (summary, open-services table, ranked findings).
- **`vantage.report_html`** — renders both the findings report and the OSINT
  assessment as self-contained, theme-aware (light/dark) HTML, using the
  validated status palette (severity/risk, always with a text label) and a
  single blue ramp for magnitude bars. All external strings are HTML-escaped.
- **`vantage.agents.ad_enum`** — SMB/AD enumeration for Windows lab targets.
  Wraps nmap SMB NSE scripts (OS/domain discovery, shares, users, security
  mode), scope-gated and audited like recon. Enumeration only — no auth, no
  brute-forcing, no exploitation. Parses host-script XML into structured
  findings.
- **`vantage.orchestrator`** — wires recon → analyze → report. The exploit
  stage is intentionally not implemented (safety-framework.md rule 2).
- **`vantage.cli`** — `recon <target>`, `analyze <recon.json|->`,
  `report <recon.json|-> [-o out.md]`.

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

The vuln-analysis agent consumes this and maps `product`/`version` pairs to
known CVEs, emitting ranked findings that the reporting agent renders. See
[`reports/samples/`](../reports/samples/metasploitable2-sample.md) for a worked
example generated from synthetic data.

## Module 2 — OSINT (`vantage.osint`)

Footprint → breach check → attack-scenario mapping → 0–100 risk score →
remediation. Subjects are consent-gated through `scope.yaml` (`osint.subjects`,
each `kind` self/synthetic/consented); only synthetic personas are committed.

- **`persona.py`** — the subject model + YAML loader; `Posture` holds the
  mutable security flags (MFA, unique passwords, phone public) that remediation
  changes, enabling before/after scoring.
- **`breach.py`** — pluggable `BreachSource`; the offline `StaticBreachSource`
  reads breaches off the persona. A HIBP-backed source implements the same
  interface and records only exposure metadata, never breached passwords.
- **`scoring.py`** — the 6-factor weighted model (see osint-methodology.md).
  Derives each 0–3 rating from persona facts + posture, normalises to 0–100,
  and bands the result.
- **`assess.py`** — `OsintAgent` orchestrates the pipeline and renders the
  Markdown report (factor breakdown, scenarios, remediation).
- **CLI** — `osint <persona.yaml> [--remediated] [--markdown]`.

See the [methodology](osint-methodology.md) and the
[before/after demo](../reports/samples/remediation-demo.md).

## Where it runs

The red-team agents shell out to `nmap` and are meant to run from a testing
host (e.g. Kali) on the same isolated lab network as the targets. This remote
repo environment has no route to any lab, so live scans are run by the operator
locally; the test suite exercises the logic offline against saved sample data.
