# Safety Framework

vantage is a security assessment platform. It only ever operates against
targets that are **explicitly authorized** and, for the red-team module,
**isolated from any production or third-party system**. This document states
the rules and — importantly — how each is enforced in *code*, not just prose.

> Read this before running anything.

## The Rules (from AGENTS.md, expanded)

### 1. `scope.yaml` is the single source of truth
No agent acts against any target — IP, hostname, CIDR, or person — that is not
explicitly listed in `scope.yaml` with `authorized: true`.

**Enforced by:** `vantage.scope.Scope`. Every agent resolves its target through
`Scope.require_authorized(target)` *before* doing anything. Out-of-scope
targets raise `OutOfScopeError`; the agent never reaches its action code. The
recon agent calls this gate as the first line of `scan()`. This is covered by
`tests/test_scope.py` (authorized pass, out-of-scope raises, empty scope
refuses everything).

### 2. The exploit agent never acts autonomously
Every exploitation action requires explicit, in-the-moment human confirmation —
never a blanket "yes" at session start.

**Enforced by:** not yet applicable — the exploit agent is **not implemented**
and is deliberately deferred to a later phase (see build order). When it is
built, confirmation will be a per-action prompt that cannot be satisfied by a
config flag or environment variable. Until then, no exploitation code exists in
this repo.

### 3. The OSINT module is consent-gated
It runs only against: the author (self), a synthetic demo persona, or a real
subject with documented, scoped consent. Never an arbitrary real person.

**Enforced by:** `scope.yaml`'s `osint.subjects` list, each with an explicit
`kind` (`self` / `synthetic` / `consented`). The OSINT pipeline (later phase)
resolves subjects through the same scope gate. Sample reports committed to this
repo use a synthetic persona only.

### 4. Never commit secrets
API keys, credentials, and `.env` contents stay out of git.

**Enforced by:** `.gitignore` (`.env`, `logs/`, `reports/real/`); `.env.example`
documents required variables with placeholder values only. Code reads secrets
from the environment, never from committed files.

### 5. Real findings stay private
Only synthetic-persona sample reports go in the public repo. Real assessment
output — even consented — is not committed.

**Enforced by:** `.gitignore` excludes `reports/real/` and audit logs. Real
output is written under ignored paths by convention; sample output lives under
`reports/samples/`.

### 6. No network scanning outside `scope.yaml` targets
Not even "just to test." The isolated lab should make this physically
impossible; the code must also refuse to attempt it.

**Enforced by:** rule 1's gate. There is no code path that scans an arbitrary
range — the recon agent requires a target that resolves as authorized, and it
does not perform host-discovery sweeps of unlisted networks.

## Operating Model

- **Where it runs:** the red-team agents are meant to run from your own testing
  host (e.g. Kali) that sits on the same isolated lab network as the targets.
  They shell out to `nmap`, so `nmap` must be installed there.
- **Isolation:** the lab network must have no route to the internet or to any
  production/third-party system. `scope.yaml` is a second line of defense, not
  the only one.
- **Audit trail:** every recon invocation is appended to `logs/audit.log`
  (git-ignored) with a timestamp, the resolved target, and the exact command.

## When Unsure

If a task would require acting outside `scope.yaml`, touching a real person's
data without documented consent, or skipping human confirmation on the (future)
exploit agent — stop and ask. Do not proceed on an assumption.
