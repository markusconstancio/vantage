# OSINT / Social-Engineering Risk Assessment — Methodology

This is the manual methodology the OSINT module follows. Phase 6 automates
these steps; this document is the reference the automation implements against.

> **Consent gate (rule 3).** This methodology is only ever applied to: the
> author (self), a synthetic demo persona, or a real subject with documented,
> scoped consent. Subjects are listed in `scope.yaml` under `osint.subjects`,
> each tagged `self` / `synthetic` / `consented`. Sample output in this repo
> uses a synthetic persona only.

## Goal

Estimate how exposed a person is to social-engineering and account-takeover
attacks based on their *public* digital footprint, and give concrete,
prioritised remediation. The output is a 0–100 risk score plus a report.

## Pipeline

```
footprint scan  ->  breach exposure  ->  attack-scenario mapping  ->  risk score  ->  remediation
```

### 1. Footprint scan
Collect what is publicly discoverable about the subject and normalise it into
categories:

| Category | Examples |
|----------|----------|
| Identity | full name, aliases, photos |
| Contact | public emails, phone numbers |
| Accounts | reused usernames/handles across platforms |
| Employment | employer, role, work email format |
| Location | city, workplace, checked-in venues |
| Interests | hobbies, pets, family — pretext + password-guess material |
| Technical | personal domains, exposed metadata |

Only public sources are used. No authentication to third-party accounts, no
scraping behind logins, no attempts to access non-public data.

### 2. Breach exposure
Check whether the subject's emails/usernames appear in known breach corpora
(Have I Been Pwned). Record: number of breaches, whether passwords were
exposed, and the sensitivity of breached data classes. **No breach passwords
are stored** — only the fact and metadata of exposure.

### 3. Attack-scenario mapping
Translate the footprint + breach data into realistic attacker playbooks, e.g.:
- **Credential stuffing** — reused username + a breach with exposed passwords.
- **Spear-phishing pretext** — employer + role + interests enable a convincing
  lure.
- **Security-question / password guessing** — pet names, birthplace, family.
- **SIM-swap / vishing** — exposed phone + employer for helpdesk pretext.

Each scenario notes the exposed data that enables it and its plausibility.

### 4. Risk score (0–100)

The score is the weighted sum of six factors, each rated 0–3, normalised to
100. Higher = more exposed.

| Factor | 0 | 1 | 2 | 3 | Weight |
|--------|---|---|---|---|:-----:|
| Breach exposure | none | 1–2 breaches, no passwords | passwords in ≥1 breach | passwords + recent/multiple | 5 |
| Credential reuse | unique everywhere | some reuse | username reused widely | username+password reuse likely | 4 |
| Identity exposure | minimal | name only | name + photos + DOB hints | full identity kit | 3 |
| Contact exposure | none public | email only | email + phone | email + phone + address | 3 |
| Pretext material | little | some interests | employer + role + interests | rich, targeted pretext ready | 3 |
| Account discoverability | none linkable | few linkable | many linkable via one handle | fully linkable persona | 2 |

`raw = Σ(rating × weight)`, `max = 3 × Σweights = 3 × 20 = 60`,
`score = round(raw / max × 100)`.

Bands: **0–24 Low · 25–49 Moderate · 50–74 High · 75–100 Critical.**

### 5. Remediation
For every contributing factor, give a specific, actionable fix ranked by
impact-per-effort (e.g. enable MFA, rotate reused passwords via a manager,
lock down profile visibility, remove exposed phone from public listings).

## What this module never does
- Never targets a person outside `scope.yaml`.
- Never accesses non-public data or authenticates as the subject.
- Never stores breach passwords.
- Never commits real subjects' findings to the repo (rule 5) — only synthetic
  samples are committed.
