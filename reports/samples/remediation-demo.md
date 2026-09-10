# Before / After Remediation Demo — Jordan Rivera (SYNTHETIC)

> Synthetic persona; automated by `vantage.osint`. Reproduce with:
> ```
> python -m vantage osint personas/jordan-rivera.yaml --markdown
> python -m vantage osint personas/jordan-rivera.yaml --remediated --markdown
> ```

The automated scorer reproduces the manual assessment (73/100) and quantifies
the impact of remediation.

| | Before | After | Δ |
|---|:---:|:---:|:---:|
| **Risk score** | **73 / 100** | **47 / 100** | **−26** |
| Band | High | Moderate | ↓ |
| Breach exposure (×5) | 2 | 1 | MFA mitigates |
| Credential reuse (×4) | 3 | 1 | unique passwords |
| Identity exposure (×3) | 2 | 2 | — |
| Contact exposure (×3) | 2 | 1 | phone delisted |
| Pretext material (×3) | 2 | 2 | — |
| Account discoverability (×2) | 2 | 2 | — |
| Raw / 60 | 44 | 28 | −16 |

## What changed

Three low-effort remediations account for the entire drop:

1. **Enable MFA** — reduces the effective breach-exposure impact (a leaked
   password no longer grants access).
2. **Unique passwords via a manager** — breaks the credential-reuse chain that
   made account takeover the most plausible attack.
3. **Remove the phone number from public listings** — lowers contact exposure
   and undercuts the vishing/SIM-swap pretext.

Full reports:
[before](osint-automated-before.md) · [after](osint-automated-after.md).

The remaining exposure (identity, pretext, discoverability) is inherent to
having a public professional presence; it is managed by profile-visibility
hygiene rather than eliminated.
