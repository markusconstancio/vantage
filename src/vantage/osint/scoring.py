"""Risk scoring engine.

Implements the 6-factor weighted model from docs/osint-methodology.md. Each
factor is rated 0-3 from the persona's facts + current posture; ratings are
weighted, summed, and normalised to 0-100.
"""

from __future__ import annotations

from dataclasses import dataclass

from .persona import Breach, Persona

WEIGHTS = {
    "breach_exposure": 5,
    "credential_reuse": 4,
    "identity_exposure": 3,
    "contact_exposure": 3,
    "pretext_material": 3,
    "account_discoverability": 2,
}
MAX_RAW = 3 * sum(WEIGHTS.values())  # 60


@dataclass
class FactorScore:
    factor: str
    rating: int
    weight: int
    rationale: str

    @property
    def weighted(self) -> int:
        return self.rating * self.weight


def _breach_exposure(breaches: list[Breach], mfa_enabled: bool) -> FactorScore:
    with_pw = [b for b in breaches if b.passwords_exposed]
    if not breaches:
        rating, why = 0, "No known breaches."
    elif not with_pw:
        rating, why = 1, f"{len(breaches)} breach(es), no passwords exposed."
    elif len(with_pw) >= 2:
        rating, why = 3, f"Passwords exposed in {len(with_pw)} breaches."
    else:
        rating, why = 2, "Passwords exposed in 1 breach."
    if mfa_enabled and rating > 0:
        rating -= 1
        why += " MFA mitigates (-1)."
    return FactorScore("breach_exposure", rating, WEIGHTS["breach_exposure"], why)


def _credential_reuse(p: Persona) -> FactorScore:
    has_pw_breach = any(b.passwords_exposed for b in p.breaches)
    reused = bool(p.reused_handle)
    if p.posture.passwords_unique:
        rating = 1 if reused else 0
        why = "Unique passwords; residual risk from handle reuse only." if reused \
            else "Unique passwords, no handle reuse."
    elif reused and has_pw_breach:
        rating, why = 3, "Reused handle + a password breach → reuse likely."
    elif reused and len(p.linked_accounts) >= 3:
        rating, why = 2, "One handle reused across many accounts."
    elif reused:
        rating, why = 1, "Some handle reuse."
    else:
        rating, why = 0, "No obvious reuse."
    return FactorScore("credential_reuse", rating, WEIGHTS["credential_reuse"], why)


def _identity_exposure(p: Persona) -> FactorScore:
    rating, why = 1, "Full name discoverable."
    if p.photos_public:
        rating, why = 2, "Name + public photos."
    if p.dob_hints:
        rating, why = 3, "Name + photos + date-of-birth hints."
    return FactorScore("identity_exposure", rating, WEIGHTS["identity_exposure"], why)


def _contact_exposure(p: Persona) -> FactorScore:
    rating, why = 0, "No public contact details."
    if p.emails:
        rating, why = 1, "Public email(s)."
    if p.posture.phone_public and p.phone:
        rating, why = 2, "Public email and phone."
    if p.posture.address_public:
        rating, why = 3, "Public email, phone, and address."
    return FactorScore("contact_exposure", rating, WEIGHTS["contact_exposure"], why)


def _pretext_material(p: Persona) -> FactorScore:
    if p.employer and p.role and p.interests:
        rating, why = 2, "Employer + role + interests enable a targeted lure."
    elif p.interests:
        rating, why = 1, "Some interests usable as pretext."
    else:
        rating, why = 0, "Little pretext material."
    if len(p.interests) >= 4 and p.employer:
        rating, why = 3, "Rich, ready-made pretext material."
    return FactorScore("pretext_material", rating, WEIGHTS["pretext_material"], why)


def _account_discoverability(p: Persona) -> FactorScore:
    n = len(p.linked_accounts)
    if n == 0:
        rating, why = 0, "No linkable accounts."
    elif n <= 2:
        rating, why = 1, f"{n} linkable account(s)."
    elif n <= 4:
        rating, why = 2, f"{n} accounts linkable via one handle."
    else:
        rating, why = 3, "Fully linkable persona."
    return FactorScore(
        "account_discoverability", rating, WEIGHTS["account_discoverability"], why
    )


def band(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Moderate"
    return "Low"


@dataclass
class RiskScore:
    score: int
    band: str
    factors: list[FactorScore]

    @property
    def raw(self) -> int:
        return sum(f.weighted for f in self.factors)


def score_persona(p: Persona) -> RiskScore:
    factors = [
        _breach_exposure(p.breaches, p.posture.mfa_enabled),
        _credential_reuse(p),
        _identity_exposure(p),
        _contact_exposure(p),
        _pretext_material(p),
        _account_discoverability(p),
    ]
    raw = sum(f.weighted for f in factors)
    score = round(raw / MAX_RAW * 100)
    return RiskScore(score=score, band=band(score), factors=factors)
