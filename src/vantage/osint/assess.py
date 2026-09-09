"""OSINT assessment orchestrator.

Ties the pipeline together: breach lookup -> risk score -> attack-scenario
mapping -> remediation -> report. Produces a structured dict and a Markdown
rendering matching the manual sample's format.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .breach import BreachSource, StaticBreachSource
from .persona import Persona
from .scoring import RiskScore, score_persona


def _scenarios(p: Persona, score: RiskScore) -> list[dict]:
    ratings = {f.factor: f.rating for f in score.factors}
    out: list[dict] = []
    has_pw_breach = any(b.passwords_exposed for b in p.breaches)

    if has_pw_breach and ratings.get("credential_reuse", 0) >= 2:
        out.append({
            "name": "Credential stuffing / account takeover",
            "enabled_by": "breach passwords + credential reuse",
            "plausibility": "high",
        })
    if p.employer and p.role and p.emails:
        out.append({
            "name": "Spear-phishing with an internal pretext",
            "enabled_by": "employment exposure + known email format",
            "plausibility": "high",
        })
    if ratings.get("identity_exposure", 0) >= 2 or p.interests:
        out.append({
            "name": "Security-question / password guessing",
            "enabled_by": "interests + identity exposure",
            "plausibility": "medium",
        })
    if p.posture.phone_public and p.phone and p.employer:
        out.append({
            "name": "Vishing / SIM-swap groundwork",
            "enabled_by": "contact exposure + employment",
            "plausibility": "medium",
        })
    return out


def _remediation(p: Persona, score: RiskScore) -> list[str]:
    ratings = {f.factor: f.rating for f in score.factors}
    recs: list[str] = []
    if not p.posture.mfa_enabled:
        recs.append("Enable MFA everywhere, prioritising email and code hosts "
                    "(kills credential-stuffing even if a password leaks).")
    if not p.posture.passwords_unique or ratings.get("credential_reuse", 0) >= 2:
        recs.append("Rotate all reused passwords via a password manager, unique "
                    "per site.")
    if p.posture.phone_public and p.phone:
        recs.append("Remove the phone number from public listings/resumes and "
                    "request cache removal.")
    if ratings.get("account_discoverability", 0) >= 2:
        recs.append("Stop reusing one handle across personal and professional "
                    "accounts.")
    if p.interests or ratings.get("identity_exposure", 0) >= 2:
        recs.append("Tighten profile visibility; set account-recovery answers to "
                    "random values, not real facts.")
    return recs


@dataclass
class OsintAgent:
    breach_source: BreachSource = field(default_factory=StaticBreachSource)

    def assess(self, persona: Persona) -> dict:
        breaches = self.breach_source.lookup(persona)
        # ensure the persona used for scoring reflects the resolved breaches
        persona.breaches = breaches
        score = score_persona(persona)
        return {
            "subject": persona.name,
            "kind": persona.kind,
            "score": score.score,
            "band": score.band,
            "raw": score.raw,
            "max_raw": 60,
            "factors": [
                {
                    "factor": f.factor,
                    "rating": f.rating,
                    "weight": f.weight,
                    "weighted": f.weighted,
                    "rationale": f.rationale,
                }
                for f in score.factors
            ],
            "breaches": [
                {"name": b.name, "passwords_exposed": b.passwords_exposed}
                for b in breaches
            ],
            "scenarios": _scenarios(persona, score),
            "remediation": _remediation(persona, score),
        }

    def render_markdown(self, assessment: dict) -> str:
        lines: list[str] = []
        subj = assessment["subject"]
        lines.append(f"# OSINT Risk Assessment — {subj}")
        lines.append("")
        lines.append(f"- **Subject:** {subj} ({assessment['kind']})")
        lines.append(
            f"- **Risk score:** {assessment['score']}/100 — "
            f"**{assessment['band']}** "
            f"(raw {assessment['raw']}/{assessment['max_raw']})"
        )
        lines.append("")
        lines.append("## Factor breakdown")
        lines.append("")
        lines.append("| Factor | Rating | Weight | Score | Rationale |")
        lines.append("|--------|:-----:|:-----:|:-----:|-----------|")
        for f in assessment["factors"]:
            lines.append(
                f"| {f['factor'].replace('_', ' ')} | {f['rating']} | "
                f"{f['weight']} | {f['weighted']} | {f['rationale']} |"
            )
        lines.append("")
        lines.append("## Attack scenarios")
        lines.append("")
        if not assessment["scenarios"]:
            lines.append("_None mapped._")
        for i, s in enumerate(assessment["scenarios"], 1):
            lines.append(
                f"{i}. **{s['name']}** ({s['plausibility']}) — "
                f"enabled by {s['enabled_by']}."
            )
        lines.append("")
        lines.append("## Remediation (ranked)")
        lines.append("")
        for i, r in enumerate(assessment["remediation"], 1):
            lines.append(f"{i}. {r}")
        lines.append("")
        lines.append("---")
        lines.append("_Generated by vantage OSINT module. Consent-gated subject; "
                     "public-source data only; no breached passwords stored._")
        lines.append("")
        return "\n".join(lines)
