"""Subject/persona model for the OSINT module.

A subject's public footprint is normalised into this structure. For the demo,
subjects are synthetic personas loaded from YAML (see personas/). Real subjects
would be populated the same way from consented, public-only collection.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Breach:
    name: str
    data_classes: list[str] = field(default_factory=list)
    passwords_exposed: bool = False


@dataclass
class Posture:
    """Mutable security posture — what remediation can change."""

    mfa_enabled: bool = False
    passwords_unique: bool = False
    phone_public: bool = True
    address_public: bool = False


@dataclass
class Persona:
    name: str
    kind: str = "synthetic"  # self | synthetic | consented
    reused_handle: str | None = None
    emails: list[str] = field(default_factory=list)
    phone: str | None = None
    employer: str | None = None
    role: str | None = None
    location: str | None = None
    personal_domain: str | None = None
    photos_public: bool = False
    dob_hints: bool = False
    interests: list[str] = field(default_factory=list)
    linked_accounts: list[str] = field(default_factory=list)
    breaches: list[Breach] = field(default_factory=list)
    posture: Posture = field(default_factory=Posture)

    @classmethod
    def from_dict(cls, raw: dict) -> "Persona":
        breaches = [
            Breach(
                name=str(b["name"]),
                data_classes=list(b.get("data_classes", [])),
                passwords_exposed=bool(b.get("passwords_exposed", False)),
            )
            for b in (raw.get("breaches") or [])
        ]
        p = raw.get("posture") or {}
        posture = Posture(
            mfa_enabled=bool(p.get("mfa_enabled", False)),
            passwords_unique=bool(p.get("passwords_unique", False)),
            phone_public=bool(p.get("phone_public", True)),
            address_public=bool(p.get("address_public", False)),
        )
        return cls(
            name=str(raw["name"]),
            kind=str(raw.get("kind", "synthetic")),
            reused_handle=raw.get("reused_handle"),
            emails=list(raw.get("emails", [])),
            phone=raw.get("phone"),
            employer=raw.get("employer"),
            role=raw.get("role"),
            location=raw.get("location"),
            personal_domain=raw.get("personal_domain"),
            photos_public=bool(raw.get("photos_public", False)),
            dob_hints=bool(raw.get("dob_hints", False)),
            interests=list(raw.get("interests", [])),
            linked_accounts=list(raw.get("linked_accounts", [])),
            breaches=breaches,
            posture=posture,
        )

    @classmethod
    def load(cls, path) -> "Persona":
        import yaml
        from pathlib import Path

        with Path(path).open("r", encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})

    def with_posture(self, **changes) -> "Persona":
        """Return a copy with an adjusted posture (for before/after demos)."""
        import copy

        clone = copy.deepcopy(self)
        for k, v in changes.items():
            setattr(clone.posture, k, v)
        return clone
