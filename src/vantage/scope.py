"""Scope enforcement — the single gate every agent passes through.

`scope.yaml` is the source of truth for what vantage is allowed to touch.
Nothing in this codebase should act on a target without first calling
``Scope.require_authorized``. Keeping that decision in one place is what makes
rules 1 and 6 of the safety framework enforceable in code rather than prose.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_SCOPE_PATH = Path(__file__).resolve().parents[2] / "scope.yaml"


class OutOfScopeError(Exception):
    """Raised when an agent tries to act on a target not in ``scope.yaml``."""


class ScopeConfigError(Exception):
    """Raised when ``scope.yaml`` is malformed."""


@dataclass(frozen=True)
class Target:
    name: str
    address: str
    type: str  # "host" or "network"
    authorized: bool
    notes: str = ""

    def matches(self, candidate: str) -> bool:
        """True if ``candidate`` (an IP or hostname) falls under this target."""
        if not self.authorized:
            return False

        cand = candidate.strip()

        # Try IP / CIDR semantics first.
        cand_ip = _as_ip(cand)
        if cand_ip is not None:
            net = _as_network(self.address)
            if net is not None:
                return cand_ip in net
            self_ip = _as_ip(self.address)
            if self_ip is not None:
                return cand_ip == self_ip
            # entry is a hostname, candidate is an IP -> no match
            return False

        # Candidate is not an IP: treat as a hostname, require literal match.
        # We deliberately do NOT resolve DNS — resolving could pull an
        # out-of-scope address into scope by accident.
        return cand.lower() == self.address.strip().lower()


@dataclass
class Scope:
    targets: list[Target] = field(default_factory=list)
    path: Path | None = None

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Scope":
        p = Path(path) if path is not None else DEFAULT_SCOPE_PATH
        if not p.exists():
            raise ScopeConfigError(f"scope file not found: {p}")
        with p.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return cls.from_dict(raw, path=p)

    @classmethod
    def from_dict(cls, raw: dict, path: Path | None = None) -> "Scope":
        if not isinstance(raw, dict):
            raise ScopeConfigError("scope.yaml must be a mapping at the top level")

        red_team = raw.get("red_team") or {}
        entries = red_team.get("targets") or []
        if not isinstance(entries, list):
            raise ScopeConfigError("red_team.targets must be a list")

        targets: list[Target] = []
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ScopeConfigError(f"red_team.targets[{i}] must be a mapping")
            try:
                address = str(entry["address"]).strip()
                name = str(entry.get("name", address))
            except KeyError as exc:
                raise ScopeConfigError(
                    f"red_team.targets[{i}] missing required key: {exc}"
                ) from exc
            ttype = str(entry.get("type", "host")).lower()
            if ttype not in ("host", "network"):
                raise ScopeConfigError(
                    f"red_team.targets[{i}].type must be 'host' or 'network'"
                )
            authorized = bool(entry.get("authorized", False))
            _validate_address(address, ttype, index=i)
            targets.append(
                Target(
                    name=name,
                    address=address,
                    type=ttype,
                    authorized=authorized,
                    notes=str(entry.get("notes", "")),
                )
            )
        return cls(targets=targets, path=path)

    # --- the gate --------------------------------------------------------

    def is_authorized(self, target: str) -> bool:
        return any(t.matches(target) for t in self.targets)

    def matching_target(self, target: str) -> Target | None:
        for t in self.targets:
            if t.matches(target):
                return t
        return None

    def require_authorized(self, target: str) -> Target:
        """Return the matching authorized target, or raise ``OutOfScopeError``.

        This is the call every agent must make before acting.
        """
        match = self.matching_target(target)
        if match is None:
            raise OutOfScopeError(
                f"target {target!r} is not authorized in scope.yaml "
                f"(known targets: {[t.address for t in self.targets] or 'none'}). "
                "Add it to scope.yaml only if you are authorized to test it."
            )
        return match


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _as_network(value: str):
    if "/" not in value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _validate_address(address: str, ttype: str, *, index: int) -> None:
    if ttype == "network":
        if _as_network(address) is None:
            raise ScopeConfigError(
                f"red_team.targets[{index}].address {address!r} is not a valid CIDR"
            )
        return
    # host: must be an IP or a plausible hostname (non-empty, no spaces)
    if _as_ip(address) is None:
        if not address or any(ch.isspace() for ch in address):
            raise ScopeConfigError(
                f"red_team.targets[{index}].address {address!r} is not a valid "
                "IP or hostname"
            )
