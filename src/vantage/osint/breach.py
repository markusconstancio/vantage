"""Breach-exposure lookup.

Pluggable like the CVE source: the default offline source reads breaches already
attached to the (synthetic) persona, so the pipeline runs without network. A
real deployment would implement ``BreachSource`` against Have I Been Pwned —
recording only the fact and metadata of exposure, never breached passwords.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .persona import Breach, Persona


class BreachSource(Protocol):
    def lookup(self, persona: Persona) -> list[Breach]:
        ...


@dataclass
class StaticBreachSource:
    """Offline source: returns the breaches recorded on the persona itself."""

    def lookup(self, persona: Persona) -> list[Breach]:
        return list(persona.breaches)
