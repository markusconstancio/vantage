"""Orchestrator — coordinates the red-team pipeline.

Intended pipeline: recon -> vuln analysis -> reporting, with the exploit stage
gated behind explicit per-action human confirmation.

Only the recon stage exists today. This module is a thin skeleton documenting
the shape of the pipeline; later phases fill in the remaining stages. The
exploit stage is intentionally left unimplemented (safety-framework.md rule 2).
"""

from __future__ import annotations

from dataclasses import dataclass

from .agents.recon import ReconAgent
from .scope import Scope


@dataclass
class Orchestrator:
    scope: Scope

    def recon(self, target: str, **kwargs) -> dict:
        return ReconAgent(scope=self.scope).scan(target, **kwargs)

    # Later phases:
    # def analyze(self, recon_result: dict) -> dict: ...   # vuln analysis
    # def report(self, findings: dict) -> str: ...         # reporting
    # exploit stage: not implemented — requires per-action human confirmation.

    @classmethod
    def from_scope_file(cls, path: str | None = None) -> "Orchestrator":
        return cls(scope=Scope.load(path))
