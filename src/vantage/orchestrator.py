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
from .agents.reporting import ReportingAgent
from .agents.vuln import VulnAnalysisAgent
from .scope import Scope


@dataclass
class Orchestrator:
    scope: Scope

    def recon(self, target: str, **kwargs) -> dict:
        return ReconAgent(scope=self.scope).scan(target, **kwargs)

    def analyze(self, recon_result: dict) -> dict:
        return VulnAnalysisAgent.with_static_db().analyze(recon_result)

    def report(self, recon_result: dict, analysis: dict) -> str:
        return ReportingAgent().render_markdown(recon_result, analysis)

    def run(self, target: str, **recon_kwargs) -> dict:
        """recon -> analyze -> report. (Runs recon live, so needs nmap + scope.)"""
        recon_result = self.recon(target, **recon_kwargs)
        analysis = self.analyze(recon_result)
        return {
            "recon": recon_result,
            "analysis": analysis,
            "report_markdown": self.report(recon_result, analysis),
        }

    # exploit stage: not implemented — requires per-action human confirmation.

    @classmethod
    def from_scope_file(cls, path: str | None = None) -> "Orchestrator":
        return cls(scope=Scope.load(path))
