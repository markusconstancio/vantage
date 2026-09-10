"""Vulnerability analysis agent.

Consumes recon output and maps each open service's product/version to known
CVEs, then ranks findings by exploitability (exploit available first, then
CVSS). The CVE data comes from a pluggable ``CveSource``; the default
``StaticCveSource`` reads a curated offline database so the pipeline runs and
tests without any external service. A production build can drop in an
NVD/CPE-backed source implementing the same interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import yaml

DEFAULT_CVE_DB = Path(__file__).resolve().parents[3] / "data" / "cve_db.yaml"


@dataclass(frozen=True)
class Vulnerability:
    cve: str
    title: str
    cvss: float
    exploit_available: bool
    references: tuple[str, ...] = ()


class CveSource(Protocol):
    def lookup(self, product: str, version: str) -> list[Vulnerability]:
        """Return known vulnerabilities for a product/version pair."""
        ...


@dataclass
class StaticCveSource:
    """Offline CVE source using simple product-substring + version-prefix match.

    Version matching is intentionally simple (prefix comparison) — it is exact
    enough for a curated lab database and avoids depending on a version-parsing
    library. It does NOT implement general version-range semantics; that is the
    job of a future NVD/CPE-backed source.
    """

    entries: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "StaticCveSource":
        p = Path(path) if path is not None else DEFAULT_CVE_DB
        with p.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return cls(entries=raw.get("entries") or [])

    def lookup(self, product: str, version: str) -> list[Vulnerability]:
        if not product:
            return []
        product_l = product.lower()
        version = (version or "").strip()
        out: list[Vulnerability] = []
        for e in self.entries:
            ep = str(e.get("product", "")).lower()
            if not ep or ep not in product_l:
                continue
            prefixes = e.get("affected_prefixes") or []
            if prefixes and not any(version.startswith(str(p)) for p in prefixes):
                continue
            out.append(
                Vulnerability(
                    cve=str(e["cve"]),
                    title=str(e.get("title", e["cve"])),
                    cvss=float(e.get("cvss", 0.0)),
                    exploit_available=bool(e.get("exploit_available", False)),
                    references=tuple(e.get("references") or ()),
                )
            )
        return out


@dataclass
class VulnAnalysisAgent:
    source: CveSource

    @classmethod
    def with_static_db(cls, path: str | Path | None = None) -> "VulnAnalysisAgent":
        return cls(source=StaticCveSource.load(path))

    def analyze(self, recon_result: dict) -> dict:
        findings: list[dict] = []
        services_seen = 0
        for host in recon_result.get("hosts", []):
            address = host.get("address")
            for port in host.get("ports", []):
                if port.get("state") != "open":
                    continue
                services_seen += 1
                product = port.get("product")
                version = port.get("version", "")
                if not product:
                    continue
                for vuln in self.source.lookup(product, version):
                    findings.append(
                        {
                            "host": address,
                            "port": port.get("port"),
                            "protocol": port.get("protocol"),
                            "service": port.get("service"),
                            "product": product,
                            "version": version,
                            "cve": vuln.cve,
                            "title": vuln.title,
                            "cvss": vuln.cvss,
                            "exploit_available": vuln.exploit_available,
                            "references": list(vuln.references),
                        }
                    )

        findings.sort(key=lambda f: (not f["exploit_available"], -f["cvss"]))

        return {
            "target": recon_result.get("target"),
            "matched_scope": recon_result.get("matched_scope"),
            "scanned_at": recon_result.get("scanned_at"),
            "summary": {
                "open_services": services_seen,
                "findings": len(findings),
                "with_public_exploit": sum(
                    1 for f in findings if f["exploit_available"]
                ),
                "max_cvss": max((f["cvss"] for f in findings), default=0.0),
            },
            "findings": findings,
        }
