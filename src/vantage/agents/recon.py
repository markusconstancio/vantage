"""Recon agent — enumeration and service discovery, scope-gated.

Wraps ``nmap`` for service/version enumeration against a *single authorized
target*. It is deliberately narrow:

* The first thing ``scan()`` does is call ``Scope.require_authorized`` — an
  out-of-scope target raises before nmap is ever invoked.
* It scans one resolved target, never a discovery sweep of an unlisted range.
* It runs enumeration only (``-sV`` + default scripts). No exploitation, no
  intrusive/DoS scripts.
* Every invocation is written to the audit log.

Output is a plain dict (JSON-serialisable) that the vuln-analysis agent will
consume in the next phase.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..audit import AuditLog
from ..scope import Scope, Target


class ReconError(Exception):
    pass


@dataclass
class ReconAgent:
    scope: Scope
    audit: AuditLog = field(default_factory=AuditLog)
    nmap_path: str = "nmap"
    # Enumeration only: service/version detection + default (safe) scripts.
    base_args: tuple[str, ...] = ("-sV", "-sC")

    def build_command(self, target: str, *, ports: str | None = None,
                      extra_args: tuple[str, ...] = ()) -> list[str]:
        cmd = [self.nmap_path, *self.base_args]
        if ports:
            cmd += ["-p", ports]
        cmd += list(extra_args)
        cmd += ["-oX", "-", target]  # XML to stdout
        return cmd

    def scan(self, target: str, *, ports: str | None = None,
             extra_args: tuple[str, ...] = (), dry_run: bool = False,
             timeout: int = 1800) -> dict:
        # --- THE GATE: refuse anything not authorized in scope.yaml ---
        matched: Target = self.scope.require_authorized(target)

        cmd = self.build_command(target, ports=ports, extra_args=extra_args)

        self.audit.record(
            "recon.scan",
            target=target,
            matched_scope=matched.name,
            command=" ".join(cmd),
            dry_run=dry_run,
        )

        if dry_run:
            return {
                "target": target,
                "matched_scope": matched.name,
                "command": cmd,
                "dry_run": True,
            }

        if shutil.which(self.nmap_path) is None:
            raise ReconError(
                f"nmap not found ({self.nmap_path!r}). Install nmap on the host "
                "that runs the recon agent (e.g. your Kali box)."
            )

        started = datetime.now(timezone.utc).isoformat()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ReconError(f"nmap timed out after {timeout}s") from exc

        if proc.returncode != 0:
            raise ReconError(
                f"nmap exited {proc.returncode}: {proc.stderr.strip()[:500]}"
            )

        result = parse_nmap_xml(proc.stdout)
        result["target"] = target
        result["matched_scope"] = matched.name
        result["scanned_at"] = started
        return result


def parse_nmap_xml(xml_text: str) -> dict:
    """Parse nmap ``-oX`` XML into a structured dict.

    Returns {"hosts": [{"address", "state", "hostnames", "ports": [...]}]}.
    """
    if not xml_text or not xml_text.strip():
        raise ReconError("empty nmap output")

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ReconError(f"could not parse nmap XML: {exc}") from exc

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        state = status.get("state") if status is not None else None

        address = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                address = addr.get("addr")
                break
        if address is None:
            addr = host.find("address")
            address = addr.get("addr") if addr is not None else None

        hostnames = [
            hn.get("name")
            for hn in host.findall("hostnames/hostname")
            if hn.get("name")
        ]

        ports = []
        for port in host.findall("ports/port"):
            pstate = port.find("state")
            svc = port.find("service")
            entry = {
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": pstate.get("state") if pstate is not None else None,
            }
            if svc is not None:
                entry.update(
                    {
                        "service": svc.get("name"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "extrainfo": svc.get("extrainfo"),
                    }
                )
                entry = {k: v for k, v in entry.items() if v is not None}
            ports.append(entry)

        hosts.append(
            {
                "address": address,
                "state": state,
                "hostnames": hostnames,
                "ports": ports,
            }
        )

    return {"hosts": hosts}
