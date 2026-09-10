"""Active Directory / SMB enumeration agent.

An extension of recon for Windows/AD lab targets. It wraps nmap's SMB NSE
scripts (enumeration only — no exploitation, no credential brute-forcing) and
parses the host-script output into structured findings: OS/computer/domain,
shares, users, and SMB security posture.

Like every agent, it gates on scope first: an out-of-scope target raises before
nmap runs.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..audit import AuditLog
from ..scope import Scope, Target
from .recon import ReconError

# Enumeration-only NSE scripts. Deliberately excludes anything that
# authenticates, brute-forces, or exploits.
DEFAULT_SCRIPTS = (
    "smb-os-discovery",
    "smb-enum-shares",
    "smb-enum-users",
    "smb-enum-domains",
    "smb-security-mode",
)


@dataclass
class ADEnumAgent:
    scope: Scope
    audit: AuditLog = field(default_factory=AuditLog)
    nmap_path: str = "nmap"
    scripts: tuple[str, ...] = DEFAULT_SCRIPTS
    ports: str = "139,445"

    def build_command(self, target: str) -> list[str]:
        return [
            self.nmap_path,
            "-p", self.ports,
            "--script", ",".join(self.scripts),
            "-oX", "-",
            target,
        ]

    def enumerate(self, target: str, *, dry_run: bool = False,
                  timeout: int = 1800) -> dict:
        matched: Target = self.scope.require_authorized(target)
        cmd = self.build_command(target)

        self.audit.record(
            "ad_enum.enumerate",
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
                "that runs the AD enumeration (e.g. your Kali box)."
            )

        started = datetime.now(timezone.utc).isoformat()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise ReconError(f"nmap timed out after {timeout}s") from exc
        if proc.returncode != 0:
            raise ReconError(
                f"nmap exited {proc.returncode}: {proc.stderr.strip()[:500]}"
            )

        result = parse_ad_xml(proc.stdout)
        result["target"] = target
        result["matched_scope"] = matched.name
        result["scanned_at"] = started
        return result


def _script_text(host, script_id: str) -> str | None:
    for script in host.findall("hostscript/script"):
        if script.get("id") == script_id:
            return script.get("output")
    return None


def _enum_share_names(host) -> list[str]:
    shares: list[str] = []
    for script in host.findall("hostscript/script"):
        if script.get("id") != "smb-enum-shares":
            continue
        # nmap nests shares as tables keyed by share path.
        for table in script.findall("table"):
            key = table.get("key")
            if key:
                shares.append(key)
    return shares


def _enum_user_names(host) -> list[str]:
    users: list[str] = []
    for script in host.findall("hostscript/script"):
        if script.get("id") != "smb-enum-users":
            continue
        for table in script.findall("table"):
            key = table.get("key")
            if key:
                users.append(key)
    return users


def parse_ad_xml(xml_text: str) -> dict:
    """Parse nmap SMB-script XML into structured AD findings."""
    if not xml_text or not xml_text.strip():
        raise ReconError("empty nmap output")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ReconError(f"could not parse nmap XML: {exc}") from exc

    hosts = []
    for host in root.findall("host"):
        address = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                address = addr.get("addr")
                break

        hosts.append(
            {
                "address": address,
                "os_discovery": _script_text(host, "smb-os-discovery"),
                "security_mode": _script_text(host, "smb-security-mode"),
                "domains": _script_text(host, "smb-enum-domains"),
                "shares": _enum_share_names(host),
                "users": _enum_user_names(host),
            }
        )
    return {"hosts": hosts}
