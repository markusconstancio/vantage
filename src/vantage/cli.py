"""Command-line entry point for vantage.

Usage:
    python -m vantage recon <target> [--ports 1-1000] [--dry-run] [--json]

The recon subcommand refuses any target not authorized in scope.yaml.
"""

from __future__ import annotations

import argparse
import json
import sys

from .agents.recon import ReconAgent, ReconError
from .scope import OutOfScopeError, Scope, ScopeConfigError


def _cmd_recon(args) -> int:
    try:
        scope = Scope.load(args.scope)
    except ScopeConfigError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2

    agent = ReconAgent(scope=scope)
    try:
        result = agent.scan(
            args.target,
            ports=args.ports,
            dry_run=args.dry_run,
        )
    except OutOfScopeError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 3
    except ReconError as exc:
        print(f"recon error: {exc}", file=sys.stderr)
        return 1

    if args.json or args.dry_run:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_human(result)
    return 0


def _print_human(result: dict) -> None:
    if result.get("dry_run"):
        print("[dry-run] would run:", " ".join(result["command"]))
        return
    print(f"# recon of {result.get('target')} "
          f"(scope: {result.get('matched_scope')}) at {result.get('scanned_at')}")
    for host in result.get("hosts", []):
        print(f"\nhost {host['address']} ({host['state']})")
        for hn in host.get("hostnames", []):
            print(f"  hostname: {hn}")
        for p in host.get("ports", []):
            svc = p.get("service", "")
            prod = p.get("product", "")
            ver = p.get("version", "")
            detail = " ".join(x for x in (svc, prod, ver) if x)
            print(f"  {p['port']}/{p['protocol']:<3} {p['state']:<7} {detail}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vantage")
    parser.add_argument("--scope", default=None,
                        help="path to scope.yaml (default: repo root)")
    sub = parser.add_subparsers(dest="command", required=True)

    recon = sub.add_parser("recon", help="enumerate an authorized target")
    recon.add_argument("target", help="IP or hostname (must be in scope.yaml)")
    recon.add_argument("--ports", default=None, help="nmap port spec, e.g. 1-1000")
    recon.add_argument("--dry-run", action="store_true",
                       help="show the command without running nmap")
    recon.add_argument("--json", action="store_true", help="emit JSON")
    recon.set_defaults(func=_cmd_recon)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
