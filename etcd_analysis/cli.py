from __future__ import annotations

import argparse
import sys

from . import analyzer, lint


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="etcd_analysis",
        description="etcd analysis package CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "analyze",
        help="Run etcd analysis",
    )
    subparsers.add_parser(
        "lint-config",
        help="Validate etcd signature config",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if argv:
        if argv[0] == "analyze" and any(arg in ("--help", "-h") for arg in argv[1:]):
            return analyzer.main(["--help"])
        if argv[0] == "lint-config" and any(arg in ("--help", "-h") for arg in argv[1:]):
            return lint.main(["--help"])

    parser = build_parser()
    ns, remainder = parser.parse_known_args(argv)

    if ns.command == "analyze":
        return analyzer.main(remainder)

    if ns.command == "lint-config":
        return lint.main(remainder)

    parser.error(f"unknown command: {ns.command}")
    return 2