#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from etcd_analysis.cli import main as etcd_main


ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "tool-signatures" / "etcd-signatures.yaml"


def main() -> int:
    argv = sys.argv[1:]

    # Default to analyze if no subcommand was supplied.
    if not argv or argv[0] not in {"analyze", "lint-config"}:
        argv = ["analyze", *argv]

    # Inject default config unless user supplied one.
    if "--config" not in argv:
        argv.extend(["--config", str(DEFAULT_CONFIG)])

    return etcd_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
