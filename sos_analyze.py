#!/usr/bin/env python3
# Launcher for package sos_triage

from __future__ import annotations

import sys
from pathlib import Path

from sos_triage.cli import main as sos_main


ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "tool-signatures" / "sos-signatures.yaml"


def main() -> int:
    argv = sys.argv[1:]

    # Default to analyze if no subcommand was supplied.
    if not argv or argv[0] not in {"analyze", "lint-config"}:
        argv = ["analyze", *argv]

    # For analyze, inject default config unless user supplied one.
    if argv[0] == "analyze" and "--config" not in argv:
        argv.extend(["--config", str(DEFAULT_CONFIG)])

    return sos_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
