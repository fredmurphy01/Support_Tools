from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict

import yaml

from .config import EtcdSignatureConfigError, load_etcd_signature_config


def _count_events(raw: Dict[str, Any], section: str) -> int:
    sec = raw.get(section)
    if not isinstance(sec, dict):
        return 0
    events = sec.get('events')
    if not isinstance(events, list):
        return 0
    return len(events)


def _count_storm_rules(raw: Dict[str, Any]) -> int:
    sec = raw.get('storm_rules')
    if not isinstance(sec, dict):
        return 0
    rules = sec.get('rules')
    if not isinstance(rules, list):
        return 0
    return len(rules)


def _count_family_mappings(raw: Dict[str, Any]) -> int:
    sec = raw.get('families')
    if not isinstance(sec, dict):
        return 0
    mapping = sec.get('event_type_to_family')
    if not isinstance(mapping, dict):
        return 0
    return len(mapping)


def _count_duration_policies(raw: Dict[str, Any]) -> int:
    sec = raw.get('duration_policies')
    if not isinstance(sec, dict):
        return 0
    policies = sec.get('policies')
    if not isinstance(policies, dict):
        return 0
    return len(policies)


def lint_config(config_path: Path) -> int:
    try:
        cfg = load_etcd_signature_config(config_path)
    except EtcdSignatureConfigError as e:
        print(f'FAIL: {e}', file=sys.stderr)
        return 2

    try:
        raw = yaml.safe_load(config_path.read_text(encoding='utf-8'))
    except Exception as e:
        print(f'FAIL: could not re-read config for summary: {e}', file=sys.stderr)
        return 2
    if not isinstance(raw, dict):
        print('FAIL: config root must be a mapping', file=sys.stderr)
        return 2

    print(f'PASS: {config_path}')
    print(f'  primary signatures: {_count_events(raw, "signatures")}')
    print(f'  journal signatures: {_count_events(raw, "journal_signatures")}')
    print(f'  storm rules: {_count_storm_rules(raw)}')
    print(f'  family mappings: {_count_family_mappings(raw)}')
    print(f'  duration policies: {_count_duration_policies(raw)}')
    print(f'  compiled primary patterns: {len(cfg.event_patterns)}')
    print(f'  compiled journal patterns: {len(cfg.journal_signal_patterns)}')
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='etcd_signature_lint',
        description='Validate etcd-signatures.yaml for loader/runtime safety.',
    )
    p.add_argument(
        '--config',
        default='./configs/etcd-signatures.yaml',
        help='Path to etcd signature config (default: ./configs/etcd-signatures.yaml)',
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return lint_config(Path(args.config))


if __name__ == '__main__':
    raise SystemExit(main())
