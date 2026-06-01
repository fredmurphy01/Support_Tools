from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Pattern, Sequence, Tuple

import yaml


class EtcdSignatureConfigError(RuntimeError):
    """Raised when etcd signature configuration cannot be loaded safely."""


@dataclass(frozen=True)
class DurationThresholds:
    low_ms: float
    medium_ms: float
    high_ms: float
    critical_ms: float


@dataclass(frozen=True)
class RatioBoostThresholds:
    medium_gte: float
    high_gte: float
    critical_gte: float


@dataclass(frozen=True)
class KeyspaceOverridePolicy:
    key_prefix: str
    thresholds: DurationThresholds


@dataclass(frozen=True)
class LoadedEtcdSignatureConfig:
    config_path: Path
    event_patterns: List[Tuple[str, Pattern[str]]]
    base_severity: Dict[str, str]
    journal_signal_patterns: List[Tuple[str, Pattern[str], str]]
    storm_rules: Dict[str, Tuple[int, int, str, str]]
    family_by_event_type: Dict[str, str]
    journal_family_by_event_type: Dict[str, str]
    duration_thresholds_by_policy: Dict[str, DurationThresholds]
    duration_policy_by_event_type: Dict[str, str]
    ratio_boost: RatioBoostThresholds
    keyspace_overrides: List[KeyspaceOverridePolicy]


_REQUIRED_TOP_LEVEL_DEFAULT = [
    'validation',
    'defaults',
    'sources',
    'outputs',
    'duration_policies',
    'signatures',
    'journal_signatures',
    'storm_rules',
    'families',
    'heuristics',
    'narrative',
    'reserved',
]


def default_config_path() -> Path:
    return Path('./configs/etcd-signatures.yaml')


def _read_yaml(config_path: Path) -> Dict[str, Any]:
    try:
        raw = yaml.safe_load(config_path.read_text(encoding='utf-8'))
    except FileNotFoundError as e:
        raise EtcdSignatureConfigError(f'etcd signature config not found: {config_path}') from e
    except Exception as e:
        raise EtcdSignatureConfigError(f'failed to load etcd signature config {config_path}: {e}') from e
    if not isinstance(raw, dict):
        raise EtcdSignatureConfigError('etcd signature config root must be a mapping')
    return raw


def _required_top_level_sections(raw: Dict[str, Any]) -> Sequence[str]:
    validation = raw.get('validation')
    if isinstance(validation, dict):
        required = validation.get('required_top_level_sections')
        if isinstance(required, list) and all(isinstance(x, str) and x.strip() for x in required):
            return required
    return _REQUIRED_TOP_LEVEL_DEFAULT


def _severity_enum(raw: Dict[str, Any]) -> Sequence[str]:
    validation = raw.get('validation')
    if isinstance(validation, dict):
        enum = validation.get('severity_enum')
        if isinstance(enum, list) and all(isinstance(x, str) and x.strip() for x in enum):
            return [str(x).strip().lower() for x in enum]
    return ['critical', 'high', 'medium', 'low', 'info']


def _source_role_enum(raw: Dict[str, Any]) -> Sequence[str]:
    validation = raw.get('validation')
    if isinstance(validation, dict):
        enum = validation.get('source_role_enum')
        if isinstance(enum, list) and all(isinstance(x, str) and x.strip() for x in enum):
            return [str(x).strip() for x in enum]
    return []


def _compile_event_section(
    *,
    raw: Dict[str, Any],
    section_name: str,
    allowed_severities: set[str],
    allowed_source_roles: set[str],
    duration_policy_ids: set[str],
    validate_duration_policy: bool,
) -> Tuple[List[Tuple[str, Pattern[str]]], Dict[str, str], List[Tuple[str, Pattern[str], str]]]:
    section = raw.get(section_name)
    if not isinstance(section, dict):
        raise EtcdSignatureConfigError(f"config field '{section_name}' must be a mapping")
    events = section.get('events')
    if not isinstance(events, list) or not events:
        raise EtcdSignatureConfigError(f"config field '{section_name}.events' must be a non-empty list")

    seen_ids = set()
    seen_event_types = set()
    compiled_patterns: List[Tuple[str, Pattern[str]]] = []
    base_severity: Dict[str, str] = {}
    journal_patterns: List[Tuple[str, Pattern[str], str]] = []

    for idx, event in enumerate(events):
        path = f'{section_name}.events[{idx}]'
        if not isinstance(event, dict):
            raise EtcdSignatureConfigError(f'{path} must be a mapping')

        sig_id = event.get('id')
        event_type = event.get('event_type')
        default_severity = event.get('default_severity')
        patterns = event.get('patterns')
        source_roles = event.get('source_roles') or []
        duration_policy = event.get('duration_policy')

        if not isinstance(sig_id, str) or not sig_id.strip():
            raise EtcdSignatureConfigError(f'{path}.id must be a non-empty string')
        if sig_id in seen_ids:
            raise EtcdSignatureConfigError(f'duplicate signature id: {sig_id}')
        seen_ids.add(sig_id)

        if not isinstance(event_type, str) or not event_type.strip():
            raise EtcdSignatureConfigError(f'{path}.event_type must be a non-empty string')
        if event_type in seen_event_types:
            raise EtcdSignatureConfigError(f'duplicate signature event_type: {event_type}')
        seen_event_types.add(event_type)

        if not isinstance(default_severity, str) or default_severity.strip().lower() not in allowed_severities:
            raise EtcdSignatureConfigError(
                f"{path}.default_severity must be one of {sorted(allowed_severities)}"
            )

        if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) and p for p in patterns):
            raise EtcdSignatureConfigError(f'{path}.patterns must be a non-empty list of strings')

        if not isinstance(source_roles, list):
            raise EtcdSignatureConfigError(f'{path}.source_roles must be a list')
        if allowed_source_roles:
            bad_roles = [role for role in source_roles if not isinstance(role, str) or role not in allowed_source_roles]
            if bad_roles:
                raise EtcdSignatureConfigError(
                    f"{path}.source_roles contains unknown values: {bad_roles}; allowed={sorted(allowed_source_roles)}"
                )

        if validate_duration_policy and duration_policy is not None:
            if not isinstance(duration_policy, str) or not duration_policy.strip():
                raise EtcdSignatureConfigError(f'{path}.duration_policy must be a non-empty string when provided')
            if duration_policy not in duration_policy_ids:
                raise EtcdSignatureConfigError(
                    f'{path}.duration_policy references unknown policy: {duration_policy}'
                )

        sev_upper = default_severity.strip().upper()
        base_severity[event_type] = sev_upper

        for pat_idx, pattern_text in enumerate(patterns):
            try:
                compiled = re.compile(pattern_text, re.IGNORECASE)
            except re.error as e:
                raise EtcdSignatureConfigError(
                    f'{path}.patterns[{pat_idx}] failed regex compilation: {e}'
                ) from e
            compiled_patterns.append((event_type, compiled))
            journal_patterns.append((event_type, compiled, sev_upper))

    return compiled_patterns, base_severity, journal_patterns



def _validate_thresholds(path: str, thresholds: Any) -> DurationThresholds:
    if not isinstance(thresholds, dict):
        raise EtcdSignatureConfigError(f'{path} must be a mapping')
    required = ('low', 'medium', 'high', 'critical')
    values: Dict[str, float] = {}
    for key in required:
        value = thresholds.get(key)
        if not isinstance(value, (int, float)):
            raise EtcdSignatureConfigError(f'{path}.{key} must be numeric')
        values[key] = float(value)
    if not (values['low'] <= values['medium'] <= values['high'] <= values['critical']):
        raise EtcdSignatureConfigError(f'{path} thresholds must be monotonic low<=medium<=high<=critical')
    return DurationThresholds(
        low_ms=values['low'],
        medium_ms=values['medium'],
        high_ms=values['high'],
        critical_ms=values['critical'],
    )


def _load_duration_policies(raw: Dict[str, Any]) -> Tuple[Dict[str, DurationThresholds], RatioBoostThresholds, List[KeyspaceOverridePolicy]]:
    duration_policies = raw.get('duration_policies')
    if not isinstance(duration_policies, dict):
        raise EtcdSignatureConfigError("config field 'duration_policies' must be a mapping")

    ratio_boost = duration_policies.get('ratio_boost')
    if not isinstance(ratio_boost, dict):
        raise EtcdSignatureConfigError("config field 'duration_policies.ratio_boost' must be a mapping")
    medium_gte = ratio_boost.get('medium_gte')
    high_gte = ratio_boost.get('high_gte')
    critical_gte = ratio_boost.get('critical_gte')
    if not all(isinstance(v, (int, float)) for v in (medium_gte, high_gte, critical_gte)):
        raise EtcdSignatureConfigError("config field 'duration_policies.ratio_boost' values must be numeric")
    ratio = RatioBoostThresholds(float(medium_gte), float(high_gte), float(critical_gte))
    if not (ratio.medium_gte <= ratio.high_gte <= ratio.critical_gte):
        raise EtcdSignatureConfigError("config field 'duration_policies.ratio_boost' must be monotonic medium<=high<=critical")

    raw_overrides = duration_policies.get('keyspace_overrides') or []
    if not isinstance(raw_overrides, list):
        raise EtcdSignatureConfigError("config field 'duration_policies.keyspace_overrides' must be a list")
    keyspace_overrides: List[KeyspaceOverridePolicy] = []
    for idx, item in enumerate(raw_overrides):
        path = f'duration_policies.keyspace_overrides[{idx}]'
        if not isinstance(item, dict):
            raise EtcdSignatureConfigError(f'{path} must be a mapping')
        key_prefix = item.get('key_prefix')
        if not isinstance(key_prefix, str) or not key_prefix.strip():
            raise EtcdSignatureConfigError(f'{path}.key_prefix must be a non-empty string')
        thresholds = _validate_thresholds(f'{path}.thresholds_ms', item.get('thresholds_ms'))
        keyspace_overrides.append(KeyspaceOverridePolicy(key_prefix=key_prefix.strip(), thresholds=thresholds))

    raw_policies = duration_policies.get('policies')
    if not isinstance(raw_policies, dict) or not raw_policies:
        raise EtcdSignatureConfigError("config field 'duration_policies.policies' must be a non-empty mapping")
    loaded: Dict[str, DurationThresholds] = {}
    for policy_id, policy in raw_policies.items():
        path = f'duration_policies.policies[{policy_id!r}]'
        if not isinstance(policy_id, str) or not policy_id.strip():
            raise EtcdSignatureConfigError('duration_policies.policies keys must be non-empty strings')
        if not isinstance(policy, dict):
            raise EtcdSignatureConfigError(f'{path} must be a mapping')
        loaded[policy_id.strip()] = _validate_thresholds(f'{path}.thresholds_ms', policy.get('thresholds_ms'))

    return loaded, ratio, keyspace_overrides



def _load_storm_rules(
    *,
    raw: Dict[str, Any],
    allowed_severities: set[str],
    known_event_types: set[str],
) -> Dict[str, Tuple[int, int, str, str]]:
    storm_rules = raw.get('storm_rules')
    if not isinstance(storm_rules, dict):
        raise EtcdSignatureConfigError("config field 'storm_rules' must be a mapping")
    rules = storm_rules.get('rules')
    if not isinstance(rules, list) or not rules:
        raise EtcdSignatureConfigError("config field 'storm_rules.rules' must be a non-empty list")

    seen_ids = set()
    seen_event_types = set()
    loaded: Dict[str, Tuple[int, int, str, str]] = {}

    for idx, rule in enumerate(rules):
        path = f'storm_rules.rules[{idx}]'
        if not isinstance(rule, dict):
            raise EtcdSignatureConfigError(f'{path} must be a mapping')

        rule_id = rule.get('id')
        event_type = rule.get('event_type')
        window_seconds = rule.get('window_seconds')
        count_gte = rule.get('count_gte')
        synthetic_event_type = rule.get('synthetic_event_type')
        severity = rule.get('severity')

        if not isinstance(rule_id, str) or not rule_id.strip():
            raise EtcdSignatureConfigError(f'{path}.id must be a non-empty string')
        if rule_id in seen_ids:
            raise EtcdSignatureConfigError(f'duplicate storm rule id: {rule_id}')
        seen_ids.add(rule_id)

        if not isinstance(event_type, str) or not event_type.strip():
            raise EtcdSignatureConfigError(f'{path}.event_type must be a non-empty string')
        if event_type not in known_event_types:
            raise EtcdSignatureConfigError(f'{path}.event_type references unknown signature event_type: {event_type}')
        if event_type in seen_event_types:
            raise EtcdSignatureConfigError(f'duplicate storm rule event_type: {event_type}')
        seen_event_types.add(event_type)

        if not isinstance(window_seconds, int) or window_seconds <= 0:
            raise EtcdSignatureConfigError(f'{path}.window_seconds must be a positive integer')
        if not isinstance(count_gte, int) or count_gte <= 0:
            raise EtcdSignatureConfigError(f'{path}.count_gte must be a positive integer')
        if not isinstance(synthetic_event_type, str) or not synthetic_event_type.strip():
            raise EtcdSignatureConfigError(f'{path}.synthetic_event_type must be a non-empty string')
        if not isinstance(severity, str) or severity.strip().lower() not in allowed_severities:
            raise EtcdSignatureConfigError(f"{path}.severity must be one of {sorted(allowed_severities)}")

        loaded[event_type] = (window_seconds, count_gte, severity.strip().upper(), synthetic_event_type.strip())

    return loaded



def _load_families(
    *,
    raw: Dict[str, Any],
    known_event_types: set[str],
    known_journal_event_types: set[str],
) -> Tuple[Dict[str, str], Dict[str, str]]:
    families = raw.get('families')
    if not isinstance(families, dict):
        raise EtcdSignatureConfigError("config field 'families' must be a mapping")
    mapping = families.get('event_type_to_family')
    if not isinstance(mapping, dict) or not mapping:
        raise EtcdSignatureConfigError("config field 'families.event_type_to_family' must be a non-empty mapping")

    loaded_primary: Dict[str, str] = {}
    loaded_journal: Dict[str, str] = {}
    allowed_family_names = {'read_path', 'apply_path', 'storage_timing', 'client_network', 'raft_election'}

    for event_type, family_name in mapping.items():
        if not isinstance(event_type, str) or not event_type.strip():
            raise EtcdSignatureConfigError('families.event_type_to_family keys must be non-empty strings')
        if not isinstance(family_name, str) or not family_name.strip():
            raise EtcdSignatureConfigError(f'families.event_type_to_family[{event_type!r}] must be a non-empty string')
        family_name = family_name.strip()
        if family_name not in allowed_family_names:
            raise EtcdSignatureConfigError(
                f"families.event_type_to_family[{event_type!r}] references unknown family: {family_name}"
            )

        if event_type in known_event_types:
            loaded_primary[event_type] = family_name
        elif event_type in known_journal_event_types:
            loaded_journal[event_type] = family_name
        else:
            raise EtcdSignatureConfigError(
                f"families.event_type_to_family[{event_type!r}] references unknown event_type"
            )

    return loaded_primary, loaded_journal

def load_etcd_signature_config(config_path: Path) -> LoadedEtcdSignatureConfig:
    config_path = Path(config_path)
    raw = _read_yaml(config_path)

    missing = [key for key in _required_top_level_sections(raw) if key not in raw]
    if missing:
        raise EtcdSignatureConfigError(
            'etcd signature config missing required top-level section(s): ' + ', '.join(missing)
        )

    allowed_severities = set(_severity_enum(raw))
    allowed_source_roles = set(_source_role_enum(raw))

    duration_thresholds_by_policy, ratio_boost, keyspace_overrides = _load_duration_policies(raw)
    duration_policy_ids = set(duration_thresholds_by_policy.keys())

    event_patterns, base_severity, _ = _compile_event_section(
        raw=raw,
        section_name='signatures',
        allowed_severities=allowed_severities,
        allowed_source_roles=allowed_source_roles,
        duration_policy_ids=duration_policy_ids,
        validate_duration_policy=True,
    )
    _, _, journal_signal_patterns = _compile_event_section(
        raw=raw,
        section_name='journal_signatures',
        allowed_severities=allowed_severities,
        allowed_source_roles=allowed_source_roles,
        duration_policy_ids=duration_policy_ids,
        validate_duration_policy=False,
    )
    known_event_types = set(base_severity.keys())
    known_journal_event_types = {kind for kind, _, _ in journal_signal_patterns}
    duration_policy_by_event_type: Dict[str, str] = {}
    signatures = raw.get('signatures') or {}
    for event in signatures.get('events', []):
        if isinstance(event, dict):
            event_type = event.get('event_type')
            duration_policy = event.get('duration_policy')
            if isinstance(event_type, str) and isinstance(duration_policy, str) and duration_policy.strip():
                duration_policy_by_event_type[event_type] = duration_policy.strip()
    storm_rules = _load_storm_rules(
        raw=raw,
        allowed_severities=allowed_severities,
        known_event_types=known_event_types,
    )
    family_by_event_type, journal_family_by_event_type = _load_families(
        raw=raw,
        known_event_types=known_event_types,
        known_journal_event_types=known_journal_event_types,
    )

    return LoadedEtcdSignatureConfig(
        config_path=config_path,
        event_patterns=event_patterns,
        base_severity=base_severity,
        journal_signal_patterns=journal_signal_patterns,
        storm_rules=storm_rules,
        family_by_event_type=family_by_event_type,
        journal_family_by_event_type=journal_family_by_event_type,
        duration_thresholds_by_policy=duration_thresholds_by_policy,
        duration_policy_by_event_type=duration_policy_by_event_type,
        ratio_boost=ratio_boost,
        keyspace_overrides=keyspace_overrides,
    )
