#!/usr/bin/env python3
"""etcd_analysis.py  version 23

Parse etcd logs and related signals (JSON-per-line and/or plain text), classify lines into event types,
extract timestamps + durations, assign duration-aware + storm-aware severity, and
print incident summaries (with a short narrative) to stdout.

Outputs:
  - <log>.events.csv
Design goals:
  1) Assign severity automatically based on measured durations where possible.

  2) Detect bursts/storms (many events of same kind in a small window) and surface
     them as explicit "storm" events.
  3) Collapse correlated events into a concise incident narrative per window.

  4) This groups into an >>Incident<< a contiguous period of abnormal etcd behaviour -
     A time window where the system is >>meaningfully degraded<< not just noisy.

  5) An Incident Window is a group of detected etcd events that occur close enough in
     time to be considered part of the same underlying degradation episode.
     Meaning, it is essentially a gap-based clustering of events.
     If the time gap between consecutive events exceeds a threshold then start a new incident otherwise its the same incident.
     So, essentially, an incident is fundamentally a time-bounded degradation episode.
     Each Incident answers:
        "Something was wrong during this period"
        "Multiple symptoms appeared together"
        "This was not just one-off noise"
    That's why an Incident Window includes:
        time range
        severity rollup
        event counts
        storm detection
        a narrative summary

    What an Incident is not
    ❌ Not a root cause
    ❌ Not a single failure
    ❌ Not guaranteed to be unique (you can have many incidents with similar patterns)
    An Incident is observational, not explanatory.

"""

from __future__ import annotations

import csv
import argparse
import json
import re
import sys
import io
import math
import signal
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone, time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set

from .config import (
    EtcdSignatureConfigError,
    default_config_path as default_signature_config_path,
    load_etcd_signature_config,
)


@dataclass
class SlowEndpointStats:
    endpoint: str
    seen_count: int
    slow_count: int
    min_hits: int  # ceil(seen_count/3)
    max_ms: float
    min_ms: float
    slow_seen_on_hosts: List[str]
    seen_on_hosts: List[str]

@dataclass
class ClusterTopologyRisk:
    observed_snapshot_hosts: int
    observed_endpoints: int
    quorum_candidate_count: int
    is_single_member: bool
    note: Optional[str] = None

@dataclass
class IncidentFamilySummary:
    read_path: bool
    apply_path: bool
    disk_timing: bool
    client_network: bool
    raft_election: bool
    counts: Optional[Dict[str, int]] = None

@dataclass
class ClusterSynthesis:
    # Coverage
    nodes_analyzed: int
    snapshot_hosts: int
    health_present_hosts: int
    health_missing_hosts: int

    # Leader / term
    leader_endpoint: Optional[str]
    leaders_observed: Set[str]
    leader_stable: bool

    raft_term_min: Optional[int]
    raft_term_max: Optional[int]
    term_stable: bool

    # Membership
    members_min: Optional[int]
    members_max: Optional[int]
    learners_max: Optional[int]

    # Drift
    max_raft_index_drift: Optional[int]
    max_raft_applied_drift: Optional[int]
    drift_warn_threshold: int
    drift_concerning: bool

    # Health
    fastest_observed_ms: Optional[float]
    slowest_observed_ms: Optional[float]
    max_skew_ms: Optional[float]
    max_ratio_vs_fastest: Optional[float]
    slow_threshold_ms: float

    # Slow endpoints
    slow_endpoints: List[SlowEndpointStats]
    intermittent_slow_endpoints: List[str]
    sustained_slow_endpoints: List[str]
    slow_significant_endpoints: List[str]

    # Topology risk
    topology: ClusterTopologyRisk

    # Incident families
    incident_families: IncidentFamilySummary

    # Convenience for interactive ordering
    leader_host: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        return {
            "nodes_analyzed": self.nodes_analyzed,
            "snapshot_hosts": self.snapshot_hosts,
            "health_present_hosts": self.health_present_hosts,
            "health_missing_hosts": self.health_missing_hosts,
            "leader": {
                "endpoint": self.leader_endpoint,
                "leaders_observed": sorted(list(self.leaders_observed)),
                "stable": self.leader_stable,
            },
            "raft_term": {
                "min": self.raft_term_min,
                "max": self.raft_term_max,
                "stable": self.term_stable,
            },
            "members": {
                "min": self.members_min,
                "max": self.members_max,
                "learners_max": self.learners_max,
            },
            "drift": {
                "max_raft_index_drift": self.max_raft_index_drift,
                "max_raft_applied_drift": self.max_raft_applied_drift,
                "warn_threshold": self.drift_warn_threshold,
                "concerning": self.drift_concerning,
            },
            "health": {
                "fastest_ms": self.fastest_observed_ms,
                "slowest_ms": self.slowest_observed_ms,
                "max_skew_ms": self.max_skew_ms,
                "max_ratio_vs_fastest": self.max_ratio_vs_fastest,
                "slow_threshold_ms": self.slow_threshold_ms,
            },
            "slow_endpoints": [
                {
                    "endpoint": s.endpoint,
                    "seen_count": s.seen_count,
                    "slow_count": s.slow_count,
                    "min_hits": s.min_hits,
                    "max_ms": s.max_ms,
                    "min_ms": s.min_ms,
                    "slow_seen_on_hosts": s.slow_seen_on_hosts,
                    "seen_on_hosts": s.seen_on_hosts,
                }
                for s in self.slow_endpoints
            ],
            "slow_endpoint_sets": {
                "significant": self.slow_significant_endpoints,
                "intermittent": self.intermittent_slow_endpoints,
                "sustained": self.sustained_slow_endpoints,
            },
            "topology": {
                "observed_snapshot_hosts": self.topology.observed_snapshot_hosts,
                "observed_endpoints": self.topology.observed_endpoints,
                "quorum_candidate_count": self.topology.quorum_candidate_count,
                "is_single_member": self.topology.is_single_member,
                "note": self.topology.note,
            },
            "incident_families": {
                "read_path": self.incident_families.read_path,
                "apply_path": self.incident_families.apply_path,
                "disk_timing": self.incident_families.disk_timing,
                "client_network": self.incident_families.client_network,
                "raft_election": self.incident_families.raft_election,
                "counts": self.incident_families.counts,
            },
            "leader_host": self.leader_host,
        }


# ----------------------------
# Event patterns
# ----------------------------
# NOTE: These are intentionally "broad" and keyed on high-signal phrases.
#       Tune as you see fit for your environment.
LEGACY_EVENT_PATTERNS = [
    # etcd WAL durability stalls
    ("slow_fdatasync", re.compile(r'"msg"\s*:\s*"slow fdatasync"|slow fdatasync', re.IGNORECASE)),

    # linearizable read path backing up
    ("readindex_retry", re.compile(r"waiting for ReadIndex response took too long", re.IGNORECASE)),
    ("linearizable_read_slow", re.compile(r'"msg"\s*:\s*"trace\[.*\]\s+linearizableReadLoop"|\blinearizableReadLoop\b', re.IGNORECASE)),
    ("raft_read_agreement_slow", re.compile(r"agreement among raft nodes before linearized reading", re.IGNORECASE)),

    # raft timing slipping (often points to slow disk)
    ("raft_heartbeat_miss", re.compile(r"leader failed to send out heartbeat on time", re.IGNORECASE)),

    # request apply latency SLO violation
    ("apply_took_too_long", re.compile(r"apply request took too long", re.IGNORECASE)),

    # trace step detail that often reveals the bottleneck
    ("raft_process_slow", re.compile(r"'process raft request'\s*\(duration:", re.IGNORECASE)),
    ("raft_compare_slow", re.compile(r"'compare'\s*\(duration:", re.IGNORECASE)),
    ("inmemory_index_scan_slow", re.compile(r"range keys from in-memory index tree", re.IGNORECASE)),

    # applied index lagging read state
    ("applied_index_lag", re.compile(r"appliedIndex\s+is\s+now\s+lower\s+than\s+readState\.Index", re.IGNORECASE)),

    # client timeouts / cancellations
    ("context_deadline", re.compile(r"context deadline exceeded", re.IGNORECASE)),
    ("context_canceled", re.compile(r"context canceled", re.IGNORECASE)),

    # grpc churn symptoms
    ("grpc_transport_closing", re.compile(r"transport is closing", re.IGNORECASE)),

    # peer connectivity failures
    ("peer_probe_unhealthy", re.compile(r"prober detected unhealthy status", re.IGNORECASE)),
    ("peer_connect_refused", re.compile(r"connect:\s*connection refused", re.IGNORECASE)),

    # hard health degradation / no leader
    ("health_no_leader", re.compile(r"serving\s+/health\s+false;\s+no leader|RAFT NO LEADER|/health error", re.IGNORECASE)),

    # /registry/health key-range reads (kube control-plane impact)
    ("health_registry_read", re.compile(r'key:"/registry/health"', re.IGNORECASE)),

    # leader churn / election activity
    ("raft_election", re.compile(r"starting a new election|became pre-candidate|elected leader|became follower|higher term", re.IGNORECASE)),

    # client-side connection rejects/resets at etcd endpoint
    ("client_conn_rejected", re.compile(r"rejected connection on client endpoint", re.IGNORECASE)),
    ("client_conn_reset", re.compile(r"connection reset by peer|\bEOF\b", re.IGNORECASE)),

    # slow RPC accounting (often catches slow reads/writes more broadly)
    ("rpc_request_stats", re.compile(r'"msg"\s*:\s*"request stats"|\brequest stats\b', re.IGNORECASE)),
]


# ----------------------------
# Severity levels and ordering
# ----------------------------
SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ORDER_SEV = {v: k for k, v in SEV_ORDER.items()}

# Emojis for console output (visual severity cues)
SEV_ICON = {"CRITICAL": "❌", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

# Declarative severity levels (lower is more severe)
SEV_LEVEL = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}


def sev_with_icon(sev: str) -> str:
    icon = SEV_ICON.get(sev, "")
    return f"{icon} {sev}".strip()


def sev_bracket(sev: str) -> str:
    icon = SEV_ICON.get(sev, "")
    return f"[{icon} {sev}]" if icon else f"[{sev}]"


# Baseline severity for categorical (non-duration) events.
LEGACY_BASE_SEVERITY: Dict[str, str] = {
    # CRITICAL (correctness/availability broken)
    "health_no_leader": "CRITICAL",
    "raft_election": "CRITICAL",
    "peer_connect_refused": "CRITICAL",
    "peer_probe_unhealthy": "CRITICAL",

    # HIGH (near-failure / strong outage precursor)
    "slow_fdatasync": "HIGH",
    "raft_heartbeat_miss": "HIGH",
    "grpc_transport_closing": "HIGH",
    "client_conn_rejected": "HIGH",
    "applied_index_lag": "HIGH",

    # MEDIUM (degraded service)
    "apply_took_too_long": "MEDIUM",
    "readindex_retry": "MEDIUM",
    "linearizable_read_slow": "MEDIUM",
    "raft_read_agreement_slow": "MEDIUM",
    "rpc_request_stats": "MEDIUM",
    "context_deadline": "MEDIUM",
    "context_canceled": "MEDIUM",

    # LOW (supporting/noisy)
    "client_conn_reset": "LOW",
    "health_registry_read": "LOW",
    "raft_process_slow": "LOW",
    "raft_compare_slow": "LOW",
    "inmemory_index_scan_slow": "LOW",
}


EVENT_PATTERNS = list(LEGACY_EVENT_PATTERNS)
BASE_SEVERITY: Dict[str, str] = dict(LEGACY_BASE_SEVERITY)
ACTIVE_SIGNATURE_CONFIG_PATH: Optional[Path] = None
STORM_RULES: Dict[str, Tuple[int, int, str, str]] = {
    "readindex_retry": (30, 5, "HIGH", "storm_readindex_retry"),
    "apply_took_too_long": (60, 20, "HIGH", "storm_apply_took_too_long"),
    "linearizable_read_slow": (60, 20, "HIGH", "storm_linearizable_read_slow"),
    "raft_heartbeat_miss": (30, 3, "CRITICAL", "storm_raft_heartbeat_miss"),
    "slow_fdatasync": (60, 3, "CRITICAL", "storm_slow_fdatasync"),
    "context_deadline": (60, 10, "HIGH", "storm_context_deadline"),
    "applied_index_lag": (60, 5, "CRITICAL", "storm_applied_index_lag"),
}
FAMILY_BY_EVENT_TYPE: Dict[str, str] = {}
JOURNAL_FAMILY_BY_EVENT_TYPE: Dict[str, str] = {}
DURATION_THRESHOLDS_BY_POLICY: Dict[str, Tuple[float, float, float, float]] = {}
DURATION_POLICY_BY_EVENT_TYPE: Dict[str, str] = {}
RATIO_BOOST_THRESHOLDS: Tuple[float, float, float] = (3.0, 10.0, 50.0)
KEYSPACE_OVERRIDE_THRESHOLDS: List[Tuple[str, Tuple[float, float, float, float]]] = []


def configure_signature_runtime(config_path: Path) -> None:
    global EVENT_PATTERNS, BASE_SEVERITY, _JOURNAL_SIGNAL_PATTERNS, ACTIVE_SIGNATURE_CONFIG_PATH, STORM_RULES, FAMILY_BY_EVENT_TYPE, JOURNAL_FAMILY_BY_EVENT_TYPE, DURATION_THRESHOLDS_BY_POLICY, DURATION_POLICY_BY_EVENT_TYPE, RATIO_BOOST_THRESHOLDS, KEYSPACE_OVERRIDE_THRESHOLDS
    loaded = load_etcd_signature_config(config_path)
    EVENT_PATTERNS = list(loaded.event_patterns)
    BASE_SEVERITY = dict(loaded.base_severity)
    _JOURNAL_SIGNAL_PATTERNS = list(loaded.journal_signal_patterns)
    STORM_RULES = dict(loaded.storm_rules)
    FAMILY_BY_EVENT_TYPE = dict(loaded.family_by_event_type)
    JOURNAL_FAMILY_BY_EVENT_TYPE = dict(loaded.journal_family_by_event_type)
    DURATION_THRESHOLDS_BY_POLICY = {
        policy_id: (thresholds.low_ms, thresholds.medium_ms, thresholds.high_ms, thresholds.critical_ms)
        for policy_id, thresholds in loaded.duration_thresholds_by_policy.items()
    }
    DURATION_POLICY_BY_EVENT_TYPE = dict(loaded.duration_policy_by_event_type)
    RATIO_BOOST_THRESHOLDS = (
        loaded.ratio_boost.medium_gte,
        loaded.ratio_boost.high_gte,
        loaded.ratio_boost.critical_gte,
    )
    KEYSPACE_OVERRIDE_THRESHOLDS = [
        (override.key_prefix, (override.thresholds.low_ms, override.thresholds.medium_ms, override.thresholds.high_ms, override.thresholds.critical_ms))
        for override in loaded.keyspace_overrides
    ]
    ACTIVE_SIGNATURE_CONFIG_PATH = loaded.config_path


# ----------------------------
# Timestamp + duration extraction
# ----------------------------
RFC3339_Z_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")
PLAIN_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?")

# JSON-style duration fields
DURATION_TOKENS = {
    "took": re.compile(r'(?:^|[,{\s"])took"\s*:\s*"([^\"]+)"', re.IGNORECASE),
    "duration": re.compile(r'(?:^|[,{\s"])duration"\s*:\s*"([^\"]+)"', re.IGNORECASE),
    "time_spent": re.compile(r'(?:^|[,{\s"])time spent"\s*:\s*"([^\"]+)"', re.IGNORECASE),
    "exceeded": re.compile(r'(?:^|[,{\s"])exceeded-duration"\s*:\s*"([^\"]+)"', re.IGNORECASE),
    "expected": re.compile(r'(?:^|[,{\s"])expected-duration"\s*:\s*"([^\"]+)"', re.IGNORECASE),
    "retry_timeout": re.compile(r'(?:^|[,{\s"])retry-timeout"\s*:\s*"([^\"]+)"', re.IGNORECASE),
}

KEY_RE = re.compile(r'key:"([^\"]+)"')



def parse_yyyy_mm_dd(s: str) -> date:
    """Parse YYYY-MM-DD into a date."""
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError as e:
        raise ValueError(f"Invalid --date '{s}'. Expected format YYYY-MM-DD.") from e


def parse_level_list(s: str) -> List[int]:
    """Parse --level like '1,2,3' into a sorted list of unique ints in [1..4]."""
    if s is None:
        return [1, 2, 3, 4]
    parts = [p.strip() for p in str(s).split(",") if p.strip()]
    if not parts:
        return [1, 2, 3, 4]
    levels: set[int] = set()
    for p in parts:
        try:
            n = int(p)
        except ValueError as e:
            raise ValueError(f"Invalid --level entry '{p}'. Expected integers 1..4 (e.g. --level=1,2).") from e
        if n < 1 or n > 4:
            raise ValueError(f"Invalid --level '{n}'. Valid values are 1..4 (1=CRITICAL,2=HIGH,3=MEDIUM,4=LOW).")
        levels.add(n)
    return sorted(levels)


def filter_events_by_date_window(events: List["Event"], center: date, days: int) -> List["Event"]:
    """Filter events to a calendar-day window centered on `center` (inclusive)."""
    if days < 0:
        raise ValueError("--days must be >= 0")
    start = center - timedelta(days=days)
    end = center + timedelta(days=days)
    return [e for e in events if start <= e.ts.date() <= end]

def parse_rfc3339(ts_str: str) -> datetime:
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    return datetime.fromisoformat(ts_str)


def try_parse_json_payload(line: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Return (json_obj, line_without_prefix).

    Many etcd logs look like:
      2025-...Z {"level":"warn", ...}

    This function tries to parse the JSON object even if a timestamp prefix exists.
    """
    s = line.strip()

    # Fast path: starts with '{'
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            return (obj if isinstance(obj, dict) else None), s
        except Exception:
            return None, s

    # Common: prefix + JSON
    brace = s.find("{")
    if brace != -1:
        maybe = s[brace:]
        try:
            obj = json.loads(maybe)
            return (obj if isinstance(obj, dict) else None), maybe
        except Exception:
            return None, s

    return None, s


def extract_timestamp(line: str, j: Optional[Dict[str, Any]]) -> Optional[datetime]:
    if j and isinstance(j, dict) and "ts" in j:
        try:
            return parse_rfc3339(str(j["ts"]))
        except Exception:
            pass

    m = RFC3339_Z_RE.search(line)
    if m:
        try:
            return parse_rfc3339(m.group(0))
        except Exception:
            return None

    m = PLAIN_TS_RE.search(line)
    if m:
        try:
            return datetime.fromisoformat(m.group(0).replace(" ", "T")).replace(tzinfo=timezone.utc)
        except Exception:
            return None

    return None


def parse_duration_to_seconds(d: Optional[str]) -> Optional[float]:
    if not d:
        return None
    d = str(d).strip().lower()

    num_m = re.search(r"[0-9]+(?:\.[0-9]+)?", d)
    if not num_m:
        return None
    val = float(num_m.group(0))

    # etcd uses 'ms', 's', and 'µs' in traces
    if "ms" in d:
        return val / 1000.0
    if "µs" in d or "us" in d:
        return val / 1_000_000.0
    if "ns" in d:
        return val / 1_000_000_000.0
    if d.endswith("s") or "s" in d:
        return val
    return None




# -----------------------------
# etcd-status.txt integration
# -----------------------------

_HEALTH_LINE_RE = re.compile(
    r"^(?P<endpoint>\S+)\s+is\s+(?P<state>healthy|unhealthy)\b.*?took\s*=\s*(?P<val>[0-9]+(?:\.[0-9]+)?)\s*(?P<unit>ns|us|µs|ms|s|m)\b",
    re.IGNORECASE,
)


_TABLE_TOOK_RE = re.compile(
    r"^(?P<val>[0-9]+(?:\.[0-9]+)?)\s*(?P<unit>ns|us|µs|ms|s|m)\s*$",
    re.IGNORECASE,
)

_MEMBER_LINE_RE = re.compile(r"^\s*member\s+(?P<id>\S+)\s+(?P<rest>.*)$", re.IGNORECASE)

_MEMBER_KV_LINE_RE = re.compile(r"^\s*(?P<id>[^:\s]+)\s*:\s*(?P<rest>.*)$")



def _dur_val_unit_to_ms(val: str, unit: str) -> Optional[float]:
    try:
        v = float(val)
    except ValueError:
        return None
    u = unit.strip().lower()
    if u == "ms":
        return v
    if u == "s":
        return v * 1000.0
    if u in ("us", "µs"):
        return v / 1000.0
    if u == "ns":
        return v / 1_000_000.0
    if u == "m":
        return v * 60_000.0
    return None


def parse_etcd_status_text(raw_text: str) -> Dict[str, Any]:
    """Parse the contents of etcd-status.txt (best-effort, format-tolerant).

    Returns a dict:
      {
        "parsed": {...},
        "metrics": {...},
        "raw": "<verbatim text>"
      }
    """
    lines = raw_text.splitlines()

    # endpoint health (latency)
    # Support both narrative lines and the etcdctl endpoint health -w table format.
    health: List[Dict[str, Any]] = []

    # 1) Narrative lines (rare in your capture, but keep for tolerance)
    for ln in lines:
        m = _HEALTH_LINE_RE.search(ln.strip())
        if not m:
            continue
        ms = _dur_val_unit_to_ms(m.group("val"), m.group("unit"))
        health.append(
            {
                "endpoint": m.group("endpoint"),
                "state": m.group("state").lower(),
                "took_ms": ms,
                "raw": ln.strip(),
            }
        )

    # 2) Table: | ENDPOINT | HEALTH | TOOK | ERROR |
    health_headers: List[str] = []
    health_header_idx: Optional[int] = None
    for i, ln in enumerate(lines):
        if "|" in ln and "ENDPOINT" in ln and "TOOK" in ln and "HEALTH" in ln:
            health_header_idx = i
            health_headers = [h.strip().lower().replace(" ", "_") for h in ln.strip().strip("|").split("|")]
            break

    if health_header_idx is not None and health_headers:
        for ln in lines[health_header_idx + 1 :]:
            s = ln.strip()
            if not s:
                continue
            if s.startswith("+"):
                continue
            if not s.startswith("|"):
                if health:
                    break
                continue

            cols = [c.strip() for c in s.strip("|").split("|")]
            if len(cols) != len(health_headers):
                continue
            row = dict(zip(health_headers, cols))

            endpoint = (row.get("endpoint") or "").strip()
            if not endpoint:
                continue

            # health can be "true/false" in table output
            state = (row.get("health") or "").strip().lower()
            took = (row.get("took") or "").strip()
            err = (row.get("error") or "").strip() or None

            took_ms: Optional[float] = None
            if took:
                mm = _TABLE_TOOK_RE.match(took)
                if mm:
                    took_ms = _dur_val_unit_to_ms(mm.group("val"), mm.group("unit"))

            health.append(
                {
                    "endpoint": endpoint,
                    "state": state if state else None,
                    "took_ms": took_ms,
                    "error": err,
                    "raw": s,
                }
            )

    # endpoint status table (etcdctl endpoint status -w table)
    endpoint_status: List[Dict[str, Any]] = []
    headers: List[str] = []
    header_idx: Optional[int] = None
    for i, ln in enumerate(lines):
        # Header line tends to include these tokens, separated by |
        if "ENDPOINT" in ln and "IS LEADER" in ln and "RAFT" in ln and "|" in ln:
            header_idx = i
            headers = [h.strip().lower().replace(" ", "_") for h in ln.strip().strip("|").split("|")]
            break

    def _to_int(x: Any) -> Optional[int]:
        try:
            return int(str(x).strip())
        except Exception:
            return None

    if header_idx is not None and headers:
        for ln in lines[header_idx + 1 :]:
            s = ln.strip()
            if not s:
                continue
            if s.startswith("+"):
                continue
            if not s.startswith("|"):
                # stop once we move past the table
                if endpoint_status:
                    break
                continue

            cols = [c.strip() for c in s.strip("|").split("|")]
            if len(cols) != len(headers):
                continue
            row = dict(zip(headers, cols))

            endpoint = row.get("endpoint") or row.get("endpoints")
            if not endpoint:
                continue

            endpoint_status.append(
                {
                    "endpoint": endpoint,
                    "id": row.get("id"),
                    "version": row.get("version"),
                    "db_size": row.get("db_size"),
                    "is_leader": str(row.get("is_leader", "")).strip().lower() == "true",
                    "is_learner": str(row.get("is_learner", "")).strip().lower() == "true",
                    "raft_term": _to_int(row.get("raft_term")),
                    "raft_index": _to_int(row.get("raft_index")),
                    "raft_applied_index": _to_int(row.get("raft_applied_index") or row.get("raft_applied")),
                    "errors": (row.get("errors") or "").strip() or None,
                    "raw": s,
                }
            )

    leader_endpoint: Optional[str] = None
    for r in endpoint_status:
        if r.get("is_leader"):
            leader_endpoint = r.get("endpoint")
            break

    # member list (best-effort: parse id/name/urls if present)
    # Support both:
    #  - "member <id> <rest>"
    #  - "<id>: name=... peerURLs=... clientURLs=... isLeader=..."
    members: List[Dict[str, Any]] = []
    for ln in lines:
        m = _MEMBER_LINE_RE.match(ln)
        if not m:
            m = _MEMBER_KV_LINE_RE.match(ln)
        if not m:
            continue

        rest = m.group("rest")
        name_m = re.search(r"\bname\s*=\s*([^\s]+)", rest)
        peer_m = re.search(r"\bpeerURLs\s*=\s*([^\s]+)", rest)
        client_m = re.search(r"\bclientURLs\s*=\s*([^\s]+)", rest)
        leader_m = re.search(r"\bisLeader\s*=\s*(true|false)\b", rest, re.IGNORECASE)
        learner_m = re.search(r"\bisLearner\s*=\s*(true|false)\b", rest, re.IGNORECASE)

        members.append(
            {
                "id": m.group("id"),
                "name": name_m.group(1) if name_m else None,
                "peer_urls": peer_m.group(1).split(",") if peer_m else None,
                "client_urls": client_m.group(1).split(",") if client_m else None,
                "is_leader": (leader_m.group(1).lower() == "true") if leader_m else None,
                "is_learner": (learner_m.group(1).lower() == "true") if learner_m else None,
                "raw": ln.strip(),
            }
        )


    parsed: Dict[str, Any] = {
        "leader_endpoint": leader_endpoint,
        "health": health or None,
        "endpoint_status": endpoint_status or None,
        "members": members or None,
    }

    metrics: Dict[str, Any] = {}
    if health:
        # Health timings
        took_rows = [
            {"endpoint": h.get("endpoint"), "took_ms": h.get("took_ms")}
            for h in health
            if h.get("endpoint") and h.get("took_ms") is not None
        ]
        took_vals = [r["took_ms"] for r in took_rows]
        if took_vals:
            mn = float(min(took_vals))
            mx = float(max(took_vals))
            metrics["health_latency_ms_min"] = mn
            metrics["health_latency_ms_max"] = mx
            metrics["health_latency_ms_skew"] = float(mx - mn)  # max - min
            metrics["health_latency_skew_ratio"] = float(mx / mn) if mn > 0 else None

            metrics["fastest_endpoints"] = sorted(
                {r["endpoint"] for r in took_rows if r.get("took_ms") == mn}
            )
            metrics["slowest_endpoints"] = sorted(
                {r["endpoint"] for r in took_rows if r.get("took_ms") == mx}
            )

            # Slow endpoints: all endpoints above threshold (default 110ms for console/JSON)
            slow_threshold_ms = 110.0
            over = [r for r in took_rows if float(r["took_ms"]) > slow_threshold_ms]
            over_sorted = sorted(over, key=lambda x: float(x["took_ms"]), reverse=True)

            metrics["slow_threshold_ms"] = slow_threshold_ms
            metrics["slow_endpoints_over_threshold"] = over_sorted or []


    if endpoint_status:
        raft_idxs = [r.get("raft_index") for r in endpoint_status if r.get("raft_index") is not None]
        if raft_idxs:
            metrics["raft_index_drift"] = int(max(raft_idxs) - min(raft_idxs))
        applied_idxs = [
            r.get("raft_applied_index")
            for r in endpoint_status
            if r.get("raft_applied_index") is not None
        ]
        if applied_idxs:
            metrics["raft_applied_index_drift"] = int(max(applied_idxs) - min(applied_idxs))

        terms = [r.get("raft_term") for r in endpoint_status if r.get("raft_term") is not None]
        if terms:
            metrics["raft_term_min"] = int(min(terms))
            metrics["raft_term_max"] = int(max(terms))

        # Counts (robust even if member list lines are missing)
        ids_or_eps = [r.get("id") or r.get("endpoint") for r in endpoint_status if (r.get("id") or r.get("endpoint"))]
        metrics["members_count"] = int(len(set(ids_or_eps))) if ids_or_eps else int(len(endpoint_status))
        metrics["learners_count"] = int(sum(1 for r in endpoint_status if r.get("is_learner") is True))

        # Leader term (if determinable)
        leader_row = next((r for r in endpoint_status if r.get("is_leader") is True), None)
        if leader_row and leader_row.get("raft_term") is not None:
            metrics["leader_raft_term"] = int(leader_row["raft_term"])

    return {"parsed": parsed, "metrics": metrics, "raw": raw_text}


def load_etcd_status(status_path: Optional[Path]) -> Dict[str, Any]:
    """Load etcd-status.txt from disk (best-effort). Never raises."""
    if status_path is None:
        return {"missing": True, "path": "etcd-status.txt"}
    if not status_path.exists() or not status_path.is_file():
        return {"missing": True, "path": str(status_path)}

    try:
        raw = status_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        # Still do not fail the run; treat as missing/unreadable
        return {"missing": True, "path": str(status_path), "error": str(e)}

    doc = parse_etcd_status_text(raw)
    doc["missing"] = False
    doc["path"] = str(status_path)
    return doc


def print_etcd_status_console(status_doc: Dict[str, Any]) -> None:
    print("=== etcd-status.txt (interpreted) ===")
    if status_doc.get("missing"):
        p = status_doc.get("path", "etcd-status.txt")
        print(f"(missing) Could not find: {p}")
        print()
        return

    parsed = status_doc.get("parsed", {}) or {}
    metrics = status_doc.get("metrics", {}) or {}

    leader = parsed.get("leader_endpoint") or "unknown"
    leader_term = metrics.get("leader_raft_term")
    term_min = metrics.get("raft_term_min")
    term_max = metrics.get("raft_term_max")

    members_count = metrics.get("members_count")
    learners_count = metrics.get("learners_count")

    lat_min = metrics.get("health_latency_ms_min")
    lat_max = metrics.get("health_latency_ms_max")
    skew_ms = metrics.get("health_latency_ms_skew")
    skew_ratio = metrics.get("health_latency_skew_ratio")
    slow_threshold = metrics.get("slow_threshold_ms", 110.0)
    slow_over = metrics.get("slow_endpoints_over_threshold") or []

    raft_drift = metrics.get("raft_index_drift")
    applied_drift = metrics.get("raft_applied_index_drift")

    # Leader + term
    if leader_term is not None:
        print(f"Leader: {leader}  (term={leader_term})")
    else:
        # fallback if we only have min/max term
        if term_min is not None and term_max is not None and term_min == term_max:
            print(f"Leader: {leader}  (term={term_min})")
        else:
            print(f"Leader: {leader}")

    # Members / learners
    if members_count is not None and learners_count is not None:
        print(f"Members: {members_count}  |  Learners: {learners_count}")
    elif members_count is not None:
        print(f"Members: {members_count}")

    # Health timings
    if lat_min is not None and lat_max is not None:
        # Display min/max + skew in ms and ratio vs fastest
        skew_ms_disp = f"{skew_ms:.2f}" if isinstance(skew_ms, (int, float)) else "unknown"
        skew_ratio_disp = f"{skew_ratio:.1f}×" if isinstance(skew_ratio, (int, float)) else "unknown"
        print("Health latency (ms):")
        print(f"   fastest: {lat_min:.2f}")
        print(f"   slowest: {lat_max:.2f}")
        print(f"   skew: {skew_ms_disp} ms  ({skew_ratio_disp} vs fastest)")
    else:
        print("Health latency (ms): (unknown — no health timings parsed)")

    # Slow endpoints over threshold
    if slow_over:
        # List all endpoints over threshold, slowest first
        print(f"Slow endpoint(s) (> {slow_threshold:.0f} ms):")
        for r in slow_over:
            ep = r.get("endpoint") or "unknown"
            ms = r.get("took_ms")
            if isinstance(ms, (int, float)):
                print(f"   - {ep} ({float(ms):.2f} ms)")
            else:
                print(f"   - {ep} (unknown ms)")
    else:
        if lat_min is not None:
            print(f"Slow endpoint(s) (> {slow_threshold:.0f} ms): none")
        else:
            print("Slow endpoint(s): (unknown — no health timings parsed)")

    # Raft drift
    if raft_drift is not None or applied_drift is not None:
        print("Raft index drift:")
        if raft_drift is not None:
            print(f"   index drift: {raft_drift}")
        else:
            print("   index drift: (unknown)")
        if applied_drift is not None:
            print(f"   applied drift: {applied_drift}")
        else:
            print("   applied drift: (unknown)")
    else:
        print("Raft index drift: (unknown — no endpoint status parsed)")
    print()

    print("=== etcd-status.txt (raw) ===")
    print(status_doc.get("raw", "").rstrip("\n"))
    print()
def extract_key(line: str) -> Optional[str]:
    m = KEY_RE.search(line)
    return m.group(1) if m else None


def extract_duration_fields(raw_json_text: str, j: Optional[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    """Extract common duration fields from either parsed JSON or raw JSON string."""
    out: Dict[str, Optional[str]] = {
        "took": None,
        "expected": None,
        "duration": None,
        "time_spent": None,
        "exceeded": None,
        "retry_timeout": None,
    }

    # Prefer structured JSON keys when present
    if j and isinstance(j, dict):
        for k in ("took", "expected-duration", "duration", "time spent", "exceeded-duration", "retry-timeout"):
            if k in j:
                if k == "expected-duration":
                    out["expected"] = str(j[k])
                elif k == "time spent":
                    out["time_spent"] = str(j[k])
                elif k == "exceeded-duration":
                    out["exceeded"] = str(j[k])
                elif k == "retry-timeout":
                    out["retry_timeout"] = str(j[k])
                else:
                    out[k.replace("-", "_")] = str(j[k])

    # Regex fallback (works even when some fields are nested or quoted)
    for name, rx in DURATION_TOKENS.items():
        m = rx.search(raw_json_text)
        if m:
            val = m.group(1)
            if name == "expected":
                out["expected"] = out["expected"] or val
            elif name == "time_spent":
                out["time_spent"] = out["time_spent"] or val
            elif name == "exceeded":
                out["exceeded"] = out["exceeded"] or val
            elif name == "retry_timeout":
                out["retry_timeout"] = out["retry_timeout"] or val
            else:
                out[name] = out[name] or val

    return out


def pick_primary_duration_s(d: Dict[str, Optional[str]]) -> Tuple[Optional[str], Optional[float], str]:
    """Pick a single 'best' duration for severity scoring.

    Returns: (label, seconds, source_field)
    """
    for field in ("took", "time_spent", "duration", "exceeded", "retry_timeout"):
        if d.get(field):
            s = parse_duration_to_seconds(d[field])
            if s is not None:
                return d[field], s, field
    return None, None, ""


def classify_line(line: str) -> Optional[str]:
    for kind, pat in EVENT_PATTERNS:
        if pat.search(line):
            return kind
    return None


# ----------------------------
# Event model
# ----------------------------
@dataclass
class Event:
    ts: datetime
    kind: str
    msg: str
    severity: str

    # Backwards-compat alias: earlier versions used event_type
    @property
    def event_type(self) -> str:
        return self.kind


    # durations
    primary_duration: Optional[str] = None
    primary_duration_s: Optional[float] = None
    primary_duration_src: str = ""

    took: Optional[str] = None
    expected: Optional[str] = None
    duration: Optional[str] = None
    time_spent: Optional[str] = None
    exceeded: Optional[str] = None
    retry_timeout: Optional[str] = None

    expected_s: Optional[float] = None
    key: Optional[str] = None
    raw: str = ""



def _naive_utc(dt: datetime) -> datetime:
    """Normalize datetimes for safe comparison.

    Event timestamps may be offset-naive (no tzinfo) or offset-aware.
    Interactive time filters are parsed as offset-naive (local) or may be aware depending on source.
    For consistent comparisons we normalize aware datetimes to UTC and strip tzinfo.
    Naive datetimes are returned unchanged.
    """
    if dt is None:
        return dt
    try:
        if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        # If tzinfo is weird/unusable, fall back to naive as-is
        return dt.replace(tzinfo=None)
    return dt


# ----------------------------
# Severity engine
# ----------------------------

def clamp_sev(sev: str) -> str:
    return sev if sev in SEV_ORDER else "INFO"


def max_sev(a: str, b: str) -> str:
    return ORDER_SEV[max(SEV_ORDER[clamp_sev(a)], SEV_ORDER[clamp_sev(b)])]


def base_severity(kind: str) -> str:
    return BASE_SEVERITY.get(kind, "INFO")


def duration_bucket(ms: float, *, critical_ms: float, high_ms: float, medium_ms: float, low_ms: float) -> str:
    """Map a duration (milliseconds) to a severity bucket."""
    if ms >= critical_ms:
        return "CRITICAL"
    if ms >= high_ms:
        return "HIGH"
    if ms >= medium_ms:
        return "MEDIUM"
    if ms >= low_ms:
        return "LOW"
    return "INFO"


def duration_aware_severity(kind: str, base: str, primary_s: Optional[float], expected_s: Optional[float], key: Optional[str]) -> str:
    """Duration-aware severity rules.

    Principles:
      - For latency signals: absolute duration is primary.
      - expected-duration ratio is a useful booster when present.
      - Certain keyspaces (e.g., /registry/health) should escalate faster.
    """
    sev = base

    ratio = None
    if primary_s is not None and expected_s is not None and expected_s > 0:
        ratio = primary_s / expected_s

    if primary_s is not None:
        ms = primary_s * 1000.0

        override_thresholds = None
        if key:
            for key_prefix, thresholds in KEYSPACE_OVERRIDE_THRESHOLDS:
                if key.startswith(key_prefix):
                    override_thresholds = thresholds
                    break
        if kind == "health_registry_read" and override_thresholds is None:
            override_thresholds = (100.0, 150.0, 250.0, 500.0)

        if override_thresholds is not None:
            low_ms, medium_ms, high_ms, critical_ms = override_thresholds
            sev = max_sev(sev, duration_bucket(ms, critical_ms=critical_ms, high_ms=high_ms, medium_ms=medium_ms, low_ms=low_ms))
        else:
            policy_id = DURATION_POLICY_BY_EVENT_TYPE.get(kind)
            thresholds = DURATION_THRESHOLDS_BY_POLICY.get(policy_id) if policy_id else None
            if thresholds is None and kind in ("raft_process_slow", "raft_compare_slow"):
                thresholds = DURATION_THRESHOLDS_BY_POLICY.get("apply_took_too_long")
            if thresholds is not None:
                low_ms, medium_ms, high_ms, critical_ms = thresholds
                sev = max_sev(sev, duration_bucket(ms, critical_ms=critical_ms, high_ms=high_ms, medium_ms=medium_ms, low_ms=low_ms))

    if ratio is not None:
        medium_gte, high_gte, critical_gte = RATIO_BOOST_THRESHOLDS
        if ratio >= critical_gte:
            sev = max_sev(sev, "CRITICAL")
        elif ratio >= high_gte:
            sev = max_sev(sev, "HIGH")
        elif ratio >= medium_gte:
            sev = max_sev(sev, "MEDIUM")

    return clamp_sev(sev)


# ----------------------------
# Storm detection
# ----------------------------

def detect_storms(events: List[Event]) -> List[Event]:
    """Generate synthetic "storm" events when a kind repeats heavily.

    These events help collapse noisy output and surface the *shape* of an incident.
    """
    if not events:
        return []

    rules: Dict[str, Tuple[int, int, str, str]] = dict(STORM_RULES)

    by_kind: Dict[str, List[Event]] = {}
    for e in events:
        by_kind.setdefault(e.kind, []).append(e)

    synthetic: List[Event] = []

    for kind, (win_s, thresh, storm_sev, synthetic_event_type) in rules.items():
        lst = by_kind.get(kind)
        if not lst:
            continue
        lst = sorted(lst, key=lambda x: x.ts)

        j = 0
        for i in range(len(lst)):
            while lst[i].ts - lst[j].ts > timedelta(seconds=win_s):
                j += 1
            count = i - j + 1
            if count == thresh:
                start = lst[j].ts
                end = lst[i].ts
                msg = f"STORM: {kind} occurred {count} times in {win_s}s (window {start.isoformat()} -> {end.isoformat()})"
                synthetic.append(
                    Event(
                        ts=end,
                        kind=synthetic_event_type,
                        msg=msg,
                        severity=storm_sev,
                        raw=msg,
                    )
                )

    return synthetic


# ----------------------------
# Parsing
# ----------------------------

def iter_events(path: Path) -> Iterable[Event]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            kind = classify_line(line)
            if not kind:
                continue

            j, raw_json_text = try_parse_json_payload(line)
            ts = extract_timestamp(line, j)
            if ts is None:
                continue

            d = extract_duration_fields(raw_json_text, j)
            expected_s = parse_duration_to_seconds(d.get("expected"))
            key = extract_key(line)

            primary_label, primary_s, primary_src = pick_primary_duration_s(d)

            # Prefer JSON msg field; otherwise show the full line
            if j and "msg" in j:
                msg = str(j.get("msg") or "")
            else:
                msg = line

            base = base_severity(kind)
            sev = duration_aware_severity(kind, base, primary_s, expected_s, key)

            yield Event(
                ts=ts,
                kind=kind,
                msg=msg,
                severity=sev,
                primary_duration=primary_label,
                primary_duration_s=primary_s,
                primary_duration_src=primary_src,
                took=d.get("took"),
                expected=d.get("expected"),
                duration=d.get("duration"),
                time_spent=d.get("time_spent"),
                exceeded=d.get("exceeded"),
                retry_timeout=d.get("retry_timeout"),
                expected_s=expected_s,
                key=key,
                raw=line,
            )


# ----------------------------
# Incident windowing + narrative output
# ----------------------------

def group_incident_windows(events: List[Event], gap: timedelta = timedelta(minutes=2)) -> List[List[Event]]:
    if not events:
        return []
    events = sorted(events, key=lambda e: e.ts)
    windows: List[List[Event]] = [[events[0]]]
    for e in events[1:]:
        if e.ts - windows[-1][-1].ts > gap:
            windows.append([e])
        else:
            windows[-1].append(e)
    return windows


def _prefix_bucket(key: str) -> str:
    # Kubernetes etcd keyspace helpers
    for p in (
        "/registry/health",
        "/registry/leases/",
        "/registry/events/",
        "/registry/minions/",
        "/registry/configmaps/",
        "/registry/pods/",
        "/registry/namespaces/",
        "/registry/services/",
    ):
        if key.startswith(p):
            return p
    return "(other)"


def window_narrative(window: List[Event]) -> List[str]:
    """Heuristic narrative: concise, but attempts cause/effect ordering."""
    kinds = {e.kind for e in window}

    # Max observed durations by kind (ms)
    max_ms: Dict[str, float] = {}
    for e in window:
        if e.primary_duration_s is None:
            continue
        ms = e.primary_duration_s * 1000.0
        if ms > max_ms.get(e.kind, 0.0):
            max_ms[e.kind] = ms

    # Keyspace hotspots
    key_counts: Dict[str, int] = {}
    for e in window:
        if e.key:
            key_counts[_prefix_bucket(e.key)] = key_counts.get(_prefix_bucket(e.key), 0) + 1

    top_keys = sorted(key_counts.items(), key=lambda kv: kv[1], reverse=True)[:4]

    lines: List[str] = []

    # Early warnings
    if "raft_read_agreement_slow" in kinds or "linearizable_read_slow" in kinds or "readindex_retry" in kinds:
        parts = []
        if "raft_read_agreement_slow" in max_ms:
            parts.append(f"raft agreement before linearized read slow (max ~{max_ms['raft_read_agreement_slow']:.0f}ms)")
        if "linearizable_read_slow" in max_ms:
            parts.append(f"linearizableReadLoop slow (max ~{max_ms['linearizable_read_slow']:.0f}ms)")
        if "readindex_retry" in kinds:
            parts.append("ReadIndex retries")
        lines.append("* Early read-path pressure: " + "; ".join(parts))

    # Apply pipeline
    if "apply_took_too_long" in kinds or "raft_process_slow" in kinds or "inmemory_index_scan_slow" in kinds:
        parts = []
        if "apply_took_too_long" in max_ms:
            parts.append(f"apply latency spikes (max ~{max_ms['apply_took_too_long']:.0f}ms)")
        if "raft_process_slow" in max_ms:
            parts.append(f"raft request processing slow (max ~{max_ms['raft_process_slow']:.0f}ms)")
        if "raft_compare_slow" in max_ms:
            parts.append(f"CAS/compare slow (max ~{max_ms['raft_compare_slow']:.0f}ms)")
        if "inmemory_index_scan_slow" in kinds:
            parts.append("in-memory index scans show up")
        lines.append("* Apply pipeline pressure: " + "; ".join(parts))

    # Control-plane impact
    if "health_registry_read" in kinds:
        v = max_ms.get("health_registry_read")
        if v:
            lines.append(f"* Control-plane impact: /registry/health read slow (max ~{v:.0f}ms)")
        else:
            lines.append("* Control-plane impact: /registry/health reads present")

    # Raft timing / disk suspicion
    disk_suspect = False
    if "slow_fdatasync" in kinds or "raft_heartbeat_miss" in kinds:
        disk_suspect = True

    if disk_suspect:
        parts = []
        if "slow_fdatasync" in max_ms:
            parts.append(f"slow fdatasync (max ~{max_ms['slow_fdatasync']:.0f}ms)")
        if "raft_heartbeat_miss" in max_ms:
            parts.append(f"heartbeat slips (max exceeded ~{max_ms['raft_heartbeat_miss']:.0f}ms)")
        lines.append("* Raft timing degradation: " + "; ".join(parts) + " -> likely I/O or leader overload")

    # Applied index lag = close to stuck
    if "applied_index_lag" in kinds:
        lines.append("* Correctness risk: appliedIndex lagging readStateIndex detected")

    # Key hotspots
    if top_keys:
        pretty = ", ".join(f"{k}×{v}" for k, v in top_keys)
        lines.append("* Hot keyspaces in this window: " + pretty)

    # If nothing matched, keep a fallback
    if not lines:
        lines.append("* Narrative: events present, but no strong heuristic storyline matched")

    return lines


def window_summary(window: List[Event]) -> str:
    start = window[0].ts
    end = window[-1].ts

    # Highest severity in the window
    max_window_sev = "INFO"
    counts: Dict[str, int] = {}
    sev_counts: Dict[str, int] = {}

    # Track per-kind max duration
    max_dur: Dict[str, float] = {}

    for e in window:
        counts[e.kind] = counts.get(e.kind, 0) + 1
        sev_counts[e.severity] = sev_counts.get(e.severity, 0) + 1
        max_window_sev = max_sev(max_window_sev, e.severity)
        if e.primary_duration_s is not None:
            max_dur[e.kind] = max(max_dur.get(e.kind, 0.0), e.primary_duration_s)

    lines: List[str] = []
    lines.append(
        f"Window: {start.isoformat()}  ->  {end.isoformat()}  ({len(window)} events)  SEV={sev_with_icon(max_window_sev)}"
    )

    # severity counts
    if sev_counts:
        lines.append(
            "Severity counts: "
            + ", ".join(
                f"{k}={v}" for k, v in sorted(sev_counts.items(), key=lambda kv: SEV_ORDER[kv[0]], reverse=True)
            )
        )

    # top event kinds
    lines.append(
        "Event counts: "
        + ", ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:10])
    )

    # storms
    storms = [e for e in window if e.kind.startswith("storm_")]
    if storms:
        lines.append("Storms:")
        for s in storms:
            lines.append(f"  - {s.ts.isoformat()}  {sev_bracket(s.severity)} {s.msg}")

    # narrative
    lines.append("Narrative:")
    for n in window_narrative([e for e in window if not e.kind.startswith("storm_")]):
        lines.append(f"  {n}")

    # Show first occurrence of each kind (in time order), with severity and useful fields
    lines.append("Signals (first occurrence per kind):")
    seen = set()
    for e in window:
        if e.kind in seen:
            continue
        seen.add(e.kind)

        extras: List[str] = []
        if e.primary_duration:
            extras.append(f"{e.primary_duration_src}={e.primary_duration}")
        if e.expected:
            extras.append(f"expected={e.expected}")
        if e.key:
            extras.append(f"key={e.key}")

        lines.append(
            f"  - {e.ts.isoformat()}  {sev_bracket(e.severity)} {e.kind}: {e.msg}"
            + (f" ({', '.join(extras)})" if extras else "")
        )

    return "\n".join(lines)


def write_csv(events: List[Event], csv_path: Path) -> None:
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "ts",
                "severity",
                "kind",
                "primary_duration",
                "primary_duration_src",
                "took",
                "expected",
                "duration",
                "time_spent",
                "exceeded",
                "retry_timeout",
                "key",
                "msg",
            ]
        )
        for e in events:
            w.writerow(
                [
                    e.ts.isoformat(),
                    e.severity,
                    e.kind,
                    e.primary_duration or "",
                    e.primary_duration_src or "",
                    e.took or "",
                    e.expected or "",
                    e.duration or "",
                    e.time_spent or "",
                    e.exceeded or "",
                    e.retry_timeout or "",
                    e.key or "",
                    e.msg,
                ]
            )


def _sev_counts_full(window: List[Event]) -> Dict[str, int]:
    counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for e in window:
        counts[e.severity] = counts.get(e.severity, 0) + 1
    # Drop INFO if it's zero to reduce noise
    if counts.get("INFO", 0) == 0:
        counts.pop("INFO", None)
    return counts


def _max_severity(window: List[Event]) -> str:
    sev = "INFO"
    for e in window:
        sev = max_sev(sev, e.severity)
    return sev


def max_severity(window: List[Event]) -> str:
    """Backward-compatible alias for _max_severity (some call sites still use the old name)."""
    return _max_severity(window)


def _max_duration_ms_by_kind(window: List[Event]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for e in window:
        if e.primary_duration_s is None:
            continue
        ms = e.primary_duration_s * 1000.0
        if ms > out.get(e.kind, 0.0):
            out[e.kind] = ms
    # Round very slightly for readability, but keep numeric
    return {k: float(f"{v:.6f}") for k, v in out.items()}


def _signals_first(window: List[Event]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    signals: List[Dict[str, Any]] = []
    for e in window:
        if e.kind in seen:
            continue
        seen.add(e.kind)
        obj: Dict[str, Any] = {
            "ts": e.ts.isoformat(),
            "severity": e.severity,
            "severity_rank": SEV_LEVEL.get(e.severity, 5),
            "kind": e.kind,
            "message": e.msg,
        }
        if e.primary_duration_s is not None:
            obj["duration_ms"] = float(f"{e.primary_duration_s * 1000.0:.6f}")
            obj["duration_src"] = e.primary_duration_src or ""
        if e.expected_s is not None:
            obj["expected_ms"] = float(f"{e.expected_s * 1000.0:.6f}")
        if e.key:
            obj["key"] = e.key
        signals.append(obj)
    return signals


def _event_to_json(e: Event) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "ts": e.ts.isoformat(),
        "severity": e.severity,
        "severity_rank": SEV_LEVEL.get(e.severity, 5),
        "kind": e.kind,
        "message": e.msg,
    }
    if e.primary_duration_s is not None:
        obj["duration_ms"] = float(f"{e.primary_duration_s * 1000.0:.6f}")
        obj["duration_src"] = e.primary_duration_src or ""
    if e.expected_s is not None:
        obj["expected_ms"] = float(f"{e.expected_s * 1000.0:.6f}")
    if e.key:
        obj["key"] = e.key
    # Keep raw line for deep dives
    obj["raw"] = e.raw
    return obj


def write_incidents_json(
    *,
    out_file: Path,
    log_file: Path,
    incidents: List[List[Event]],
    date_filter: Optional[date],
    days: int,
    levels: List[int],
    include_events: bool,
    etcd_status: Optional[Dict[str, Any]] = None,
) -> None:
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Totals
    total_sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    max_total_sev = "INFO"
    for w in incidents:
        for e in w:
            total_sev_counts[e.severity] = total_sev_counts.get(e.severity, 0) + 1
            max_total_sev = max_sev(max_total_sev, e.severity)
    if total_sev_counts.get("INFO", 0) == 0:
        total_sev_counts.pop("INFO", None)

    doc: Dict[str, Any] = {
        "schema_version": "etcd_analysis.incidents.v1",
        "generated_at": generated_at,
        "source": {
            "log_file": str(log_file),
            "filters": {
                "date": date_filter.isoformat() if date_filter else None,
                "days": days,
                "levels": levels,
            },
        },
        "summary": {
            "incident_count": len(incidents),
            "max_severity": max_total_sev,
            "max_severity_rank": SEV_LEVEL.get(max_total_sev, 5),
            "severity_counts_total": total_sev_counts,
        },
        "incidents": [],
        "etcd_status": etcd_status,
    }

    for idx, w in enumerate(incidents, start=1):
        if not w:
            continue
        start = w[0].ts
        end = w[-1].ts
        sev_max = _max_severity(w)
        sev_counts = _sev_counts_full(w)

        # Event counts by kind
        kind_counts: Dict[str, int] = {}
        for e in w:
            kind_counts[e.kind] = kind_counts.get(e.kind, 0) + 1

        incident_obj: Dict[str, Any] = {
            "id": idx,
            "window": {
                "start": start.isoformat(),
                "end": end.isoformat(),
                "duration_ms": int((end - start).total_seconds() * 1000.0),
            },
            "severity": {
                "max": sev_max,
                "max_rank": SEV_LEVEL.get(sev_max, 5),
                "counts": sev_counts,
            },
            "event_counts": kind_counts,
            "metrics": {
                "max_duration_ms_by_kind": _max_duration_ms_by_kind(w),
            },
            "narrative": window_narrative([e for e in w if not e.kind.startswith("storm_")]),
            "signals_first": _signals_first(w),
        }

        if include_events:
            incident_obj["events"] = [_event_to_json(e) for e in w]

        doc["incidents"].append(incident_obj)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=False)
        f.write("\n")



def analyze_log_file(
    log_file: Path,
    output_dir: Path,
    csv_hostname: Optional[str] = None,
    status_path: Optional[Path] = None,
    date_filter: Optional[date] = None,
    days: Optional[int] = None,
    time_range: Optional[Tuple[datetime, datetime]] = None,
    levels: Optional[List[int]] = None,
    json_include_events: bool = False,
) -> Dict[str, Any]:
    """Analyze a single ucp-kv.log file and return a structured result dict.

    This is the core engine used for both single-node runs and bundle scans.
    """
    if not log_file.exists() or not log_file.is_file():
        raise FileNotFoundError(str(log_file))

    # Default status file resolution keeps v9 behavior, but bundle scans pass an explicit path.
    if status_path is None:
        status_path = log_file.parent.parent / "etcd-status.txt"

    etcd_status = load_etcd_status(status_path)

    events = list(iter_events(log_file))
    events.sort(key=lambda e: e.ts)

    # Optional time-range filter (centered window around --time in CLI)
    if time_range is not None:
        before_tr = len(events)
        start_tr = _naive_utc(time_range[0])
        end_tr = _naive_utc(time_range[1])
        events = [e for e in events if (start_tr <= _naive_utc(e.ts) < end_tr)]
        after_tr = len(events)
        # Do not print noisy per-node filtering lines; this is a forensic filter.
    
        sample_hits = [
            _naive_utc(e.ts).isoformat()
            for e in events[:10]
        ]
        print(f"DEBUG filtered sample event timestamps: {sample_hits}", file=sys.stderr)

    # Optional date/day filter.
    if date_filter is not None:
        day_span = int(days) if days is not None else 0
        before_date = len(events)
        events = filter_events_by_date_window(events, date_filter, day_span)
        after_date = len(events)

        print(
            f"DEBUG date filter: date={date_filter.isoformat()} days={day_span} kept={after_date}/{before_date}",
            file=sys.stderr,
        )

    # Add storm events (then re-sort).
    storms = detect_storms(events)
    if storms:
        events.extend(storms)
        events.sort(key=lambda e: e.ts)

    # Optional time-range filter (centered window around --time in CLI)
    if time_range is not None:
        before_tr = len(events)
        start_tr = _naive_utc(time_range[0])
        end_tr = _naive_utc(time_range[1])
        events = [e for e in events if (start_tr <= _naive_utc(e.ts) < end_tr)]
        after_tr = len(events)
        print(
            f"DEBUG time filter: start={start_tr.isoformat()} end={end_tr.isoformat()} kept={after_tr}/{before_tr}",
            file=sys.stderr,
    )

    # Optional severity-level filter (applied AFTER storm detection)
    if levels is None:
        levels = [1, 2, 3, 4]
    level_set = set(levels)
    before = len(events)
    events = [e for e in events if SEV_LEVEL.get(e.severity, 5) in level_set]
    after = len(events)
    if level_set != {1, 2, 3, 4}:
        print(
            f"Filtering events by severity level(s): {','.join(str(x) for x in sorted(level_set))} — kept {after}/{before} events"
        )

    csv_path = build_events_csv_path(output_dir, csv_hostname)
    write_csv(events, csv_path)

    # group into incident windows
    windows = group_incident_windows(events, gap=timedelta(minutes=2))

    # Build per-node JSON-like payload (used by bundle output)
    incidents_payload: List[Dict[str, Any]] = []
    for w in windows:
        incident_obj = {
            "window_start": w[0].ts.isoformat() if w else None,
            "window_end": w[-1].ts.isoformat() if w else None,
            "severity_max": max_severity(w),
            "severity_icon": SEV_ICON.get(max_severity(w), ""),
            "event_types": sorted(set([getattr(e, 'event_type', getattr(e, 'kind', 'unknown')) for e in w if not getattr(e, 'event_type', getattr(e, 'kind', 'unknown')).startswith("storm_")])),
            "signals_first": _signals_first(w),
        }
        if json_include_events:
            incident_obj["events"] = [_event_to_json(e) for e in w]
        incidents_payload.append(incident_obj)

    return {
        "log_file": str(log_file),
        "csv_file": str(csv_path),
        "events_count": int(len(events)),
        "windows_count": int(len(windows)),
        "incidents": incidents_payload,
        "windows": windows,
        "all_events": events,
        "etcd_status": etcd_status,
        "filters": {
            "date": date_filter.isoformat() if date_filter else None,
            "days": (int(days) if days is not None else None),
            "levels": list(levels) if levels is not None else [1, 2, 3, 4],
            "json_include_events": bool(json_include_events),
        },
    }


_NODE_ADDR_RE = re.compile(r"^\s*Node\s+Address\s*:\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s*$", re.IGNORECASE)
_NODE_HOSTNAME_RE = re.compile(r'^\s*Hostname\s*:\s*"(?P<hostname>[^"]+)"\s*$', re.IGNORECASE)


def parse_node_ip(dsinfo_txt: Path) -> Optional[str]:
    """Extract Node Address IP from dsinfo.txt (best-effort)."""
    try:
        raw = dsinfo_txt.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    for ln in raw.splitlines():
        m = _NODE_ADDR_RE.match(ln)
        if m:
            return m.group("ip")
    return None

def parse_node_hostname(dsinfo_txt: Path) -> Optional[str]:
    """Extract Hostname from dsinfo.txt (best-effort)."""
    try:
        raw = dsinfo_txt.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    for ln in raw.splitlines():
        m = _NODE_HOSTNAME_RE.search(ln)
        if m:
            return m.group("hostname").strip()

    return None

def sanitize_hostname_for_filename(hostname: Optional[str]) -> str:
    raw = (hostname or "").strip()
    if not raw:
        return "unknown-host"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    return safe or "unknown-host"


def build_events_csv_path(output_dir: Path, hostname: Optional[str]) -> Path:
    safe_host = sanitize_hostname_for_filename(hostname)
    return output_dir / f"{safe_host}_ucp-kv.log.events.csv"

def parse_node_hostname(dsinfo_txt: Path) -> Optional[str]:
    """Extract Hostname from dsinfo.txt (best-effort)."""
    try:
        raw = dsinfo_txt.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    for ln in raw.splitlines():
        m = _NODE_HOSTNAME_RE.match(ln)
        if m:
            return m.group("hostname").strip()
    return None

def find_ucp_kv_log(dsinfo_logs_dir: Path) -> Optional[Path]:
    """Find ucp-kv.log under <hostname>/dsinfo/logs/** (nested). Choose the newest by mtime."""
    if not dsinfo_logs_dir.exists() or not dsinfo_logs_dir.is_dir():
        return None
    candidates = sorted(dsinfo_logs_dir.rglob("ucp-kv.log"))
    if not candidates:
        return None
    # pick newest by mtime; tie-breaker by path for determinism
    candidates.sort(key=lambda p: (p.stat().st_mtime, str(p)), reverse=True)
    return candidates[0]



def find_journalctl_daemon_log(dsinfo_dir: Path) -> Optional[Path]:
    """Find journalctl_daemon.log for a node.

    Preferred location: <hostname>/dsinfo/journalctl_daemon.log
    Fallback: search under <hostname>/dsinfo/logs/**/journalctl_daemon.log
    Choose the newest by mtime if multiple are found.
    """
    if not dsinfo_dir.exists() or not dsinfo_dir.is_dir():
        return None
    direct = dsinfo_dir / "journalctl_daemon.log"
    candidates: List[Path] = []
    if direct.exists():
        candidates.append(direct)
    logs_dir = dsinfo_dir / "logs"
    if logs_dir.exists() and logs_dir.is_dir():
        candidates.extend(sorted(logs_dir.rglob("journalctl_daemon.log")))
    if not candidates:
        return None
    candidates.sort(key=lambda p: (p.stat().st_mtime, str(p)), reverse=True)
    return candidates[0]

@dataclass(frozen=True)
class ResolvedInput:
    kind: str
    mode: str  # "cluster" | "single_node"
    input_path: Path
    bundle_root: Optional[Path] = None
    host_dir: Optional[Path] = None
    dsinfo_dir: Optional[Path] = None
    log_file: Optional[Path] = None
    status_path: Optional[Path] = None
    journal_path: Optional[Path] = None


def _looks_like_cluster_bundle_root(path: Path) -> bool:
    if not path.exists() or not path.is_dir():
        return False

    has_bundle_marker = (path / "ucp-nodes.txt").exists() or (path / "dsinfo.json").exists()
    if not has_bundle_marker:
        return False

    for child in path.iterdir():
        if child.is_dir() and (child / "dsinfo").is_dir():
            return True

    return False


def classify_bundle_input(path: Path) -> str:
    """
    Classify a user-supplied path into one of:
      - cluster_bundle_root
      - single_node_host_dir
      - single_node_dsinfo_dir
      - single_node_parent_dir
      - unknown
    """
    if not path.exists() or not path.is_dir():
        return "unknown"

    if _looks_like_cluster_bundle_root(path):
        return "cluster_bundle_root"

    if path.name == "dsinfo" and path.is_dir():
        return "single_node_dsinfo_dir"

    if (path / "dsinfo").is_dir():
        return "single_node_host_dir"

    dsinfo_children = [p for p in path.iterdir() if p.is_dir() and p.name == "dsinfo"]
    if dsinfo_children:
        return "single_node_parent_dir"

    return "unknown"


def resolve_single_node_inputs(path: Path, kind: str) -> ResolvedInput:
    """
    Normalize all supported single-node input shapes into a common structure.
    """
    if kind == "single_node_dsinfo_dir":
        dsinfo_dir = path
        host_dir = path.parent
    elif kind == "single_node_host_dir":
        dsinfo_dir = path / "dsinfo"
        host_dir = path
    elif kind == "single_node_parent_dir":
        dsinfo_dir = path / "dsinfo"
        host_dir = path
    else:
        raise ValueError(f"Unsupported single-node input kind: {kind}")

    if not dsinfo_dir.exists() or not dsinfo_dir.is_dir():
        raise ValueError(f"Resolved dsinfo directory not found: {dsinfo_dir}")

    logs_dir = dsinfo_dir / "logs"
    status_path = dsinfo_dir / "etcd-status.txt"
    journal_path = find_journalctl_daemon_log(dsinfo_dir)
    log_file = find_ucp_kv_log(logs_dir)

    return ResolvedInput(
        kind=kind,
        mode="single_node",
        input_path=path,
        host_dir=host_dir,
        dsinfo_dir=dsinfo_dir,
        log_file=log_file if (log_file is not None and log_file.exists()) else None,
        status_path=status_path if status_path.exists() else None,
        journal_path=journal_path if (journal_path is not None and journal_path.exists()) else None,
    )


def resolve_bundle_input(path: Path) -> ResolvedInput:
    """
    Resolve a single user-facing bundle path into cluster or single-node execution input.
    """
    if not path.exists():
        raise ValueError(f"Input path not found: {path}")
    if not path.is_dir():
        raise ValueError(f"Input path must be a directory: {path}")

    kind = classify_bundle_input(path)

    if kind == "cluster_bundle_root":
        return ResolvedInput(
            kind=kind,
            mode="cluster",
            input_path=path,
            bundle_root=path,
        )

    if kind in {"single_node_host_dir", "single_node_dsinfo_dir", "single_node_parent_dir"}:
        return resolve_single_node_inputs(path, kind)

    raise ValueError(
        "Unrecognized input path. Expected one of: "
        "cluster bundle root, node directory, dsinfo directory, or parent containing dsinfo."
    )

def resolve_output_dir(output_dir_arg: Optional[str]) -> Path:
    """
    Resolve and create the directory used for all tool-created artifacts.
    Default is the current working directory.
    """
    raw = (output_dir_arg or ".").strip()
    outdir = Path(raw)
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def scan_bundle(root_dir: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Scan a support bundle root and return (nodes_to_analyze, skipped_nodes).

    v16: nodes may be included even if etcd-status/ucp-kv.log are missing, as long as a
    journalctl_daemon.log exists. This supports cases where etcd is dead/unresponsive.
    """
    nodes: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    if not root_dir.exists() or not root_dir.is_dir():
        raise FileNotFoundError(str(root_dir))

    for child in sorted([p for p in root_dir.iterdir() if p.is_dir()], key=lambda p: p.name.lower()):
        dir_hostname = child.name
        dsinfo_dir = child / "dsinfo"
        if not dsinfo_dir.exists() or not dsinfo_dir.is_dir():
            skipped.append({"hostname": dir_hostname, "reason": "missing dsinfo directory", "dsinfo_dir": str(dsinfo_dir)})
            continue

        status_path = dsinfo_dir / "etcd-status.txt"
        dsinfo_txt = dsinfo_dir / "dsinfo.txt"
        logs_dir = dsinfo_dir / "logs"

        journal_path = find_journalctl_daemon_log(dsinfo_dir)

        # Find ucp-kv.log under logs if present
        log_path = find_ucp_kv_log(logs_dir)

        # Candidate rules (v23):
        # - Include node if it has etcd quorum evidence (etcd-status.txt) OR etcd server log evidence (ucp-kv.log).
        # - journalctl_daemon.log is still *parsed* when present, but does not make a node eligible on its own.
        has_status = status_path.exists()
        has_log = log_path is not None and log_path.exists()
        has_journal = journal_path is not None and journal_path.exists()

        if not (has_status or has_log):
            skipped.append({"hostname": dir_hostname, "reason": "no etcd-status.txt and no ucp-kv.log"})
            continue

        parsed_hostname = parse_node_hostname(dsinfo_txt) if dsinfo_txt.exists() else None
        hostname = parsed_hostname or dir_hostname
        ip = parse_node_ip(dsinfo_txt) if dsinfo_txt.exists() else None

        nodes.append(
            {
                "hostname": hostname,
                "ip": ip,
                "host_dir": str(child),
                "dsinfo_txt": str(dsinfo_txt),
                "status_path": str(status_path) if has_status else None,
                "log_path": str(log_path) if has_log else None,
                "journal_path": str(journal_path) if has_journal else None,
            }
        )

    return nodes, skipped




def _classify_incident_families(node_results: List[Dict[str, Any]]) -> IncidentFamilySummary:
    """Best-effort: derive which incident families are present across all nodes (excluding storm_*)."""
    counts: Dict[str, int] = {"read_path": 0, "apply_path": 0, "disk_timing": 0, "client_network": 0, "raft_election": 0}

    def normalize_family_name(fam: Optional[str]) -> Optional[str]:
        if fam == "storage_timing":
            return "disk_timing"
        return fam

    def bump(fam: Optional[str], n: int = 1) -> None:
        fam = normalize_family_name(fam)
        if fam in counts:
            counts[fam] = counts.get(fam, 0) + n

    kinds_seen: Set[str] = set()
    for r in node_results:
        for w in (r.get("windows") or []):
            for e in w:
                k = getattr(e, "kind", None)
                if not k or str(k).startswith("storm_"):
                    continue
                kinds_seen.add(str(k))

    for r in node_results:
        j = r.get("journal") or {}
        if j.get("missing"):
            continue
        sc = (j.get("metrics") or {}).get("signal_counts") or {}
        for jk, cnt in sc.items():
            fam = JOURNAL_FAMILY_BY_EVENT_TYPE.get(str(jk))
            if fam:
                bump(fam, int(cnt) if isinstance(cnt, int) else 1)

    for k in kinds_seen:
        bump(FAMILY_BY_EVENT_TYPE.get(k))

    fam = IncidentFamilySummary(
        read_path=counts["read_path"] > 0,
        apply_path=counts["apply_path"] > 0,
        disk_timing=counts["disk_timing"] > 0,
        client_network=counts["client_network"] > 0,
        raft_election=counts["raft_election"] > 0,
        counts=counts,
    )
    return fam


def synthesize_cluster(
    node_results: List[Dict[str, Any]],
    *,
    slow_threshold_ms: float = 110.0,
    drift_warn_threshold: int = 100,
) -> ClusterSynthesis:
    """Derive a cluster synthesis from per-node etcd-status snapshots (best-effort)."""
    nodes_analyzed = len(node_results)

    # Snapshot coverage + leader/term
    snapshot_hosts = 0
    health_present_hosts = 0

    leaders_observed: Set[str] = set()
    leader_votes: Dict[str, int] = {}

    term_mins: List[int] = []
    term_maxs: List[int] = []

    members_counts: List[int] = []
    learners_counts: List[int] = []

    raft_index_drifts: List[int] = []
    raft_applied_drifts: List[int] = []

    # Health aggregates
    global_fastest: Optional[float] = None
    global_slowest: Optional[float] = None
    max_skew: Optional[float] = None
    max_ratio: Optional[float] = None

    # Endpoint-level: endpoint -> dict
    ep_stats: Dict[str, Dict[str, Any]] = {}

    # Determine observed endpoints count from endpoint status table if possible
    observed_endpoints_counts: List[int] = []

    # map leader endpoint ip -> hostname for leader_host convenience
    ip_to_host: Dict[str, str] = {}
    for r in node_results:
        ip = r.get("ip")
        hn = r.get("hostname")
        if ip and hn:
            ip_to_host[str(ip)] = str(hn)

    for r in node_results:
        status = (r.get("etcd_status") or {})
        if status.get("missing"):
            continue
        snapshot_hosts += 1
        parsed = status.get("parsed", {}) or {}
        metrics = status.get("metrics", {}) or {}

        leader = parsed.get("leader_endpoint") or "unknown"
        leaders_observed.add(leader)
        leader_votes[leader] = leader_votes.get(leader, 0) + 1

        # terms
        if metrics.get("raft_term_min") is not None:
            term_mins.append(int(metrics["raft_term_min"]))
        if metrics.get("raft_term_max") is not None:
            term_maxs.append(int(metrics["raft_term_max"]))

        # members/learners (best-effort: prefer parsed endpoint_status rows)
        mcount = metrics.get("members_count")
        lcount = metrics.get("learners_count")
        if isinstance(mcount, int):
            members_counts.append(mcount)
        if isinstance(lcount, int):
            learners_counts.append(lcount)

        # endpoint status rows to estimate observed endpoints
        rows = (parsed.get("endpoint_status") or [])
        if isinstance(rows, list) and rows:
            observed_endpoints_counts.append(len(rows))

        # drift
        if metrics.get("raft_index_drift") is not None:
            raft_index_drifts.append(int(metrics["raft_index_drift"]))
        if metrics.get("raft_applied_index_drift") is not None:
            raft_applied_drifts.append(int(metrics["raft_applied_index_drift"]))

        # health stats
        health_rows = (parsed.get("endpoint_health") or [])
        if isinstance(health_rows, list) and health_rows:
            # Health is present in this snapshot
            health_present_hosts += 1

            # snapshot min/max
            tooks = [float(h.get("took_ms")) for h in health_rows if isinstance(h.get("took_ms"), (int, float))]
            if tooks:
                snap_min = min(tooks)
                snap_max = max(tooks)
                skew = snap_max - snap_min
                ratio = (snap_max / snap_min) if snap_min > 0 else None

                global_fastest = snap_min if global_fastest is None else min(global_fastest, snap_min)
                global_slowest = snap_max if global_slowest is None else max(global_slowest, snap_max)
                max_skew = skew if max_skew is None else max(max_skew, skew)
                if ratio is not None:
                    max_ratio = ratio if max_ratio is None else max(max_ratio, ratio)

            # endpoint-level aggregation
            hn = r.get("hostname") or "unknown"
            for h in health_rows:
                ep = h.get("endpoint")
                ms = h.get("took_ms")
                if not ep or not isinstance(ms, (int, float)):
                    continue
                cur = ep_stats.get(ep)
                if cur is None:
                    ep_stats[ep] = {
                        "endpoint": str(ep),
                        "seen_count": 1,
                        "slow_count": 1 if float(ms) > slow_threshold_ms else 0,
                        "max_ms": float(ms),
                        "min_ms": float(ms),
                        "slow_seen_on_hosts": [hn] if float(ms) > slow_threshold_ms else [],
                        "seen_on_hosts": [hn],
                    }
                else:
                    cur["seen_count"] += 1
                    if float(ms) > slow_threshold_ms:
                        cur["slow_count"] += 1
                        if hn not in cur["slow_seen_on_hosts"]:
                            cur["slow_seen_on_hosts"].append(hn)
                    cur["max_ms"] = max(float(cur["max_ms"]), float(ms))
                    cur["min_ms"] = min(float(cur["min_ms"]), float(ms))
                    if hn not in cur["seen_on_hosts"]:
                        cur["seen_on_hosts"].append(hn)

    # Leader consensus
    leader_endpoint: Optional[str] = None
    leader_stable = False
    leader_host: Optional[str] = None
    if leader_votes:
        # pick top vote; deterministic tie-break by endpoint
        leader_endpoint = sorted(leader_votes.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        leader_stable = (len(leaders_observed) == 1)

        # derive leader host from leader endpoint ip (best-effort)
        if leader_endpoint and isinstance(leader_endpoint, str):
            m = re.search(r"https?://(\d+\.\d+\.\d+\.\d+):", leader_endpoint)
            if m:
                ip = m.group(1)
                leader_host = ip_to_host.get(ip)

    raft_term_min = min(term_mins) if term_mins else None
    raft_term_max = max(term_maxs) if term_maxs else None
    term_stable = (raft_term_min is not None and raft_term_max is not None and raft_term_min == raft_term_max)

    members_min = min(members_counts) if members_counts else None
    members_max = max(members_counts) if members_counts else None
    learners_max = max(learners_counts) if learners_counts else None

    max_raft_index_drift = max(raft_index_drifts) if raft_index_drifts else None
    max_raft_applied_drift = max(raft_applied_drifts) if raft_applied_drifts else None
    worst_drift = max([d for d in [max_raft_index_drift, max_raft_applied_drift] if d is not None], default=None)
    drift_concerning = bool(worst_drift is not None and worst_drift >= int(drift_warn_threshold))

    # Endpoint derived sets
    slow_endpoints_list: List[SlowEndpointStats] = []
    intermittent: List[str] = []
    sustained: List[str] = []
    significant: List[str] = []

    for ep, cur in ep_stats.items():
        seen = int(cur["seen_count"])
        slow = int(cur["slow_count"])
        min_hits = int(math.ceil(seen / 3.0)) if seen > 0 else 0
        stats = SlowEndpointStats(
            endpoint=str(ep),
            seen_count=seen,
            slow_count=slow,
            min_hits=min_hits,
            max_ms=float(cur["max_ms"]),
            min_ms=float(cur["min_ms"]),
            slow_seen_on_hosts=list(cur["slow_seen_on_hosts"]),
            seen_on_hosts=list(cur["seen_on_hosts"]),
        )
        # include endpoint if it was slow at least once OR to support seen_count when we want full list?
        if slow > 0:
            slow_endpoints_list.append(stats)
        if seen > 0 and slow >= min_hits:
            significant.append(str(ep))
            if slow < seen:
                intermittent.append(str(ep))
            else:
                sustained.append(str(ep))

    slow_endpoints_list.sort(key=lambda s: s.max_ms, reverse=True)
    intermittent.sort()
    sustained.sort()
    significant.sort()

    # Topology risk: "whichever is smaller"
    observed_snapshot_hosts = snapshot_hosts
    observed_endpoints = min(observed_endpoints_counts) if observed_endpoints_counts else 0
    quorum_candidate_count = min(observed_snapshot_hosts, observed_endpoints) if observed_endpoints > 0 else observed_snapshot_hosts
    is_single_member = (quorum_candidate_count == 1)

    topo_note = None
    if is_single_member:
        # Keep wording operational but short; detailed impact belongs in Operational impact section
        topo_note = "Only one RAFT member was observed in the available snapshots. If this endpoint becomes unavailable, quorum and availability will be impacted."

    topology = ClusterTopologyRisk(
        observed_snapshot_hosts=int(observed_snapshot_hosts),
        observed_endpoints=int(observed_endpoints),
        quorum_candidate_count=int(quorum_candidate_count),
        is_single_member=bool(is_single_member),
        note=topo_note,
    )

    incident_families = _classify_incident_families(node_results)

    return ClusterSynthesis(
        nodes_analyzed=int(nodes_analyzed),
        snapshot_hosts=int(snapshot_hosts),
        health_present_hosts=int(health_present_hosts),
        health_missing_hosts=int(snapshot_hosts - health_present_hosts),
        leader_endpoint=leader_endpoint,
        leaders_observed=leaders_observed,
        leader_stable=leader_stable,
        raft_term_min=raft_term_min,
        raft_term_max=raft_term_max,
        term_stable=term_stable,
        members_min=members_min,
        members_max=members_max,
        learners_max=learners_max,
        max_raft_index_drift=max_raft_index_drift,
        max_raft_applied_drift=max_raft_applied_drift,
        drift_warn_threshold=int(drift_warn_threshold),
        drift_concerning=drift_concerning,
        fastest_observed_ms=global_fastest,
        slowest_observed_ms=global_slowest,
        max_skew_ms=max_skew,
        max_ratio_vs_fastest=max_ratio,
        slow_threshold_ms=float(slow_threshold_ms),
        slow_endpoints=slow_endpoints_list,
        intermittent_slow_endpoints=intermittent,
        sustained_slow_endpoints=sustained,
        slow_significant_endpoints=significant,
        topology=topology,
        incident_families=incident_families,
        leader_host=leader_host,
    )


def _fmt_opt_float(v: Optional[float], decimals: int = 2) -> str:
    if v is None:
        return "(unknown)"
    try:
        return f"{float(v):.{decimals}f}"
    except Exception:
        return "(unknown)"


def print_cluster_synthesis_console(synth: ClusterSynthesis) -> None:
    print("=== etcd cluster synthesis ===")
    print()

    # --- Cluster overview paragraph (tight, clinical + light tint)
    leader_part = "unknown leader"
    if synth.leader_endpoint:
        if synth.leader_stable:
            leader_part = f"stable leader {synth.leader_endpoint}"
        else:
            leader_part = f"leader most observed: {synth.leader_endpoint}"
    term_part = ""
    if synth.raft_term_min is not None and synth.raft_term_max is not None:
        if synth.term_stable:
            term_part = f"RAFT term is stable (term={synth.raft_term_min})."
        else:
            term_part = f"RAFT term varies across snapshots (term={synth.raft_term_min}..{synth.raft_term_max})."

    drift_part = ""
    if synth.max_raft_index_drift is not None or synth.max_raft_applied_drift is not None:
        worst = max([d for d in [synth.max_raft_index_drift, synth.max_raft_applied_drift] if d is not None])
        if synth.drift_concerning:
            drift_part = f"Raft drift is elevated (worst drift={worst}, threshold={synth.drift_warn_threshold})."
        else:
            drift_part = f"Raft drift remains low (worst drift={worst})."

    slow_part = ""
    if synth.slow_significant_endpoints:
        n = len(synth.slow_significant_endpoints)
        slow_part = f"Intermittent slow endpoint-health latencies are observed on {n} member(s), suggesting transient stalls rather than sustained consensus failure."
    else:
        if synth.health_present_hosts > 0:
            slow_part = "No slow endpoint-health outliers were observed in the available snapshots."

    topo_part = ""
    if synth.topology.is_single_member and synth.topology.note:
        topo_part = synth.topology.note

    coverage_part = ""
    if synth.health_missing_hosts > 0:
        coverage_part = f"Health timing data is missing in {synth.health_missing_hosts}/{synth.snapshot_hosts} snapshot(s), so slow-endpoint detection may be incomplete."

    overview_sentences = [
        f"The etcd cluster appears logically healthy ({leader_part}); {term_part} {drift_part}".strip(),
        slow_part.strip(),
    ]
    if topo_part:
        overview_sentences.append(topo_part.strip())
    if coverage_part:
        overview_sentences.append(coverage_part.strip())

    print("Cluster overview:")
    print("  " + " ".join([s for s in overview_sentences if s]))
    print()

    # --- Cluster facts bullets
    print("Cluster facts:")
    print(f"  - Nodes analyzed: {synth.nodes_analyzed}")
    print(f"  - Nodes with etcd-status snapshots: {synth.snapshot_hosts}")
    print(f"  - Snapshots with health timings: {synth.health_present_hosts} (missing: {synth.health_missing_hosts})")

    if synth.leader_endpoint:
        if synth.leader_stable:
            print(f"  - Leader stability: consistent ({synth.leader_endpoint})")
        else:
            observed = ", ".join(sorted(list(synth.leaders_observed))[:4])
            if len(synth.leaders_observed) > 4:
                observed += ", …"
            print(f"  - Leader stability: varies (observed: {observed})")
            print(f"  - Leader most observed: {synth.leader_endpoint}")

    if synth.raft_term_min is not None and synth.raft_term_max is not None:
        if synth.term_stable:
            print(f"  - RAFT term: {synth.raft_term_min} (stable)")
        else:
            print(f"  - RAFT term range: {synth.raft_term_min} .. {synth.raft_term_max}")

    if synth.members_min is not None and synth.members_max is not None:
        if synth.members_min == synth.members_max:
            print(f"  - Members: {synth.members_min}")
        else:
            print(f"  - Members range: {synth.members_min} .. {synth.members_max}")
    if synth.learners_max is not None:
        print(f"  - Learners (max observed): {synth.learners_max}")

    if synth.max_raft_index_drift is not None or synth.max_raft_applied_drift is not None:
        print(f"  - Drift threshold: {synth.drift_warn_threshold} (concerning: {str(synth.drift_concerning).lower()})")
        if synth.max_raft_index_drift is not None:
            print(f"  - Max raft index drift observed: {synth.max_raft_index_drift}")
        if synth.max_raft_applied_drift is not None:
            print(f"  - Max raft applied drift observed: {synth.max_raft_applied_drift}")

    if synth.fastest_observed_ms is not None or synth.slowest_observed_ms is not None:
        print("  - Endpoint-health latency (ms):")
        print(f"      - fastest observed: {_fmt_opt_float(synth.fastest_observed_ms)}")
        print(f"      - slowest observed: {_fmt_opt_float(synth.slowest_observed_ms)}")
        if synth.max_skew_ms is not None:
            ratio_txt = ""
            if synth.max_ratio_vs_fastest is not None:
                ratio_txt = f" ({_fmt_opt_float(synth.max_ratio_vs_fastest, decimals=1)}× vs fastest)"
            print(f"      - max skew: {_fmt_opt_float(synth.max_skew_ms)} ms{ratio_txt}")

    if synth.slow_endpoints:
        print(f"  - Slow endpoints (> {int(synth.slow_threshold_ms)} ms):")
        for s in synth.slow_endpoints[:10]:
            seen = f"{s.slow_count}/{s.seen_count}"
            host_hint = ", ".join(s.slow_seen_on_hosts[:3]) + ("…" if len(s.slow_seen_on_hosts) > 3 else "")
            print(f"      - {s.endpoint} ({s.max_ms:.2f} ms; seen {seen}; on: {host_hint})")
    else:
        if synth.health_present_hosts > 0:
            print(f"  - Slow endpoints (> {int(synth.slow_threshold_ms)} ms): none observed")

    if synth.topology.is_single_member:
        print(f"  - Topology risk: single RAFT member observed (quorum candidates={synth.topology.quorum_candidate_count})")

    print()

    # --- Pattern analysis (clinical + light tint)
    print("Pattern analysis:")
    if synth.slow_significant_endpoints:
        if len(synth.slow_significant_endpoints) == 1:
            print("  - Latency spikes are isolated to a single member.")
        else:
            print(f"  - Latency spikes are isolated to {len(synth.slow_significant_endpoints)} members.")
    else:
        if synth.health_present_hosts > 0:
            print("  - No endpoint-health latency spikes above threshold were observed.")
        else:
            print("  - Endpoint-health timing data was not available; latency spike detection is incomplete.")

    if synth.intermittent_slow_endpoints:
        print("  - The same member(s) appear healthy in other snapshots, indicating intermittent stalls.")
    elif synth.sustained_slow_endpoints:
        print("  - Slow behavior appears sustained for at least one member across the available snapshots.")

    if synth.leader_stable and synth.leader_endpoint:
        print(f"  - Leader is consistent across snapshots ({synth.leader_endpoint}).")
    elif synth.leader_endpoint:
        print(f"  - Leader varies across snapshots (most observed: {synth.leader_endpoint}).")

    if synth.term_stable and synth.raft_term_min is not None:
        print(f"  - RAFT term is stable (term={synth.raft_term_min}).")
    elif synth.raft_term_min is not None and synth.raft_term_max is not None:
        print(f"  - RAFT term varies (term={synth.raft_term_min}..{synth.raft_term_max}).")

    if synth.max_raft_index_drift is not None or synth.max_raft_applied_drift is not None:
        worst = max([d for d in [synth.max_raft_index_drift, synth.max_raft_applied_drift] if d is not None])
        if synth.drift_concerning:
            print(f"  - Raft drift is elevated (worst drift={worst}, threshold={synth.drift_warn_threshold}).")
        else:
            print(f"  - No sustained raft lag is observed (worst drift={worst}).")

    if synth.health_missing_hosts > 0:
        print(f"  - Health latency data is missing in {synth.health_missing_hosts}/{synth.snapshot_hosts} snapshot(s).")

    if synth.topology.is_single_member:
        print("  - Only one RAFT member was observed in the available data.")

    print()

    # --- Overall interpretation (clinical + light tint)
    print("Overall interpretation:")
    parts: List[str] = []
    base_ok = (synth.leader_stable and synth.term_stable and not synth.drift_concerning)
    if base_ok:
        parts.append("The etcd cluster is operating in a logically healthy state, with stable consensus and consistent leadership.")
    else:
        parts.append("The etcd cluster shows signs of consensus instability or uneven progress across snapshots.")

    if synth.slow_significant_endpoints:
        if synth.intermittent_slow_endpoints:
            parts.append("However, intermittent performance degradation on one or more followers suggests short-lived resource contention rather than sustained cluster failure.")
        else:
            parts.append("However, sustained performance degradation on one or more members suggests ongoing contention or capacity issues.")

        parts.append("This pattern is consistent with short-lived resource contention (disk I/O pauses, CPU scheduling pressure, or transient network jitter) rather than immediate loss of quorum.")

    if synth.topology.is_single_member:
        parts.append("Only a single RAFT member was observed; this reduces fault tolerance and increases the risk of availability impact during any node interruption.")

    if synth.health_missing_hosts > 0:
        parts.append("Some snapshots lacked health timing data, so latency conclusions should be treated as best-effort.")

    print("  " + " ".join(parts))
    print()

    # --- Operational impact (operational)
    print("Operational impact:")
    if synth.topology.is_single_member:
        print("  - Single-member topology observed: if this endpoint becomes unavailable, quorum is lost and availability will be impacted.")
    if synth.slow_significant_endpoints:
        print("  - Intermittent slow members can amplify tail latency for linearizable reads and quorum-dependent operations, even when the cluster reports healthy.")
        if synth.slowest_observed_ms is not None and synth.max_skew_ms is not None and synth.max_ratio_vs_fastest is not None:
            print(f"  - Worst observed endpoint-health latency: {synth.slowest_observed_ms:.2f} ms (max skew {synth.max_skew_ms:.2f} ms, {synth.max_ratio_vs_fastest:.1f}× vs fastest).")
    # Tie to incident families (best-effort)
    fam = synth.incident_families
    if fam.read_path:
        print("  - Read-path incident signals are present; expect sensitivity in linearizable reads (ReadIndex) and higher tail latencies under load.")
    if fam.apply_path:
        print("  - Apply-path incident signals are present; apply latency spikes can stall writes and cascade into read pressure.")
    if fam.disk_timing:
        print("  - Disk/timing incident signals are present; short I/O stalls (e.g., fsync/fdatasync pauses) can produce bursty latency and heartbeat misses.")
    if fam.raft_election:
        print("  - RAFT/election signals are present; elections/leader transitions can occur during transient node pauses (e.g., scheduling stalls or vmotion-like events).")
    if fam.client_network:
        print("  - Client/network incident signals are present; connection churn or transport closures may surface as API timeouts and retries.")

    if not any([fam.read_path, fam.apply_path, fam.disk_timing, fam.raft_election, fam.client_network]) and not synth.slow_significant_endpoints and not synth.topology.is_single_member:
        print("  - No major operational risk signals were detected beyond baseline incident observations.")

    print()


def write_bundle_json(
    out_file: Path,
    bundle_root: Path,
    node_results: List[Dict[str, Any]],
    skipped_nodes: List[Dict[str, Any]],
    cluster_synth: Dict[str, Any],
    filters: Dict[str, Any],
) -> None:
    doc: Dict[str, Any] = {
        "schema_version": "v10",
        "bundle_root": str(bundle_root),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "filters": filters,
        "counts": {
            "nodes_total_seen": int(len(node_results) + len(skipped_nodes)),
            "nodes_analyzed": int(len(node_results)),
            "nodes_skipped": int(len(skipped_nodes)),
        },
        "skipped_nodes": skipped_nodes,
        "nodes": [],
        "cluster_synthesis": cluster_synth,
    }

    for r in node_results:
        node_obj = {
            "hostname": r.get("hostname"),
            "ip": r.get("ip"),
            "log_path": r.get("log_file"),
            "csv_path": r.get("csv_file"),
            "status_path": (r.get("etcd_status") or {}).get("path"),
            "etcd_status": r.get("etcd_status"),
            "incidents": r.get("incidents") or [],
            "events_count": r.get("events_count"),
            "windows_count": r.get("windows_count"),
        }
        doc["nodes"].append(node_obj)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=False)
        f.write("\n")


def main_single(
    log_path: str,
    output_dir: Path,
    date_filter: Optional[date] = None,
    days: Optional[int] = None,
    time_range: Optional[Tuple[datetime, datetime]] = None,
    levels: Optional[List[int]] = None,
    json_include_events: bool = False,
    status_path: Optional[Path] = None,
) -> int:
    """Single-log mode (v9 compatible, with optional explicit etcd-status path)."""
    path = Path(log_path)
    dsinfo_txt = path.parent.parent / "dsinfo.txt"
    csv_hostname = parse_node_hostname(dsinfo_txt) if dsinfo_txt.exists() else path.parent.parent.parent.name
    if not path.exists():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 2

    dsinfo_txt = path.parent.parent / "dsinfo.txt"
    csv_hostname = parse_node_hostname(dsinfo_txt) if dsinfo_txt.exists() else path.parent.parent.parent.name

    try:
        result = analyze_log_file(
            log_file=path,
            output_dir=output_dir,
            csv_hostname=csv_hostname,
            status_path=status_path,
            date_filter=date_filter,
            days=days,
            time_range=time_range,
            levels=levels,
            json_include_events=json_include_events,
        )
    except FileNotFoundError:
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 2

    json_path = output_dir / "etcd_analysis.json"

    write_incidents_json(
        out_file=json_path,
        log_file=path,
        incidents=result["windows"],
        date_filter=date_filter,
        days=(int(days) if days is not None else 0),
        levels=levels if levels is not None else [1, 2, 3, 4],
        include_events=json_include_events,
        etcd_status=result["etcd_status"],
    )


    print(f"Parsed {result['events_count']} events from: {path}")
    print(f"Wrote CSV: {result['csv_file']}")
    
    
    print(f"Wrote JSON: {json_path}")
    print()

    for i, w in enumerate(result["windows"], start=1):
        print(f"=== Incident Window {i} ===")
        print(window_summary(w))
        print()

    print_etcd_status_console(result["etcd_status"])
    return 0


def main_single_resolved(
    resolved: ResolvedInput,
    output_dir: Path,
    date_filter: Optional[date] = None,
    days: Optional[int] = None,
    time_range: Optional[Tuple[datetime, datetime]] = None,
    levels: Optional[List[int]] = None,
    json_include_events: bool = False,
    journal_raw_mode: str = "collapsed",
) -> int:
    """
    Single-node entry driven by resolved bundle input.
    Preserves the node eligibility rule:
      node skipped: no etcd-status.txt and no ucp-kv.log
    """
    has_status = resolved.status_path is not None and resolved.status_path.exists()
    has_log = resolved.log_file is not None and resolved.log_file.exists()
    has_journal = resolved.journal_path is not None and resolved.journal_path.exists()

    if not (has_status or has_log):
        print("node skipped: no etcd-status.txt and no ucp-kv.log", file=sys.stderr)
        return 2

    if has_log:
        return main_single(
            str(resolved.log_file),
            output_dir=output_dir,
            date_filter=date_filter,
            days=days,
            time_range=time_range,
            levels=levels,
            json_include_events=json_include_events,
            status_path=resolved.status_path,
        )

    # status-only node: still considered valid, but no incident log parsing is possible
    status_doc = load_etcd_status(resolved.status_path)
    print("No ucp-kv.log found for this node; rendering etcd-status only.\n")
    print_etcd_status_console(status_doc)

    if has_journal:
        jdoc = parse_journalctl_daemon_log(resolved.journal_path, time_range=time_range)
        print(render_journal_console(jdoc, raw_mode=journal_raw_mode), end="")

    json_path = output_dir / "etcd_analysis.json"
    status_only_doc: Dict[str, Any] = {
        "schema_version": "etcd_analysis.single_node.v1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "mode": "single_node",
        "status": "status_only",
        "source": {
            "input_path": str(resolved.input_path),
            "host_dir": str(resolved.host_dir) if resolved.host_dir else None,
            "dsinfo_dir": str(resolved.dsinfo_dir) if resolved.dsinfo_dir else None,
            "log_file": str(resolved.log_file) if resolved.log_file else None,
            "status_path": str(resolved.status_path) if resolved.status_path else None,
            "journal_path": str(resolved.journal_path) if resolved.journal_path else None,
        },
        "filters": {
            "date": date_filter.isoformat() if date_filter else None,
            "days": (int(days) if days is not None else None),
            "levels": list(levels) if levels is not None else [1, 2, 3, 4],
            "json_include_events": bool(json_include_events),
        },
        "note": "No ucp-kv.log available; status-only analysis performed.",
        "etcd_status": status_doc,
        "journal": jdoc if has_journal else {"missing": True},
        "incidents": [],
    }
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(status_only_doc, f, indent=2, sort_keys=False)
        f.write("\n")

    print(f"Wrote JSON: {json_path}")

    
    return 0



def _render_node_block(res: Dict[str, Any], banner: str, allowed_levels: Optional[Set[int]] = None, active_date: Optional[date] = None, active_days: Optional[int] = None, active_time_range: Optional[Tuple[datetime, datetime]] = None) -> str:
    """Render the existing per-node console output into a string block."""
    buf = io.StringIO()
    def w(line: str = "") -> None:
        buf.write(line + "\n")

    hostname = res.get("hostname") or "unknown"
    ip = res.get("ip") or "unknown"

    w(f"{banner} {{begin}}")

    # Optional refinement: Host context
    status = res.get("etcd_status") or {}
    status_present = not bool(status.get("missing"))
    role = "unknown"
    leader_ep = (status.get("parsed") or {}).get("leader_endpoint")
    if leader_ep and isinstance(leader_ep, str) and ip != "unknown":
        role = "leader" if ip in leader_ep else "follower"
    w("Host context:")
    w(f"  - etcd-status: {'present' if status_present else 'missing'}")
    w(f"  - role: {role}")
    log_present = bool(res.get("log_file"))
    w(f"  - ucp-kv.log: {'present' if log_present else 'missing'}")
    journal_doc = res.get("journal") or {}
    journal_present = not bool(journal_doc.get("missing"))
    w(f"  - journalctl_daemon.log: {'present' if journal_present else 'missing'}")
    w("")

    log_file = res.get("log_file")
    w(f"Parsed {res.get('events_count', 0)} events from: {log_file}")
    if res.get("csv_file"):
        w(f"Wrote CSV: {res.get('csv_file')}")
    w("")

    if res.get("error"):
        w("Analysis error:")
        w(f"  - {res.get('error')}")
        w("")

    # Apply interactive severity filter at render-time (allowed_levels is a set of ints 1-4).
    windows = res.get("windows") or []
    # Apply interactive time/date/days filters at render-time.
    # Convert all interactive filters into one concrete [start,end) range.
    filter_range: Optional[Tuple[datetime, datetime]] = None

    all_events = [e for win in windows for e in win]
    newest_ts = max((_naive_utc(e.ts) for e in all_events), default=None)

# debug section start
    if active_time_range is not None:
        dbg_start = _naive_utc(active_time_range[0])
        dbg_end = _naive_utc(active_time_range[1])
        first_ts = min((_naive_utc(e.ts) for e in all_events), default=None)
        last_ts = max((_naive_utc(e.ts) for e in all_events), default=None)
        w("DEBUG interactive time filter:")
        w(f"  - requested range: {dbg_start.isoformat()} -> {dbg_end.isoformat()}")
        w(f"  - node incident-event count: {len(all_events)}")
        w(f"  - first incident-event ts: {first_ts.isoformat() if first_ts else '(none)'}")
        w(f"  - last incident-event ts: {last_ts.isoformat() if last_ts else '(none)'}")
        sample_hits = [
            _naive_utc(e.ts).isoformat()
            for e in all_events
            if dbg_start <= _naive_utc(e.ts) < dbg_end
        ][:10]
        w(f"  - matching incident-event timestamps: {sample_hits if sample_hits else '[]'}")
        w("")

    raw_events = res.get("all_events") or []
    if active_time_range is not None:
        dbg_start = _naive_utc(active_time_range[0])
        dbg_end = _naive_utc(active_time_range[1])
        raw_hits = [
            _naive_utc(e.ts).isoformat()
            for e in raw_events
            if dbg_start <= _naive_utc(e.ts) < dbg_end
        ][:10]
        w("DEBUG raw parsed events:")
        w(f"  - raw parsed-event count: {len(raw_events)}")
        w(f"  - matching raw parsed-event timestamps: {raw_hits if raw_hits else '[]'}")
        w("")
# debug section end

    if active_time_range is not None:
        filter_range = (
            _naive_utc(active_time_range[0]),
            _naive_utc(active_time_range[1]),
        )
    elif active_date is not None:
        # Date filter means the whole selected calendar day.
        # If active_days is set too, expand to ±N calendar days around that date.
        day_span = int(active_days) if (active_days is not None and active_days >= 0) else 0
        start = datetime.combine(active_date - timedelta(days=day_span), time(0, 0, 0))
        end = datetime.combine(active_date + timedelta(days=day_span) + timedelta(days=1), time(0, 0, 0))
        filter_range = (start, end)
    elif active_days is not None and active_days > 0 and newest_ts is not None:
        # Relative window from newest event seen for this node.
        filter_range = (newest_ts - timedelta(days=int(active_days)), newest_ts + timedelta(seconds=1))

    if filter_range is not None:
        start, end = filter_range
        filtered_by_time: List[List[Event]] = []
        for win in windows:
            fwin = [e for e in win if start <= _naive_utc(e.ts) < end]
            if fwin:
                filtered_by_time.append(fwin)
        windows = filtered_by_time
    if allowed_levels:
        level_to_sev = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
        allowed_sev = {level_to_sev[l] for l in allowed_levels if l in level_to_sev}
    else:
        allowed_sev = None  # type: ignore

    filtered_windows: List[List[Event]] = []
    for win in windows:
        if allowed_sev is None:
            fwin = list(win)
        else:
            fwin = [e for e in win if e.severity in allowed_sev]
        if fwin:
            filtered_windows.append(fwin)

    for i, win in enumerate(filtered_windows, start=1):
        w(f"=== Incident Window {i} ===")
        w(window_summary(win).rstrip())
        w("")

    # etcd-status (interpreted + raw) uses existing printer; capture by calling helper that returns strings?
    # Here we replicate by temporarily redirecting stdout-like behavior:
    # We'll call a new helper that returns strings by using print-style into buf.
    # To avoid re-plumbing, we reproduce minimal lines via existing data using the same formatting logic.
    # Easiest: invoke print_etcd_status_console but monkeypatch print via local write.
    # We'll implement a small internal rendering wrapper here.
    etcd_txt = _render_etcd_status_console_text(status)
    if etcd_txt:
        buf.write(etcd_txt)
        if not etcd_txt.endswith("\n"):
            buf.write("\n")

    w(f"{banner} {{end}}")
    w("")
    return buf.getvalue()



def _render_two_column_table(lines: List[str]) -> str:
    """Render a simple 2-column bordered table from pre-formatted cell strings."""
    if not lines:
        return ""
    col_w = max(len(s) for s in lines)
    col_w = max(col_w, 24)
    # Add some breathing room inside cells
    inner_w = col_w + 2
    border = "+" + ("-" * inner_w) + "+" + ("-" * inner_w) + "+"

    out = io.StringIO()
    out.write(border + "\n")
    i = 0
    while i < len(lines):
        left = lines[i]
        right = lines[i + 1] if i + 1 < len(lines) else ""
        out.write("| " + left.ljust(col_w) + " | " + right.ljust(col_w) + " |\n")
        i += 2
    out.write(border + "\n")
    return out.getvalue()

def _render_node_journal_block(res: Dict[str, Any], banner: str, journal_raw_mode: str = "collapsed") -> str:
    """Render per-node journalctl_daemon.log analysis into a string block."""
    buf = io.StringIO()

    def w(line: str = "") -> None:
        buf.write(line + "\n")

    w(f"{banner} {{begin}}\n")
    w(render_journal_console(res.get("journal") or {}, raw_mode=journal_raw_mode).rstrip())
    w(f"{banner} {{end}}\n")
    return buf.getvalue()

def _derive_time_range_for_filters(
    *,
    active_date: Optional[date],
    active_days: Optional[int],
    active_time_range: Optional[Tuple[datetime, datetime]],
    newest_ts: Optional[datetime] = None,
) -> Optional[Tuple[datetime, datetime]]:
    """Convert interactive filters into a concrete [start,end) datetime range.

    Precedence: active_time_range > active_date > active_days > None.
    For active_days, newest_ts must be provided (relative window).
    """
    if active_time_range is not None:
        return active_time_range
    if active_date is not None:
        start = datetime.combine(active_date, time(0, 0, 0))
        end = start + timedelta(days=1)
        return (start, end)
    if active_days is not None and active_days > 0 and newest_ts is not None:
        start = newest_ts - timedelta(days=int(active_days))
        end = newest_ts + timedelta(seconds=1)
        return (start, end)
    return None


def _derive_time_range_for_journal_path(
    journal_path: Path,
    *,
    active_date: Optional[date],
    active_days: Optional[int],
    active_time_range: Optional[Tuple[datetime, datetime]],
) -> Optional[Tuple[datetime, datetime]]:
    """Derive a time range for filtering journal lines, scanning for newest_ts when needed."""
    if active_time_range is not None or active_date is not None:
        return _derive_time_range_for_filters(
            active_date=active_date,
            active_days=None,
            active_time_range=active_time_range,
            newest_ts=None,
        )
    if active_days is None or active_days <= 0:
        return None

    newest: Optional[datetime] = None
    try:
        with journal_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                ts, _ = _extract_journal_ts_and_rest(line.rstrip("\n"))
                if ts is None:
                    continue
                if newest is None or ts > newest:
                    newest = ts
    except Exception:
        newest = None

    return _derive_time_range_for_filters(
        active_date=None,
        active_days=active_days,
        active_time_range=None,
        newest_ts=newest,
    )


def _render_node_etcd_status_raw_block(res: Dict[str, Any], banner: str) -> str:
    """Render per-node etcd-status.txt raw-only display into a string block (interactive [E] view)."""
    buf = io.StringIO()

    def w(line: str = "") -> None:
        buf.write(line + "\n")

    hostname = res.get("hostname") or "unknown"
    ip = res.get("ip") or "unknown"
    w(f"{banner} {{begin}}\n")
    w(_render_etcd_status_raw_display_text(res.get("etcd_status") or {}).rstrip())
    w(f"{banner} {{end}}\n")
    return buf.getvalue()

def _write_text_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class InteractiveTranscriptWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("w", encoding="utf-8")
        self._closed = False

    def write(self, text: str) -> None:
        if self._closed:
            return
        self._fh.write(text)
        self._fh.flush()

    def writeln(self, text: str = "") -> None:
        self.write(text + "\n")

    def close(self) -> None:
        if self._closed:
            return
        self._fh.close()
        self._closed = True


def _capture_cluster_synthesis_text(cluster_synth: ClusterSynthesis) -> str:
    buf = io.StringIO()
    old_stdout = sys.stdout
    try:
        sys.stdout = buf
        print_cluster_synthesis_console(cluster_synth)
    finally:
        sys.stdout = old_stdout
    return buf.getvalue()


def _render_bundle_markdown_report(
    *,
    bundle_root: Path,
    cluster_synth: ClusterSynthesis,
    node_results: List[Dict[str, Any]],
    skipped_nodes: List[Dict[str, Any]],
    date_filter: Optional[date],
    days: Optional[int],
    time_range: Optional[Tuple[datetime, datetime]],
    levels: Optional[List[int]],
    journal_raw_mode: str,
) -> str:
    parts: List[str] = []

    parts.append("# ETCD Analysis Report")
    parts.append("")
    parts.append(f"- Bundle root: `{bundle_root}`")
    parts.append(f"- Nodes analyzed: `{len(node_results)}`")
    parts.append(f"- Skipped nodes: `{len(skipped_nodes)}`")
    parts.append("")

    parts.append("## Filters")
    parts.append("")
    parts.append(f"- Date: `{date_filter.isoformat() if date_filter else 'none'}`")
    parts.append(f"- Days: `{days if days is not None else 'none'}`")
    parts.append(f"- Levels: `{','.join(str(x) for x in levels) if levels else '1,2,3,4'}`")
    if time_range is None:
        parts.append("- Time range: `none`")
    else:
        parts.append(f"- Time range: `{time_range[0].isoformat()} -> {time_range[1].isoformat()}`")
    parts.append("")

    parts.append("## Cluster Synthesis")
    parts.append("")
    parts.append("```text")
    parts.append(_capture_cluster_synthesis_text(cluster_synth).rstrip())
    parts.append("```")
    parts.append("")

    for res in node_results:
        hostname = res.get("hostname") or "unknown"
        ip = res.get("ip") or "unknown"
        banner = f"========== {hostname} ({ip}) =========="

        parts.append(f"## Node: {hostname}")
        parts.append("")
        parts.append("```text")
        parts.append(_render_node_block(res, banner).rstrip())
        parts.append("```")
        parts.append("")

        journal_block = _render_node_journal_block(
            res,
            banner,
            journal_raw_mode=journal_raw_mode,
        ).rstrip()
        if journal_block:
            parts.append(f"### Journal: {hostname}")
            parts.append("")
            parts.append("```text")
            parts.append(journal_block)
            parts.append("```")
            parts.append("")

    if skipped_nodes:
        parts.append("## Skipped Nodes")
        parts.append("")
        for item in skipped_nodes:
            hostname = item.get("hostname") or "unknown"
            reason = item.get("reason") or "unknown"
            parts.append(f"- `{hostname}` — {reason}")
        parts.append("")

    return "\n".join(parts).rstrip() + "\n"

def _render_etcd_status_console_text(etcd_status: Dict[str, Any]) -> str:
    """Return the same etcd-status console block as print_etcd_status_console(), but as text."""
    buf = io.StringIO()
    # Reuse existing formatting by replicating the print logic in a controlled way.
    # (This avoids restructuring the original function to accept a file-like.)
    if not etcd_status:
        return ""
    if etcd_status.get("missing"):
        buf.write("=== etcd-status.txt ===\n")
        buf.write("(missing)\n\n")
        return buf.getvalue()

    parsed = etcd_status.get("parsed", {}) or {}
    metrics = etcd_status.get("metrics", {}) or {}
    raw = ((etcd_status.get("raw_text") or etcd_status.get("raw") or ""))

    buf.write("=== etcd-status.txt (interpreted) ===\n")
    leader = parsed.get("leader_endpoint") or "unknown"
    term = metrics.get("leader_raft_term")
    if term is not None:
        buf.write(f"Leader: {leader}  (term={term})\n")
    else:
        buf.write(f"Leader: {leader}\n")

    m = metrics.get("members_count")
    l = metrics.get("learners_count")
    if m is not None:
        buf.write(f"Members: {m}")
        if l is not None:
            buf.write(f"  |  Learners: {l}")
        buf.write("\n")

    # Health
    if metrics.get("health_min_ms") is not None:
        buf.write("Health latency (ms):\n")
        buf.write(f"   fastest: {metrics.get('health_min_ms'):.2f}\n")
        buf.write(f"   slowest: {metrics.get('health_max_ms'):.2f}\n")
        skew = metrics.get("health_skew_ms")
        ratio = metrics.get("health_ratio_vs_fastest")
        if skew is not None:
            if ratio is not None:
                buf.write(f"   skew: {skew:.2f} ms  ({ratio:.1f}× vs fastest)\n")
            else:
                buf.write(f"   skew: {skew:.2f} ms\n")
    else:
        buf.write("Health latency (ms):\n")
        buf.write("   (unknown — no health timings parsed)\n")

    # Slow endpoints
    over = metrics.get("slow_endpoints_over_threshold") or []
    thr = metrics.get("slow_threshold_ms", 110)
    if over:
        buf.write(f"Slow endpoint(s) (> {int(thr)} ms):\n")
        for item in over:
            ep = item.get("endpoint")
            ms = item.get("took_ms")
            if ep and isinstance(ms, (int, float)):
                buf.write(f"   - {ep} ({float(ms):.2f} ms)\n")
            elif ep:
                buf.write(f"   - {ep} (unknown ms)\n")
    else:
        buf.write(f"Slow endpoint(s) (> {int(thr)} ms): none\n")

    # Drift
    rid = metrics.get("raft_index_drift")
    aid = metrics.get("raft_applied_index_drift")
    if rid is not None or aid is not None:
        buf.write("Raft drift:\n")
        if rid is not None:
            buf.write(f"   index drift: {rid}\n")
        if aid is not None:
            buf.write(f"   applied drift: {aid}\n")

    buf.write("\n")
    buf.write("=== etcd-status.txt (raw) ===\n")
    if raw:
        buf.write(raw.rstrip() + "\n\n")
    else:
        buf.write("(raw text unavailable)\n\n")
    return buf.getvalue()

def _render_etcd_status_raw_display_text(etcd_status: Dict[str, Any]) -> str:
    """Raw-only display for etcd-status.txt (interactive [E] view)."""
    buf = io.StringIO()
    buf.write("=== etcd-status.txt display ===\n")
    if not etcd_status or etcd_status.get("missing"):
        buf.write("No etcd-status.txt found for this node.\n\n")
        return buf.getvalue()
    raw = ((etcd_status.get("raw_text") or etcd_status.get("raw") or "")).rstrip()
    if raw:
        buf.write(raw + "\n\n")
    else:
        buf.write("(empty)\n\n")
    return buf.getvalue()



# -----------------------
# journalctl_daemon.log support (v16)
# -----------------------

# Timestamp extraction:
# journalctl_daemon.log can contain several timestamp styles:
#   1) Leading RFC3339: 2026-01-28T07:49:17.919171Z <rest>
#   2) Leading RFC3339 with offset: 2026-01-28T06:26:13.392604992+01:00 <rest>
#   3) Docker-style key: time="2026-01-28T06:26:13.392604992+01:00" <rest>
_JOURNAL_LEADING_TS_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(?P<rest>.*)$'
)
_JOURNAL_TIME_KV_RE = re.compile(r'^time="(?P<ts>[^"]+)"\s+(?P<rest>.*)$')

def _parse_rfc3339(ts: str) -> Optional[datetime]:
    """Parse RFC3339-ish timestamp into an aware datetime (UTC)."""
    try:
        # Normalize trailing Z -> +00:00 for fromisoformat
        t = ts.strip()
        if t.endswith("Z"):
            # trim Z for fractional normalization, then force UTC
            core = t[:-1]
            tz = timezone.utc
        else:
            core = t
            tz = None

        # Truncate fractional seconds to microseconds for datetime compatibility.
        if "." in core:
            base, frac = core.split(".", 1)
            frac = re.sub(r'[^0-9]', '', frac)
            frac = (frac + "000000")[:6]
            core2 = f"{base}.{frac}"
        else:
            core2 = core

        dt = datetime.fromisoformat(core2)
        # If original had Z, force UTC; if it had offset, normalize to UTC.
        if tz is not None:
            dt = dt.replace(tzinfo=tz)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def _extract_journal_ts_and_rest(line: str) -> Tuple[Optional[datetime], str]:
    """Return (timestamp, rest_of_line) best-effort."""
    m = _JOURNAL_LEADING_TS_RE.match(line)
    if m:
        ts = _parse_rfc3339(m.group("ts"))
        return ts, m.group("rest")
    m = _JOURNAL_TIME_KV_RE.match(line)
    if m:
        ts = _parse_rfc3339(m.group("ts"))
        return ts, m.group("rest")
    return None, line

# Signal patterns (high-value, bounded scope)
LEGACY_JOURNAL_SIGNAL_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    # kind, regex, default severity
    ("swarm_no_leader", re.compile(r"swarm does not have a leader", re.IGNORECASE), "CRITICAL"),
    ("deadline_exceeded", re.compile(r"(DeadlineExceeded|context deadline exceeded)", re.IGNORECASE), "HIGH"),
    ("no_route_to_host", re.compile(r"no route to host", re.IGNORECASE), "HIGH"),
    ("connection_refused", re.compile(r"connection refused", re.IGNORECASE), "HIGH"),
    ("dns_no_such_host", re.compile(r"lookup .* no such host", re.IGNORECASE), "MEDIUM"),
    ("memberlist_refuting", re.compile(r"memberlist:.*Refuting", re.IGNORECASE), "MEDIUM"),
    ("networkdb_connectivity_issues", re.compile(r"NetworkDB stats.*healthscore", re.IGNORECASE), "MEDIUM"),
    ("agent_session_failed", re.compile(r"agent: session failed", re.IGNORECASE), "HIGH"),
    # etcd client / grpc-ish
    ("etcd_rpc_unavailable", re.compile(r'logger":"etcd-client"|"logger"\s*:\s*"etcd-client"', re.IGNORECASE), "HIGH"),
    ("grpc_transport_closing", re.compile(r"transport is closing", re.IGNORECASE), "MEDIUM"),
]
_JOURNAL_SIGNAL_PATTERNS: List[Tuple[str, re.Pattern, str]] = list(LEGACY_JOURNAL_SIGNAL_PATTERNS)
_IPPORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})")
_HTTPS_EP_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}")

def _journal_signature_normalize(line: str) -> str:
    """Normalize a raw journal line into a stable signature for repetition grouping."""
    s = line
    # Strip common time prefix forms
    s = re.sub(r'^time="[^"]+"\s+', '', s)
    s = re.sub(r'^\d{4}-\d{2}-\d{2}T[0-9:\.]+(?:Z|[+-]\d{2}:\d{2})\s+', '', s)

    # Collapse endpoints / addresses
    s = re.sub(r'https?://\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}', '<endpoint>', s)
    s = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b', '<ip:port>', s)
    s = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', '<ip>', s)

    # Collapse retry backoff numbers
    s = re.sub(r'(retrying in )\d+\w', r'\1<n>', s)

    # Collapse standalone numbers (keep it late so ports already collapsed)
    s = re.sub(r'\b\d+\b', '<n>', s)

    # Whitespace normalize
    s = re.sub(r'\s+', ' ', s).strip()
    # Keep signatures bounded
    if len(s) > 180:
        s = s[:177] + "..."
    return s


def _journal_signature_label(kind: str, normalized: str) -> str:
    """Human-friendly label for a signature group."""
    n = normalized.lower()
    if "pxd.sock" in n:
        return "docker_plugin_pxd_sock_refused"
    if "/run/docker/plugins" in n and "plugin.activate" in n and "refused" in n:
        return "docker_plugin_activate_refused"
    if kind == "swarm_no_leader":
        return "swarm_no_leader"
    if kind == "deadline_exceeded":
        return "deadline_exceeded"
    if kind == "no_route_to_host":
        return "no_route_to_host"
    if kind == "connection_refused":
        return "connection_refused"
    if kind == "etcd_rpc_unavailable":
        return "etcd_rpc_unavailable"
    return kind


def parse_journalctl_daemon_log(journal_path: Optional[Path], time_range: Optional[Tuple[datetime, datetime]] = None) -> Dict[str, Any]:
    """Parse journalctl_daemon.log best-effort and extract etcd-relevant signals.
    Returns a document with:
      - missing flag
      - path
      - metrics: time window, counts, targets, signature groups
      - raw_matches: matched lines only (verbatim)
    """
    if journal_path is None or (not journal_path.exists()) or (not journal_path.is_file()):
        return {"missing": True, "path": str(journal_path) if journal_path else "journalctl_daemon.log"}

    raw_matches: List[str] = []
    counts: Dict[str, int] = {}
    targets: Dict[str, List[str]] = {}
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None

    # Signature groups (for summarizing repetitive patterns)
    sig_counts: Dict[str, int] = {}
    sig_first_ts: Dict[str, datetime] = {}
    sig_last_ts: Dict[str, datetime] = {}
    sig_kind: Dict[str, str] = {}
    sig_label: Dict[str, str] = {}
    sig_retry_intervals: Dict[str, Set[str]] = {}

    def add_target(kind: str, t: str) -> None:
        if kind not in targets:
            targets[kind] = []
        if t not in targets[kind]:
            targets[kind].append(t)

    try:
        with journal_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                ln = line.rstrip("\n")
                ts, rest = _extract_journal_ts_and_rest(ln)
                if time_range is not None and ts is not None:
                    if ts < time_range[0] or ts >= time_range[1]:
                        continue

                # If the line is JSON and includes a timestamp field, prefer it
                # (common keys: ts, time).
                # This helps when the leading prefix isn't parseable.


                # Try JSON decode if it looks like JSON
                msg_text = rest
                if rest.lstrip().startswith("{"):
                    try:
                        obj = json.loads(rest)
                        if ts is None:
                            ts_val = None
                            if isinstance(obj.get("ts"), str):
                                ts_val = obj.get("ts")
                            elif isinstance(obj.get("time"), str):
                                ts_val = obj.get("time")
                            if ts_val:
                                ts = _parse_rfc3339(ts_val)
                        msg_text = " ".join(
                            str(v) for v in obj.values() if isinstance(v, (str, int, float, bool))
                        )
                    except Exception:
                        msg_text = rest

                kind_hit: Optional[str] = None
                for kind, rx, default_sev in _JOURNAL_SIGNAL_PATTERNS:
                    if rx.search(msg_text):
                        kind_hit = kind
                        break

                # Specialize etcd_rpc_unavailable: require Unavailable/EOF/etcd target when possible
                if kind_hit == "etcd_rpc_unavailable":
                    if not re.search(r"rpc error|Unavailable|EOF", msg_text, re.IGNORECASE):
                        continue

                if kind_hit:
                    raw_matches.append(ln)
                    counts[kind_hit] = counts.get(kind_hit, 0) + 1

                    if ts:
                        first_ts = ts if first_ts is None else min(first_ts, ts)
                        last_ts = ts if last_ts is None else max(last_ts, ts)

                    # Extract targets (best-effort)
                    for ep in _HTTPS_EP_RE.findall(ln):
                        add_target(kind_hit, ep)
                    for ip, port in _IPPORT_RE.findall(ln):
                        add_target(kind_hit, f"{ip}:{port}")

                    # Signature grouping
                    norm = _journal_signature_normalize(ln)
                    sig = f"{kind_hit}|{norm}"
                    sig_counts[sig] = sig_counts.get(sig, 0) + 1
                    sig_kind[sig] = kind_hit
                    sig_label[sig] = _journal_signature_label(kind_hit, norm)
                    if ts:
                        if sig not in sig_first_ts:
                            sig_first_ts[sig] = ts
                            sig_last_ts[sig] = ts
                        else:
                            sig_first_ts[sig] = min(sig_first_ts[sig], ts)
                            sig_last_ts[sig] = max(sig_last_ts[sig], ts)

                    # Track retry intervals for backoff hint
                    rm = re.search(r"retrying in (\d+\w)", ln)
                    if rm:
                        if sig not in sig_retry_intervals:
                            sig_retry_intervals[sig] = set()
                        sig_retry_intervals[sig].add(rm.group(1))
    except Exception as e:
        return {"missing": False, "path": str(journal_path), "error": str(e), "raw_matches": raw_matches, "metrics": {}}

    # Sort targets lists for determinism
    for k in list(targets.keys()):
        targets[k].sort()

    # Build signature summary list (sorted by count desc)
    sig_summary = []
    for sig, cnt in sig_counts.items():
        ft = sig_first_ts.get(sig)
        lt = sig_last_ts.get(sig)
        intervals = sorted(list(sig_retry_intervals.get(sig, set())))
        sig_summary.append(
            {
                "signature": sig,
                "kind": sig_kind.get(sig),
                "label": sig_label.get(sig) or sig_kind.get(sig),
                "count": cnt,
                "first_ts": ft.isoformat() if ft else None,
                "last_ts": lt.isoformat() if lt else None,
                "retry_intervals": intervals,
            }
        )
    sig_summary.sort(key=lambda d: (-int(d.get("count", 0)), str(d.get("label", ""))))

    metrics = {
        "first_ts": first_ts.isoformat() if first_ts else None,
        "last_ts": last_ts.isoformat() if last_ts else None,
        "signal_counts": counts,
        "signal_targets": targets,
        "matched_lines": len(raw_matches),
        "signature_summary": sig_summary,
    }
    return {"missing": False, "path": str(journal_path), "metrics": metrics, "raw_matches": raw_matches}

def render_journal_console(jdoc: Dict[str, Any], raw_mode: str = "collapsed") -> str:
    """Render journalctl analysis to console text.
    raw_mode:
      - "all": print every matched line
      - "collapsed": group repetitive signatures and show first/last samples
      - "none": suppress raw matched lines section
    """
    buf = io.StringIO()
    buf.write("=== journalctl_daemon.log (interpreted) ===\n")
    if not jdoc or jdoc.get("missing"):
        p = (jdoc or {}).get("path", "journalctl_daemon.log")
        buf.write(f"(missing) Could not find: {p}\n\n")
        return buf.getvalue()

    metrics = jdoc.get("metrics", {}) or {}
    first_ts = metrics.get("first_ts")
    last_ts = metrics.get("last_ts")
    counts = metrics.get("signal_counts", {}) or {}
    targets = metrics.get("signal_targets", {}) or {}
    sig_summary = metrics.get("signature_summary", []) or []

    if first_ts or last_ts:
        buf.write(f"Time window: {first_ts or '?'}  ->  {last_ts or '?'}\n")

    # Top repeating patterns (signature-level)
    top = [s for s in sig_summary if int(s.get("count") or 0) >= 3]
    if top:
        buf.write("Top repeating patterns:\n")
        for s in top[:5]:
            label = s.get("label") or (s.get("kind") or "unknown")
            cnt = int(s.get("count") or 0)
            ft = s.get("first_ts") or "?"
            lt = s.get("last_ts") or "?"
            buf.write(f"  - {label}: {cnt} hits\n")
            buf.write(f"      first: {ft}\n")
            buf.write(f"      last:  {lt}\n")
            intervals = s.get("retry_intervals") or []
            if intervals and len(intervals) > 1:
                shown = "→".join(intervals[:4]) + ("→..." if len(intervals) > 4 else "")
                buf.write(f"      pattern: backoff observed ({shown})\n")
    # Kind-level rollup
    if counts:
        buf.write("Signals:\n")
        for kind, cnt in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            buf.write(f"  - {kind}: {cnt}\n")
            t = targets.get(kind) or []
            if t:
                shown = ", ".join(t[:5])
                more = f" (+{len(t)-5} more)" if len(t) > 5 else ""
                buf.write(f"    targets: {shown}{more}\n")
    else:
        buf.write("Signals: none (no high-value patterns matched)\n")

    buf.write("\n")
    buf.write("=== journalctl_daemon.log (raw matches) ===\n")

    if raw_mode == "none":
        buf.write("(suppressed; use --journal-raw=all to print)\n\n")
        return buf.getvalue()

    raw = jdoc.get("raw_matches") or []
    if not raw:
        buf.write("(no matched lines)\n\n")
        return buf.getvalue()

    if raw_mode == "all":
        for ln in raw:
            buf.write(ln.rstrip() + "\n")
        buf.write("\n")
        return buf.getvalue()

    # collapsed (default): group by signature and show first/last samples
    # Build groups based on the stored signature_summary ordering.
    # We re-derive signature keys (kind|normalized) deterministically.
    groups: Dict[str, List[str]] = {}
    for ln in raw:
        # Determine kind by re-running match (cheap, and avoids storing per-line kind)
        ts2, rest2 = _extract_journal_ts_and_rest(ln)
        msg_text = rest2
        kind_hit = None
        for kind, rx, default_sev in _JOURNAL_SIGNAL_PATTERNS:
            if rx.search(msg_text):
                kind_hit = kind
                break
        if kind_hit == "etcd_rpc_unavailable":
            if not re.search(r"rpc error|Unavailable|EOF", msg_text, re.IGNORECASE):
                continue
        if not kind_hit:
            continue
        norm = _journal_signature_normalize(ln)
        sig = f"{kind_hit}|{norm}"
        groups.setdefault(sig, []).append(ln)

    # Order groups by count desc using signature_summary if available
    order = [s.get("signature") for s in sig_summary if s.get("signature") in groups]
    # Add any groups not in summary (shouldn't happen, but safe)
    for sig in sorted(groups.keys()):
        if sig not in order:
            order.append(sig)

    for sig in order:
        lines = groups.get(sig) or []
        if not lines:
            continue
        # Lookup label/count
        label = None
        cnt = len(lines)
        for s in sig_summary:
            if s.get("signature") == sig:
                label = s.get("label") or s.get("kind")
                cnt = int(s.get("count") or cnt)
                break
        label = label or sig.split("|", 1)[0]
        buf.write(f"[{label}: {cnt} hits | showing first 2, last 2]\n")
        head = lines[:2]
        tail = lines[-2:] if len(lines) > 2 else []
        for ln in head:
            buf.write(f"  {ln.rstrip()}\n")
        if len(lines) > 4:
            buf.write("  ...\n")
        for ln in tail:
            buf.write(f"  {ln.rstrip()}\n")
        suppressed = max(0, len(lines) - (len(head) + len(tail)))
        if suppressed > 0:
            buf.write(f"(+{suppressed} more suppressed)\n")
        buf.write("\n")

    return buf.getvalue()





def main_bundle(
    bundle_root: Path,
    output_dir: Path,
    date_filter: Optional[date] = None,
    days: Optional[int] = None,
    time_range: Optional[Tuple[datetime, datetime]] = None,
    levels: Optional[List[int]] = None,
    json_include_events: bool = False,
    interactive: bool = False,
    journal_raw_mode: str = "collapsed",
) -> int:
    nodes, skipped = scan_bundle(bundle_root)
    if not nodes:
        print(f"No RAFT member candidates found under: {bundle_root}")
        if skipped:
            print(f"Skipped {len(skipped)} node(s). Example: {skipped[0]}")
        return 0

    node_results: List[Dict[str, Any]] = []
    node_blocks: Dict[str, str] = {}
    journal_blocks: Dict[str, str] = {}
    status_raw_blocks: Dict[str, str] = {}
    res_by_host: Dict[str, Dict[str, Any]] = {}

    transcript_writer: Optional[InteractiveTranscriptWriter] = None
    transcript_path: Optional[Path] = None

    # In interactive mode we keep parsing/analysis unfiltered so that date/days/time
    # can be adjusted at render-time without re-reading logs.
    analysis_date_filter = None if interactive else date_filter
    analysis_days = None if interactive else days
    analysis_time_range = None if interactive else time_range

    if interactive:
        transcript_path = output_dir / "interactive_transcript.md"
        transcript_writer = InteractiveTranscriptWriter(transcript_path)
        transcript_writer.writeln("# Interactive ETCD Transcript")
        transcript_writer.writeln("")
        transcript_writer.writeln(f"- Bundle root: `{bundle_root}`")
        transcript_writer.writeln("")

    def emit(text: str = "", *, end: str = "\n") -> None:
        print(text, end=end)
        if transcript_writer is not None:
            transcript_writer.write(text)
            transcript_writer.write(end)

    def record_input(prompt: str, value: str) -> None:
        if transcript_writer is None:
            return
        transcript_writer.write(prompt)
        transcript_writer.write(value)
        transcript_writer.write("\n")

    def emit_cluster_synthesis() -> None:
        text = _capture_cluster_synthesis_text(cluster_synth)
        print(text, end="")
        if transcript_writer is not None:
            transcript_writer.writeln("## Cluster Synthesis")
            transcript_writer.writeln("")
            transcript_writer.writeln("```text")
            transcript_writer.write(text)
            if not text.endswith("\n"):
                transcript_writer.writeln("")
            transcript_writer.writeln("```")
            transcript_writer.writeln("")

    for node in nodes:

        hostname = node["hostname"]
        ip = node.get("ip") or "unknown"
        banner = f"========== {hostname} ({ip}) =========="

        log_path = node.get("log_path")
        status_path_s = node.get("status_path")
        journal_path_s = node.get("journal_path")

        log_file = Path(log_path) if log_path else None
        status_path = Path(status_path_s) if status_path_s else None
        journal_path = Path(journal_path_s) if journal_path_s else None

        # 1) Analyze ucp-kv.log if present
        if log_file is not None and log_file.exists():
            try:
                res = analyze_log_file(
                    log_file=log_file,
                    output_dir=output_dir,
                    csv_hostname=hostname,
                    status_path=status_path,
                    date_filter=analysis_date_filter,
                    days=analysis_days,
                    time_range=analysis_time_range,
                    levels=levels,
                    json_include_events=json_include_events,
                )
            except Exception as e:
                partial_status = load_etcd_status(status_path)
                res = {
                    "log_file": str(log_file),
                    "csv_file": None,
                    "events_count": 0,
                    "windows_count": 0,
                    "incidents": [],
                    "windows": [],
                    "etcd_status": partial_status,
                    "filters": {
                        "date": date_filter.isoformat() if date_filter else None,
                        "days": (int(days) if days is not None else None),
                        "levels": list(levels) if levels is not None else [1, 2, 3, 4],
                        "json_include_events": bool(json_include_events),
                    },
                    "error": str(e),
                }
        else:
            # No etcd log present (etcd may be dead); still allow status/journal context
            res = {
                "log_file": str(log_file) if log_file else None,
                "csv_file": None,
                "events_count": 0,
                "windows_count": 0,
                "incidents": [],
                "windows": [],
                "etcd_status": load_etcd_status(status_path),
                "filters": {
                    "date": date_filter.isoformat() if date_filter else None,
                    "days": (int(days) if days is not None else None),
                    "levels": list(levels) if levels is not None else [1, 2, 3, 4],
                    "json_include_events": bool(json_include_events),
                },
                "note": "ucp-kv.log missing; etcd incident analysis skipped",
            }

        # 2) Attach journal analysis (always computed if file present)
        res["journal"] = parse_journalctl_daemon_log(journal_path, time_range=analysis_time_range)

        # 3) Attach node identity
        res["hostname"] = hostname
        res["ip"] = node.get("ip")
        # 4) Node role flags from etcd-status endpoint status (best-effort, primary mapping: match host IP)
        node_ip = (res.get("ip") or "") if isinstance(res.get("ip"), str) else ""
        is_leader = None
        is_learner = None
        st = res.get("etcd_status") or {}
        if node_ip and (not st.get("missing")):
            es = (st.get("parsed") or {}).get("endpoint_status") or []
            for row in es:
                ep = str(row.get("endpoint") or "")
                if node_ip and node_ip in ep:
                    is_leader = bool(row.get("is_leader"))
                    is_learner = bool(row.get("is_learner"))
                    break
        res["node_is_leader"] = is_leader
        res["node_is_learner"] = is_learner
        res["journal_path"] = str(journal_path) if journal_path else None
        res["kv_log_present"] = bool(log_file is not None and log_file.exists())
        st2 = res.get("etcd_status") or {}
        res["status_present"] = (not bool(st2.get("missing")))
        j2 = res.get("journal") or {}
        res["journal_present"] = (not bool(j2.get("missing")))
        node_results.append(res)
        res_by_host[hostname] = res

        # Render per-node block once (existing begin/end output)
        block = _render_node_block(res, banner)
        node_blocks[hostname] = block
        journal_blocks[hostname] = _render_node_journal_block(res, banner, journal_raw_mode=journal_raw_mode)
        status_raw_blocks[hostname] = _render_node_etcd_status_raw_block(res, banner)

        if not interactive:
            # Print immediately (existing behavior)
            print(block, end="")

    # Cluster synthesis (now narrative-rich)
    cluster_synth = synthesize_cluster(node_results, slow_threshold_ms=110.0, drift_warn_threshold=100)

    if interactive:
        emit_cluster_synthesis()

        # Interactive menu loop
        # Determine leader-first ordering
        ordered_hosts = list(node_blocks.keys())
        if cluster_synth.leader_host and cluster_synth.leader_host in ordered_hosts:
            ordered_hosts = [cluster_synth.leader_host] + [h for h in ordered_hosts if h != cluster_synth.leader_host]
        else:
            ordered_hosts.sort()

        # Interactive render-time severity filter for incidents (levels 1-4).
        active_levels: Set[int] = set(levels) if levels else {1, 2, 3, 4}

        # Interactive, render-time time filters (do not change computed results).
        active_date: Optional[date] = date_filter
        active_days: Optional[int] = days
        active_time_range: Optional[Tuple[datetime, datetime]] = time_range

        while True:
            emit("Interactive mode: select a node to display output.")
            emit()
            emit(f"Nodes discovered constituting etcd: {len(ordered_hosts)}")
            node_lines: List[str] = []
            for idx2, hn in enumerate(ordered_hosts, start=1):
                ip = next((r.get("ip") for r in node_results if r.get("hostname") == hn), "unknown")
                r = next((rr for rr in node_results if rr.get("hostname") == hn), {}) or {}
                is_leader = r.get("node_is_leader")
                is_learner = r.get("node_is_learner")
            
                status_doc = (r.get("etcd_status") or {})
                is_member = bool(status_doc) and (status_doc.get("missing") is not True)
                if is_leader is True:
                    role_suffix = " [LEADER]"
                elif is_learner is True:
                    role_suffix = " [LEARNER]"
                elif is_member:
                    role_suffix = " [MEMBER]"
                else:
                    role_suffix = ""
                node_lines.append(f"[{idx2}] {hn} ({ip}){role_suffix}")
            emit(_render_two_column_table(node_lines).rstrip())
            emit("Options:")
            # Show current incident severity filter for this interactive session
            cur_levels = ",".join(str(x) for x in sorted(active_levels))
            cur_label = cur_levels
            if active_levels == {1}:
                cur_label = "1 (CRITICAL)"
            elif active_levels == {1, 2}:
                cur_label = "1,2 (CRITICAL,HIGH)"
            emit(f"  [A] All nodes (print default output for every node)")
            emit(f"  [L] Set incident severity filter (currently: {cur_label})")

            # Date / days / time filters (render-time only in interactive mode)
            date_label = active_date.isoformat() if active_date else "none"
            days_label = str(active_days) if (active_days is not None and active_days > 0) else "none"
            time_label = "none"
            if active_time_range is not None:
                start_dt, end_dt = active_time_range
                if (end_dt - start_dt) <= timedelta(minutes=1, seconds=1):
                    time_label = f"{start_dt.strftime('%Y-%m-%dT%H:%M')} (exact minute)"
                else:
                    half_hours = int(round(((end_dt - start_dt).total_seconds() / 3600.0) / 2.0))
                    anchor = start_dt + timedelta(hours=half_hours)
                    time_label = f"{anchor.strftime('%Y-%m-%dT%H:%M')} (±{half_hours}h)"
            emit(f"  [D] Set date filter (currently: {date_label})")
            emit(f"  [W] Set days filter (currently: {days_label})")
            emit(f"  [T] Set time-window filter (currently: {time_label})")
            emit("  [S] Show cluster synthesis again")
            emit("  [Q] Quit")
            emit()

            prompt = "Select a node (number) or option [A/L/D/W/T/S/Q]: "
            try:
                raw_choice = input(prompt)
                record_input(prompt, raw_choice)
                choice = raw_choice.strip()
            except (EOFError, KeyboardInterrupt):
                emit("\nExiting.")
                break

            if not choice:
                continue
            c = choice.strip().lower()

            if c == "q":
                break
            if c == "s":
                emit()
                emit_cluster_synthesis()
                continue
            if c == "l":
                emit()
                # emit("Levels: 1=CRITICAL 2=HIGH 3=MEDIUM 4=LOW")
                severity_prompt = "Enter severity levels to display (comma-separated, e.g. 1 or 1,2,3,4): "
                try:
                    raw_input_value = input(severity_prompt)
                    record_input(severity_prompt, raw_input_value)
                    raw = raw_input_value.strip()
                except (EOFError, KeyboardInterrupt):
                    emit("\nExiting.")
                    break
                if not raw:
                    continue
                parts = [p.strip() for p in raw.split(",") if p.strip()]
                new_levels: Set[int] = set()
                ok = True
                for p in parts:
                    if not p.isdigit():
                        ok = False
                        break
                    v = int(p)
                    if v not in (1, 2, 3, 4):
                        ok = False
                        break
                    new_levels.add(v)
                if not ok or not new_levels:
                    emit("Invalid levels. Please enter a comma-separated subset of 1,2,3,4.\n")
                    continue
                active_levels = new_levels
                continue
            if c == "d":
                emit()
                date_prompt = "Enter date filter (YYYY-MM-DD) or blank to clear: "
                try:
                    raw_input_value = input(date_prompt)
                    record_input(date_prompt, raw_input_value)
                    raw = raw_input_value.strip()
                except (EOFError, KeyboardInterrupt):
                    emit("\nExiting.")
                    break
                if not raw:
                    active_date = None
                    active_time_range = None
                    emit("Active date filter: none\n")
                    continue
                try:
                    active_date = datetime.strptime(raw, "%Y-%m-%d").date()
                except Exception:
                    emit("Invalid date format. Example: 2026-01-28\n")
                    continue
                # Setting date clears time filter
                active_time_range = None
                emit(f"Active date filter: {active_date.isoformat()}\n")
                continue

            if c == "w":
                emit()
                days_prompt = "Enter days window (integer, e.g. 2) or blank to clear: "
                try:
                    raw_input_value = input(days_prompt)
                    record_input(days_prompt, raw_input_value)
                    raw = raw_input_value.strip()
                except (EOFError, KeyboardInterrupt):
                    emit("\nExiting.")
                    break
                if not raw:
                    active_days = None
                    active_time_range = None
                    emit("Active days filter: none\n")
                    continue
                if not raw.isdigit():
                    emit("Invalid days value. Example: 2\n")
                    continue
                v = int(raw)
                if v <= 0:
                    active_days = None
                    active_time_range = None
                    emit("Active days filter: none\n")
                    continue
                active_days = v
                # Setting days clears time filter
                active_time_range = None
                emit(f"Active days filter: last {active_days} day(s)\n")
                continue

            if c == "t":
                emit()
                time_anchor_prompt = "Enter time anchor (YYYY-MM-DDThh:mm, interpreted in log time) or blank to clear: "
                try:
                    raw_input_value = input(time_anchor_prompt)
                    record_input(time_anchor_prompt, raw_input_value)
                    raw = raw_input_value.strip()
                except (EOFError, KeyboardInterrupt):
                    emit("\nExiting.")
                    break
                if not raw:
                    active_time_range = None
                    emit("Active time filter: none\n")
                    continue
                try:
                    anchor = datetime.strptime(raw, "%Y-%m-%dT%H:%M")
                except Exception:
                    emit("Invalid time format. Example: 2026-01-28T06:20\n")
                    continue
                time_width_prompt = "Enter time window half-width in hours (0..N, where 0 means only that minute): "
                try:
                    raw_input_value = input(time_width_prompt)
                    record_input(time_width_prompt, raw_input_value)
                    raw_h = raw_input_value.strip()
                except (EOFError, KeyboardInterrupt):
                    emit("\nExiting.")
                    break
                if not raw_h:
                    raw_h = "0"
                if not raw_h.isdigit():
                    emit("Invalid hours value. Example: 2\n")
                    continue
                h = int(raw_h)
                if h < 0:
                    emit("Invalid hours value. Example: 2\n")
                    continue
                # Centered window: ±h around the anchor minute; when h=0, 1-minute slice.
                if h == 0:
                    active_time_range = (anchor, anchor + timedelta(minutes=1))
                    emit(f"Active time filter: {anchor.strftime('%Y-%m-%dT%H:%M')} (exact minute)\n")
                    # emit(f"Active time filter: {anchor.strftime('%Y-%m-%dT%H:%M')} (±0h)\n")
                else:
                    active_time_range = (anchor - timedelta(hours=h), anchor + timedelta(hours=h))
                    emit(f"Active time filter: {anchor.strftime('%Y-%m-%dT%H:%M')} (±{h}h)\n")
                # Setting time clears date/days
                active_date = None
                active_days = None
                continue

            if c == "a":
                emit()
                for hn in ordered_hosts:
                    rr = res_by_host.get(hn, {})
                    ip2 = rr.get("ip") or "unknown"
                    banner2 = f"========== {hn} ({ip2}) =========="
                    emit(
                        _render_node_block(
                            rr,
                            banner2,
                            allowed_levels=active_levels,
                            active_date=active_date,
                            active_days=active_days,
                            active_time_range=active_time_range,
                        ),
                        end="",
                    )
                continue

            if c.isdigit():
                sel = int(c)
                if 1 <= sel <= len(ordered_hosts):
                    hn = ordered_hosts[sel - 1]
                    ip = next((r.get("ip") for r in node_results if r.get("hostname") == hn), "unknown") or "unknown"
                    emit()
                    emit(f"Selected node: {hn} ({ip})")
                    # Node view menu (only show options that make sense for this node)
                    r = next((rr for rr in node_results if rr.get("hostname") == hn), {}) or {}
                    status_present = bool(r.get("status_present"))
                    journal_present = bool(r.get("journal_present"))
                    kv_present = bool(r.get("kv_log_present"))

                    journal_only = journal_present and (not status_present) and (not kv_present)

                    views: List[str] = []
                    emit("Views:")
                    if journal_only:
                        views = ["J", "B"]
                        emit("  [J] journalctl_daemon.log analysis (interpreted + raw matches)")
                        emit("  [B] Back")
                    else:
                        views.append("D")
                        emit("  [D] Default output (incidents + etcd-status)")
                        if status_present:
                            views.append("E")
                            emit("  [E] etcd-status.txt display (raw only)")
                        if journal_present:
                            views.append("J")
                            emit("  [J] journalctl_daemon.log analysis (interpreted + raw matches)")
                            views.append("A")
                            emit("  [A] All (default + journal)")
                        views.append("B")
                        emit("  [B] Back")

                    emit()
                    view_prompt = f"Select one of the following: {', '.join(views)}: "

                    try:
                        raw_view = input(view_prompt)
                        record_input(view_prompt, raw_view)
                        v = raw_view.strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        emit("\nExiting.")
                        break
                    if not v:
                        continue
                    if v == "b":
                        continue
                    if v == "d":
                        emit()
                        rr = res_by_host.get(hn, {})
                        ip2 = rr.get("ip") or "unknown"
                        banner2 = f"========== {hn} ({ip2}) =========="
                        emit(
                            _render_node_block(
                                rr,
                                banner2,
                                allowed_levels=active_levels,
                                active_date=active_date,
                                active_days=active_days,
                                active_time_range=active_time_range,
                            ),
                            end="",
                        )
                        continue
                    if v == "e":
                        emit()
                        emit(status_raw_blocks[hn], end="")
                        continue
                    if v == "j":
                        emit()
                        rr = res_by_host.get(hn, {})
                        jdoc0 = (rr or {}).get("journal") or {}
                        jpath_s = (jdoc0 or {}).get("path") or ""
                        if not jpath_s or (jdoc0 or {}).get("missing"):
                            emit(render_journal_console(jdoc0, raw_mode=journal_raw_mode), end="")
                            continue
                        jpath = Path(jpath_s)
                        tr = _derive_time_range_for_journal_path(
                            jpath,
                            active_date=active_date,
                            active_days=active_days,
                            active_time_range=active_time_range,
                        )
                        jdoc = parse_journalctl_daemon_log(jpath, time_range=tr)
                        emit(render_journal_console(jdoc, raw_mode=journal_raw_mode), end="")
                        continue
                    if v == "a" and journal_present and (not journal_only):
                        emit()
                        rr = res_by_host.get(hn, {})
                        ip2 = rr.get("ip") or "unknown"
                        banner2 = f"========== {hn} ({ip2}) =========="
                        emit(
                            _render_node_block(
                                rr,
                                banner2,
                                allowed_levels=active_levels,
                                active_date=active_date,
                                active_days=active_days,
                                active_time_range=active_time_range,
                            ),
                            end="",
                        )
                        rr = res_by_host.get(hn, {})
                        jdoc0 = (rr or {}).get("journal") or {}
                        jpath_s = (jdoc0 or {}).get("path") or ""
                        if not jpath_s or (jdoc0 or {}).get("missing"):
                            emit(render_journal_console(jdoc0, raw_mode=journal_raw_mode), end="")
                            continue
                        jpath = Path(jpath_s)
                        tr = _derive_time_range_for_journal_path(
                            jpath,
                            active_date=active_date,
                            active_days=active_days,
                            active_time_range=active_time_range,
                        )
                        jdoc = parse_journalctl_daemon_log(jpath, time_range=tr)
                        emit(render_journal_console(jdoc, raw_mode=journal_raw_mode), end="")
                        continue

                    emit("Invalid selection. Please choose one of the listed options.\n")
                    continue

            emit("Invalid selection. Please choose one of the listed options.\n")
    else:
        # Non-interactive: print synthesis at end (existing behavior)
        print_cluster_synthesis_console(cluster_synth)

    report_path = output_dir / "etcd_analysis_report.md"
    report_text = _render_bundle_markdown_report(
        bundle_root=bundle_root,
        cluster_synth=cluster_synth,
        node_results=node_results,
        skipped_nodes=skipped,
        date_filter=date_filter,
        days=days,
        time_range=time_range,
        levels=levels,
        journal_raw_mode=journal_raw_mode,
    )
    _write_text_file(report_path, report_text)
    print(f"Wrote report: {report_path}")

    json_path = output_dir / "etcd_analysis.json"

    filters = {
        "date": date_filter.isoformat() if date_filter else None,
        "days": (int(days) if days is not None else None),
        "levels": list(levels) if levels is not None else [1, 2, 3, 4],
        "json_include_events": bool(json_include_events),
    }

    write_bundle_json(
        out_file=json_path,
        bundle_root=bundle_root,
        node_results=node_results,
        skipped_nodes=skipped,
        cluster_synth=cluster_synth.to_json(),
        filters=filters,
    )
    print(f"Wrote JSON: {json_path}")

    if transcript_writer is not None:
        transcript_writer.close()
        print(f"Wrote transcript: {transcript_path}")

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="etcd_analysis ver 23",
        description="Parse etcd logs (single-node) OR scan a support bundle (multi-node), detect incidents, and emit duration/storm-aware findings.",
    )

    # Multi-node support bundle scan (new in v10)

    # Input selection
    parser.add_argument(
        "--path",
        help="Root directory of an extracted support bundle to scan (multi-node mode). If set, --logpath is ignored.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Interactive console mode: print cluster synthesis first, then let you choose which node(s) to display (bundle mode only).",
    )

    # Single-node input (v9 behavior)
    parser.add_argument(
        "--logpath",
        default=".",
        help="Path to ucp-kv.log file or directory containing it (single-node mode). If a directory is given, ucp-kv.log is assumed inside it.",
    )

    # Filters
    parser.add_argument(
        "--date",
        dest="date_str",
        help="Filter log events to a specific date (YYYY-MM-DD).",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Analyze only the last N days relative to the newest timestamp in the log (works with --date too).",
    )

    parser.add_argument(
        "--time",
        dest="time_str",
        default=None,
        help='Filter events to a point-in-time window centered on the given minute (format: YYYY-MM-DDThh:mm). Example: --time=2026-01-28T06:20',
    )
    parser.add_argument(
        "--time-window",
        dest="time_window_hours",
        type=int,
        default=0,
        help="Time window half-width in hours when used with --time. The effective range is ±hours around --time. 0 means only that minute.",
    )
    parser.add_argument(
        "--level",
        default=None,
        help="Comma-separated severity levels to include (1,2,3,4). Default: all.",
    )

    # output directory
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        default=".",
        help="Directory to write tool-created artifacts (default: current directory).",
    )
    parser.add_argument(
        "--json-include-events",
        action="store_true",
        help="Include per-event details in JSON output (default: false).",
    )


    parser.add_argument(
        "--journal-raw",
        choices=["all", "collapsed", "none"],
        default="collapsed",
        help="Journal raw output mode in console: all=print every matched line; collapsed=group repetitive patterns and show first/last samples; none=suppress raw matches (default: collapsed)",
    )
    parser.add_argument(
        "--config",
        dest="config_path",
        default=str(default_signature_config_path()),
        help="Path to etcd signature config YAML (default: ./configs/etcd-signatures.yaml).",
    )

    args = parser.parse_args()
    try:
        configure_signature_runtime(Path(args.config_path))
    except EtcdSignatureConfigError as e:
        print(f"ERROR: invalid etcd signature config: {e}", file=sys.stderr)
        sys.exit(2)
    # Validate --time / --time-window
    time_anchor: Optional[datetime] = None
    time_window_hours: int = int(args.time_window_hours) if getattr(args, "time_window_hours", None) is not None else 0
    if getattr(args, "time_str", None):
        ts_s = str(args.time_str).strip()
        try:
            time_anchor = datetime.strptime(ts_s, "%Y-%m-%dT%H:%M")
        except Exception:
            print("error: --time must be in format YYYY-MM-DDThh:mm (example: --time=2026-01-28T06:20)")
            sys.exit(2)
        if time_window_hours < 0:
            print("error: --time-window must be an integer >= 0 (example: --time-window=2)")
            sys.exit(2)
    else:
        # If --time is not provided, ignore --time-window (but keep parsed value for interactive prompts if desired).
        time_window_hours = 0

    time_range: Optional[Tuple[datetime, datetime]] = None
    if time_anchor is not None:
        # Centered window: ±hours around the anchor minute. When hours=0, use a 1-minute slice.
        if time_window_hours == 0:
            start_dt = time_anchor
            end_dt = time_anchor + timedelta(minutes=1)
        else:
            start_dt = time_anchor - timedelta(hours=time_window_hours)
            end_dt = time_anchor + timedelta(hours=time_window_hours)

        time_range = (start_dt, end_dt)

    # If --time is set, it overrides --date/--days (most specific filter)
    if time_range is not None:
        args.date_str = None
        args.days = None

    # Shared filters
    date_filter = None
    if args.date_str:
        try:
            date_filter = parse_yyyy_mm_dd(args.date_str)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(2)

    levels = None
    if args.level is not None:
        try:
            levels = parse_level_list(args.level)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(2)

    json_out_path = Path(args.json_out) if args.json_out is not None else Path(".")

    # Bundle mode
    if args.path:
        bundle_root = Path(args.path)
        sys.exit(
            main_bundle(
                bundle_root=bundle_root,
                date_filter=date_filter,
                days=args.days,
                time_range=time_range,
                levels=levels,
                json_out=json_out_path,
                json_include_events=bool(args.json_include_events),
                interactive=bool(args.interactive),
                journal_raw_mode=str(args.journal_raw),
            )
        )

    # Single-node mode (v9 behavior)
    log_arg = Path(args.logpath)
    if log_arg.is_dir():
        log_file = log_arg / "ucp-kv.log"
    else:
        log_file = log_arg

    if log_file.name != "ucp-kv.log":
        print(f"ERROR: Expected log file named 'ucp-kv.log'. Got: {log_file.name}", file=sys.stderr)
        sys.exit(2)

    if not log_file.exists() or not log_file.is_file():
        print(f"ERROR: Log file not found: {log_file}", file=sys.stderr)
        sys.exit(2)

    sys.exit(
        main_single(
            str(log_file),
            date_filter=date_filter,
            days=args.days,
                time_range=time_range,
            levels=levels,
            json_out=json_out_path,
            json_include_events=bool(args.json_include_events),
        )
    )

def _handle_sigterm(signum, frame):
    raise KeyboardInterrupt


def _handle_top_level_interrupt() -> int:
    print("\n[etcd_analysis] interrupted — exiting gracefully")
    return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="etcd_analysis ver 25",
        description="Parse etcd logs (single-node) OR scan a support bundle (multi-node), detect incidents, and emit duration/storm-aware findings.",
    )

    parser.add_argument(
        "--bundle-path",
        dest="bundle_path",
        default=None,
        help="Unified input path. Accepts cluster bundle root, node directory, dsinfo directory, or parent containing dsinfo.",
    )

    parser.add_argument(
        "--path",
        dest="legacy_path",
        default=None,
        help=argparse.SUPPRESS,
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Interactive console mode: print cluster synthesis first, then let you choose which node(s) to display (bundle mode only).",
    )

    parser.add_argument(
        "--logpath",
        dest="legacy_logpath",
        default=None,
        help=argparse.SUPPRESS,
    )

    parser.add_argument(
        "--date",
        dest="date_str",
        help="Filter log events to a specific date (YYYY-MM-DD).",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Analyze only the last N days relative to the newest timestamp in the log (works with --date too).",
    )

    parser.add_argument(
        "--time",
        dest="time_str",
        default=None,
        help="Filter events to a point-in-time window centered on the given minute (format: YYYY-MM-DDThh:mm). Example: --time=2026-01-28T06:20",
    )
    parser.add_argument(
        "--time-window",
        dest="time_window_hours",
        type=int,
        default=0,
        help="Time window half-width in hours when used with --time. The effective range is ±hours around --time. 0 means only that minute.",
    )
    parser.add_argument(
        "--level",
        default=None,
        help="Comma-separated severity levels to include (1,2,3,4). Default: all.",
    )

    # output directory
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        default=".",
        help="Directory to write tool-created artifacts (default: current directory).",
    )
    parser.add_argument(
        "--json-include-events",
        action="store_true",
        help="Include per-event details in JSON output (default: false).",
    )

    parser.add_argument(
        "--journal-raw",
        choices=["all", "collapsed", "none"],
        default="collapsed",
        help="Journal raw output mode in console: all=print every matched line; collapsed=group repetitive patterns and show first/last samples; none=suppress raw matches (default: collapsed)",
    )

    parser.add_argument(
        "--config",
        default=str(default_signature_config_path()),
        help="Path to etcd signature config (default: ./configs/etcd-signatures.yaml)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        configure_signature_runtime(Path(args.config))
    except EtcdSignatureConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    time_anchor: Optional[datetime] = None
    time_window_hours: int = int(args.time_window_hours) if getattr(args, "time_window_hours", None) is not None else 0
    if getattr(args, "time_str", None):
        ts_s = str(args.time_str).strip()
        try:
            time_anchor = datetime.strptime(ts_s, "%Y-%m-%dT%H:%M")
        except ValueError:
            print(
                f"ERROR: Invalid --time '{ts_s}'. Expected format YYYY-MM-DDThh:mm (example: 2026-01-28T06:20)",
                file=sys.stderr,
            )
            return 2
        if time_window_hours < 0:
            print("ERROR: --time-window must be >= 0", file=sys.stderr)
            return 2

    time_range: Optional[Tuple[datetime, datetime]] = None
    if time_anchor is not None:
        if time_window_hours == 0:
            start_dt = time_anchor
            end_dt = time_anchor + timedelta(minutes=1)
        else:
            start_dt = time_anchor - timedelta(hours=time_window_hours)
            end_dt = time_anchor + timedelta(hours=time_window_hours)
        time_range = (start_dt, end_dt)

    if time_range is not None:
        args.date_str = None
        args.days = None

    date_filter: Optional[date] = None
    if args.date_str:
        try:
            date_filter = parse_yyyy_mm_dd(args.date_str)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2

    levels: Optional[List[int]] = None
    if args.level is not None:
        try:
            levels = parse_level_list(args.level)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2

    output_dir = resolve_output_dir(getattr(args, "output_dir", "."))

    input_path_s = args.bundle_path or args.legacy_path or args.legacy_logpath
    if not input_path_s:
        print(
            "ERROR: missing input path. Use --bundle-path "
            "(or legacy --path / --logpath during this compatibility slice).",
            file=sys.stderr,
        )
        return 2

    try:
        resolved = resolve_bundle_input(Path(input_path_s))
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if resolved.mode == "cluster":
        return main_bundle(
            bundle_root=resolved.bundle_root,
            output_dir=output_dir,
            date_filter=date_filter,
            days=args.days,
            time_range=time_range,
            levels=levels,
            json_include_events=bool(args.json_include_events),
            interactive=bool(args.interactive),
            journal_raw_mode=str(args.journal_raw),
        )

    if args.interactive:
        print(
            "WARNING: --interactive currently applies only to cluster bundle mode. "
            "Proceeding with single-node analysis.",
            file=sys.stderr,
        )

    return main_single_resolved(
        resolved=resolved,
        output_dir=output_dir,
        date_filter=date_filter,
        days=args.days,
        time_range=time_range,
        levels=levels,
        json_include_events=bool(args.json_include_events),
        journal_raw_mode=str(args.journal_raw),
    )


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_sigterm)
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(_handle_top_level_interrupt())
