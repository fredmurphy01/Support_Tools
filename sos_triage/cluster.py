""" cluster.py version 1.1.0 """
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .types import Config
from .util import rfc3339_to_dt, sha1_hex


@dataclass
class ClusterStats:
    clusters_emitted: int
    clusters_by_event_type: Dict[str, int]
    chatty_events_considered: int


def _context_grouping(cfg: Config) -> Dict[str, Any]:
    block = cfg.raw.get('context_grouping', {}) or {}
    return block if isinstance(block, dict) else {}


def _cluster_id_settings(cfg: Config) -> Tuple[str, int, int, List[str]]:
    cid = (cfg.defaults or {}).get('cluster_id', {}) or {}
    prefix = str(cid.get('sequential_prefix', 'clu_'))
    width = int(cid.get('sequential_width', 6))
    stable = cid.get('stable_hash', {}) or {}
    hex_chars = int(stable.get('hex_chars', 12))
    canonical = list(stable.get('canonical_fields', []))
    return prefix, width, hex_chars, canonical


def _event_time(ev: Dict[str, Any]) -> Optional[float]:
    ts = ev.get('ts') or ev.get('ts_raw')
    if not ts:
        return None
    dt = rfc3339_to_dt(str(ts))
    return dt.timestamp() if dt else None


def build_clusters(events_path: Path, clusters_path: Path, cfg: Config) -> Tuple[List[Dict[str, Any]], ClusterStats]:
    grouping = _context_grouping(cfg)
    if not grouping.get('enabled', False):
        return [], ClusterStats(0, {}, 0)

    chatty_types = list(grouping.get('chatty_event_types', []) or [])
    group_keys = list(grouping.get('group_by_keys', ['event_type', 'peer', 'port']) or [])
    cluster_window = int(grouping.get('cluster_window_seconds', 60))
    max_gap = int(grouping.get('max_gap_seconds', 30))
    min_events = int(grouping.get('min_events', 3))

    prefix, width, hex_chars, canonical_fields = _cluster_id_settings(cfg)

    # Load and filter events
    events: List[Dict[str, Any]] = []
    chatty_considered = 0
    with open(events_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            et = ev.get('event_type')
            if et in chatty_types:
                chatty_considered += 1
                events.append(ev)

    # Group by keys
    buckets: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = {}
    for ev in events:
        key = tuple(ev.get(k) for k in group_keys)
        buckets.setdefault(key, []).append(ev)

    clusters: List[Dict[str, Any]] = []
    clusters_by_type: Dict[str, int] = {}

    def make_hash(obj: Dict[str, Any]) -> str:
        parts: List[str] = []
        for f in canonical_fields:
            if f == 'event_type':
                parts.append(str(obj.get('event_type', '') or ''))
            elif f == 'peer':
                parts.append(str(obj.get('peer', '') or ''))
            elif f == 'port':
                parts.append(str(obj.get('port', '') or ''))
            elif f == 'start_ts_normalized_or_raw':
                parts.append(str(obj.get('start_ts', '') or ''))
            elif f == 'end_ts_normalized_or_raw':
                parts.append(str(obj.get('end_ts', '') or ''))
            elif f == 'count':
                parts.append(str(obj.get('count', '') or ''))
            elif f == 'member_event_hashes_sorted':
                parts.append(','.join(sorted(obj.get('member_event_hashes', []) or [])))
            else:
                parts.append('')
        return sha1_hex('|'.join(parts))[:hex_chars]

    # Iterate buckets in a stable order for deterministic cluster IDs.
    seq = 0
    for _key in sorted(buckets.keys(), key=lambda k: tuple('' if v is None else str(v) for v in k)):
        evs = buckets[_key]
        evs_sorted = sorted(
            evs,
            key=lambda e: (_event_time(e) is None, _event_time(e) or 0.0, e.get('event_id', ''))
        )

        current: List[Dict[str, Any]] = []
        start_t: Optional[float] = None
        prev_t: Optional[float] = None

        def flush():
            nonlocal seq, current, start_t, prev_t
            if len(current) >= min_events:
                seq += 1
                cluster_id = f"{prefix}{seq:0{width}d}"
                etype = current[0].get('event_type')
                peer = current[0].get('peer')
                port = current[0].get('port')

                start_ts = current[0].get('ts') or current[0].get('ts_raw')
                end_ts = current[-1].get('ts') or current[-1].get('ts_raw')

                reasons: Dict[str, int] = {}
                sources: Dict[str, int] = {}
                member_ids: List[str] = []
                member_hashes: List[str] = []
                for e in current:
                    r = e.get('reason') or ''
                    if r:
                        reasons[r] = reasons.get(r, 0) + 1
                    src = e.get('source_relpath') or ''
                    if src:
                        sources[src] = sources.get(src, 0) + 1
                    if e.get('event_id'):
                        member_ids.append(e['event_id'])
                    if e.get('event_hash'):
                        member_hashes.append(e['event_hash'])

                cluster_obj = {
                    'schema_version': 'clusters-v1',
                    'cluster_id': cluster_id,
                    'event_type': etype,
                    'peer': peer,
                    'port': port,
                    'count': len(current),
                    'start_ts': start_ts,
                    'end_ts': end_ts,
                    'member_event_ids': member_ids,
                    'member_event_hashes': member_hashes,
                    'top_reasons': sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))[:3],
                    'sources': sorted(sources.items(), key=lambda kv: (-kv[1], kv[0]))[:10],
                }
                cluster_obj['cluster_hash'] = make_hash(cluster_obj)
                clusters.append(cluster_obj)
                clusters_by_type[str(etype)] = clusters_by_type.get(str(etype), 0) + 1

            current = []
            start_t = None
            prev_t = None

        for e in evs_sorted:
            t = _event_time(e)
            if t is None:
                continue
            if not current:
                current = [e]
                start_t = t
                prev_t = t
                continue
            assert start_t is not None and prev_t is not None
            gap = t - prev_t
            span = t - start_t
            if gap <= max_gap and span <= cluster_window:
                current.append(e)
                prev_t = t
            else:
                flush()
                current = [e]
                start_t = t
                prev_t = t

        if current:
            flush()

    clusters_path.parent.mkdir(parents=True, exist_ok=True)
    with open(clusters_path, 'w', encoding='utf-8') as f:
        json.dump(clusters, f, indent=2, ensure_ascii=False)

    stats = ClusterStats(len(clusters), clusters_by_type, chatty_considered)
    return clusters, stats
