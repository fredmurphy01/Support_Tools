""" findings.py version 1.1.0 """
from __future__ import annotations

import json
from bisect import bisect_left, bisect_right
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _parse_rfc3339(ts: Optional[str]) -> Optional[datetime]:
    """Best-effort RFC3339 parse.

    Supports timestamps with a trailing 'Z' and optional fractional seconds.
    Python's fromisoformat supports microseconds (6 digits), so we truncate
    fractional seconds to 6 digits when needed.
    """
    if not ts:
        return None
    s = ts.strip()
    if not s:
        return None
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'

    # Truncate fractional seconds to 6 digits if present.
    # Example: 2026-02-01T19:26:05.569952521+00:00 -> ...569952+00:00
    try:
        if '.' in s:
            main, rest = s.split('.', 1)
            frac = rest
            tz_part = ''
            if '+' in rest:
                frac, tz_part = rest.split('+', 1)
                tz_part = '+' + tz_part
            elif '-' in rest[6:]:
                # timezone like -01:00 (avoid the date '-' chars)
                frac, tz_part = rest.split('-', 1)
                tz_part = '-' + tz_part
            frac = (frac[:6]).ljust(6, '0')
            s = f"{main}.{frac}{tz_part}"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _sample_events(evts: List[Dict[str, Any]], max_samples: int = 3) -> List[Dict[str, Any]]:
    """Predictable evidence sampling: first, last, and (optionally) middle."""
    if not evts:
        return []
    if len(evts) == 1 or max_samples <= 1:
        return [evts[0]]
    out = [evts[0]]
    if len(evts) > 2 and max_samples >= 3:
        out.append(evts[len(evts) // 2])
    out.append(evts[-1])
    # de-dupe by event_id preserving order
    seen = set()
    dedup = []
    for e in out:
        eid = e.get('event_id')
        if eid in seen:
            continue
        seen.add(eid)
        dedup.append(e)
    return dedup[:max_samples]


def _evidence_row(evt: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'event_id': evt.get('event_id'),
        'event_hash': evt.get('event_hash'),
        'ts': evt.get('ts'),
        'event_type': evt.get('event_type'),
        'severity': evt.get('severity'),
        'signature_id': evt.get('signature_id'),
        'source_relpath': evt.get('source_relpath'),
        'line_number': evt.get('line_number'),
        'peer': evt.get('peer'),
        'port': evt.get('port'),
        'reason': evt.get('reason'),
        'excerpt': evt.get('excerpt'),
    }


def generate_findings(
    *,
    events_path: Path,
    out_path: Path,
    cfg_raw: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generate findings.json from events.jsonl using cfg_raw['heuristics'].

    Returns (findings_doc, findings_stats).
    """
    heuristics = (cfg_raw.get('heuristics') or [])
    defaults = cfg_raw.get('defaults') or {}
    excerpt_max = ((defaults.get('excerpt') or {}).get('max_chars')) or 240

    # Load events
    events: List[Dict[str, Any]] = []
    by_type_times: Dict[str, List[datetime]] = {}
    by_type_events: Dict[str, List[Dict[str, Any]]] = {}

    with events_path.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except Exception:
                continue
            # normalize excerpt length
            ex = evt.get('excerpt') or ''
            if len(ex) > excerpt_max:
                evt['excerpt'] = ex[:excerpt_max]
            dt = _parse_rfc3339(evt.get('ts')) or _parse_rfc3339(evt.get('ts_raw'))
            if not dt:
                continue
            evt['_dt'] = dt
            events.append(evt)
            et = evt.get('event_type') or 'unknown'
            by_type_times.setdefault(et, []).append(dt)
            by_type_events.setdefault(et, []).append(evt)

    # ensure sorted
    events.sort(key=lambda e: e['_dt'])
    for et in by_type_times:
        by_type_times[et].sort()
        by_type_events[et].sort(key=lambda e: e['_dt'])

    findings: List[Dict[str, Any]] = []
    fid = 1

    for h in heuristics:
        if not h or not h.get('enabled', True):
            continue
        hid = h.get('id')
        title = h.get('title') or hid or 'heuristic'
        sev = h.get('severity') or 'info'
        base_w = float(h.get('confidence_weight', 0.5))
        window_s = int(h.get('window_seconds', 600))
        window = timedelta(seconds=window_s)
        thresholds = h.get('thresholds') or []
        supports_raw = h.get('supports') or []
        supports: List[str] = []
        for s in supports_raw:
            if isinstance(s, str):
                supports.append(s)
            elif isinstance(s, dict) and s.get('event_type'):
                supports.append(str(s.get('event_type')))
        outputs = h.get('outputs') or {}

        req_types = [t.get('event_type') for t in thresholds if t.get('event_type')]
        if not req_types:
            continue
        # Candidate starts: union of required event times
        cand_times: List[datetime] = []
        for et in req_types:
            cand_times.extend(by_type_times.get(et, []))
        cand_times = sorted(set(cand_times))
        if not cand_times:
            continue

        max_findings_per_heur = 5
        idx = 0
        produced = 0
        while idx < len(cand_times) and produced < max_findings_per_heur:
            start = cand_times[idx]
            end = start + window

            counts: Dict[str, int] = {}
            ok = True
            for t in thresholds:
                et = t.get('event_type')
                if not et:
                    continue
                need = int(t.get('count_gte', 1))
                times = by_type_times.get(et, [])
                c = bisect_right(times, end) - bisect_left(times, start)
                counts[et] = c
                if c < need:
                    ok = False
                    break
            if not ok:
                idx += 1
                continue

            # Gather evidence events in window for threshold types + supports
            want_types = list(dict.fromkeys(req_types + supports))
            window_events: Dict[str, List[Dict[str, Any]]] = {}
            for et in want_types:
                evs = by_type_events.get(et, [])
                if not evs:
                    continue
                # slice by time range using bisection on times
                times = by_type_times.get(et, [])
                l = bisect_left(times, start)
                r = bisect_right(times, end)
                if l < r:
                    window_events[et] = evs[l:r]

            # Confidence: base + support presence bonus
            support_present = sum(1 for et in supports if window_events.get(et))
            bonus = min(0.10, 0.05 * support_present)
            confidence = min(0.99, base_w + bonus)

            # Evidence sampling
            evidence: List[Dict[str, Any]] = []
            for et in req_types:
                for e in _sample_events(window_events.get(et, []), max_samples=3):
                    evidence.append(_evidence_row(e))
            for et in supports:
                if len(evidence) >= 12:
                    break
                for e in _sample_events(window_events.get(et, []), max_samples=2):
                    if len(evidence) >= 12:
                        break
                    evidence.append(_evidence_row(e))

            # additional counts for supports
            for et in supports:
                if et not in counts:
                    times = by_type_times.get(et, [])
                    counts[et] = bisect_right(times, end) - bisect_left(times, start)

            finding = {
                'finding_id': f"fid_{fid:06d}",
                'heuristic_id': hid,
                'title': title,
                'severity': sev,
                'confidence': round(confidence, 3),
                'window': {
                    'start_ts': start.isoformat().replace('+00:00', 'Z'),
                    'end_ts': end.isoformat().replace('+00:00', 'Z'),
                    'window_seconds': window_s,
                },
                'counts': counts,
                'outputs': {
                    'tags': outputs.get('tags') or [],
                    'likely_causes': outputs.get('likely_causes') or [],
                    'ports_implicated': outputs.get('ports_implicated') or [],
                },
                'evidence': evidence,
            }
            findings.append(finding)
            fid += 1
            produced += 1

            # Jump forward: next candidate after this window
            idx = bisect_right(cand_times, end)

    doc = {
        'schema_version': (cfg_raw.get('outputs') or {}).get('schemas', {}).get('findings', 'findings-v1'),
        'generated_time_utc': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'findings': findings,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False))

    stats = {
        'findings_emitted': len(findings),
        'heuristics_evaluated': sum(1 for h in heuristics if (h or {}).get('enabled', True)),
    }
    return doc, stats
