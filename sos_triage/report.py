""" report.py version 1.1.0 """
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


from .util import rfc3339_to_dt


# Emojis for report.md findings severity cues
SEV_ICON = {
    "CRITICAL": "❌",
    "HIGH": "🔴",
    "MEDIUM": "🟠",
    "LOW": "🟡",
}





def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8', errors='ignore'))


def _iter_events(events_path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with events_path.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            ts = ev.get('ts') or ev.get('ts_raw')
            dt = rfc3339_to_dt(str(ts)) if ts else None
            if not dt:
                continue
            ev['_dt'] = dt
            out.append(ev)
    out.sort(key=lambda e: e['_dt'])
    return out


def _severity_rank(sev: str) -> int:
    s = (sev or '').lower()
    return {'critical': 3, 'high': 2, 'medium': 1, 'info': 0}.get(s, 0)


def _event_row(ev: Dict[str, Any]) -> str:
    ts = ev.get('ts') or ev.get('ts_raw') or ''
    et = ev.get('event_type') or ''
    peer = ev.get('peer')
    port = ev.get('port')
    sev = ev.get('severity') or ''
    reason = ev.get('reason')
    src = ev.get('source_relpath')
    ln = ev.get('line_number')
    bits = [f"{ts}", f"{sev.upper():<8}", et]
    if peer or port:
        bits.append(f"peer={peer or ''}:{port or ''}")
    if reason:
        bits.append(f"reason={reason}")
    if src and ln:
        bits.append(f"src={src}:{ln}")
    return " | ".join(bits)


def _cluster_implication(event_type: str, port: Optional[int]) -> str:
    et = (event_type or '').lower()
    if port == 2377 or 'raft' in et:
        return 'Implication: manager Raft/quorum connectivity degraded on TCP/2377'
    if port == 7946 or 'memberlist' in et:
        return 'Implication: Swarm gossip health degraded on TCP/7946 (often precedes Raft churn)'
    return 'Implication: burst of repeated control-plane signals'


def _cluster_row(c: Dict[str, Any]) -> str:
    start = c.get('start_ts') or ''
    end = c.get('end_ts') or ''
    et = c.get('event_type') or ''
    peer = c.get('peer')
    port = c.get('port')
    count = c.get('count')
    cid = c.get('cluster_id') or c.get('cluster_hash') or ''
    reasons = c.get('top_reasons') or []
    reason_txt = ', '.join([f"{r[0]}×{r[1]}" for r in reasons if isinstance(r,(list,tuple)) and len(r)==2])
    impl = _cluster_implication(str(et), int(port) if port is not None else None)
    bits = [f"CLUSTER: {et} to {peer or ''}:{port or ''} — {count} events — {start}→{end}"]
    if reason_txt:
        bits.append(f"({reason_txt[:120]})")
    if cid:
        bits.append(f"[{cid}]")
    bits.append(impl)
    return ' '.join(bits)




def _event_stream_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        by_type.setdefault(str(ev.get('event_type') or 'unknown'), []).append(ev)

    type_rows: List[Dict[str, Any]] = []
    for et, evs in by_type.items():
        evs_sorted = sorted(evs, key=lambda e: e['_dt'])
        first_ts = evs_sorted[0].get('ts') or evs_sorted[0].get('ts_raw')
        last_ts = evs_sorted[-1].get('ts') or evs_sorted[-1].get('ts_raw')
        local_peer_counts: Dict[str, int] = {}
        for e in evs:
            peer = e.get('peer')
            port = e.get('port')
            if peer or port:
                key = f"{peer or ''}:{port or ''}"
                local_peer_counts[key] = local_peer_counts.get(key, 0) + 1
        top_peers = [k for k,_n in sorted(local_peer_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]]
        type_rows.append({'event_type': et, 'count': len(evs), 'first_ts': first_ts, 'last_ts': last_ts, 'top_peers': top_peers})

    type_rows.sort(key=lambda r: (-r['count'], r['event_type']))

    first = events[0] if events else None
    last = events[-1] if events else None
    worst = None
    if events:
        worst = sorted(events, key=lambda e: (-_severity_rank(str(e.get('severity') or '')), -float(e.get('confidence') or 0.0), e['_dt']))[0]

    return {'type_rows': type_rows, 'samples': {'first': first, 'worst': worst, 'last': last}}


def generate_report(
    *,
    cfg_raw: Dict[str, Any],
    events_path: Path,
    clusters_path: Optional[Path],
    findings_path: Optional[Path],
    out_path: Path,
    tool: Dict[str, str],
    analysis_context: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Generate report.md (report-md-v1).

    Implements Timeline Option 2 (from events.jsonl with clustering + downsample).
    Produces an RCA skeleton: what happened, evidence, likely cause placeholders,
    and a compact timeline.
    """

    analysis_context = analysis_context or {}

    tl_cfg = (cfg_raw.get('timeline') or {})
    enabled = bool(tl_cfg.get('enabled', False))

    findings_doc: Optional[Dict[str, Any]] = None
    findings: List[Dict[str, Any]] = []
    referenced_event_ids: Set[str] = set()
    if findings_path and findings_path.exists():
        try:
            findings_doc = _load_json(findings_path)
            findings = list((findings_doc or {}).get('findings') or [])
            for f in findings:
                for ev in f.get('evidence') or []:
                    eid = ev.get('event_id')
                    if eid:
                        referenced_event_ids.add(str(eid))
        except Exception:
            findings_doc = None
            findings = []

    events = _iter_events(events_path)
    events_considered = len(events)
    evsum = _event_stream_summary(events) if events else {'type_rows': [], 'samples': {}}

    # Load clusters if available
    clusters: List[Dict[str, Any]] = []
    if clusters_path and clusters_path.exists():
        try:
            clusters = list(_load_json(clusters_path) or [])
        except Exception:
            clusters = []
    clusters_considered = len(clusters)

    # Timeline construction
    timeline_rows: List[str] = []
    if enabled:
        include_types = set(tl_cfg.get('include_event_types') or [])
        max_rows = int(tl_cfg.get('max_rows', 40))
        bucket_seconds = int(tl_cfg.get('bucket_seconds', 120))
        always_keep = (tl_cfg.get('always_keep') or {})
        keep_critical = always_keep.get('severity_at_least') == 'critical'

        # Chatty handling
        chatty_handling = (tl_cfg.get('chatty_handling') or {})
        prefer_cluster_for: Set[str] = set()
        for et, conf in chatty_handling.items():
            if isinstance(conf, dict) and conf.get('prefer_clusters', False):
                prefer_cluster_for.add(et)

        # Build a unified list of items with dt
        items: List[Tuple[datetime, str, Dict[str, Any]]] = []  # (dt, kind, obj)

        # Include clusters as timeline items (use start_ts)
        if clusters:
            for c in clusters:
                st = c.get('start_ts')
                dt = rfc3339_to_dt(str(st)) if st else None
                if not dt:
                    continue
                items.append((dt, 'cluster', c))

        # Include events (optionally suppress chatty types if clusters exist)
        have_clusters_for = {c.get('event_type') for c in clusters}
        for ev in events:
            et = ev.get('event_type')
            if include_types and et not in include_types:
                continue
            if et in prefer_cluster_for and et in have_clusters_for:
                # Keep only if critical or referenced by findings
                if (keep_critical and _severity_rank(ev.get('severity', '')) >= 3) or (ev.get('event_id') in referenced_event_ids):
                    pass
                else:
                    continue
            items.append((ev['_dt'], 'event', ev))

        # Always-keep rules
        keep_set: Set[int] = set()  # indices into items
        first_occurrence: Set[str] = set()
        for i, (_dt, kind, obj) in enumerate(items):
            if kind == 'event':
                et = obj.get('event_type') or ''
                sev = obj.get('severity') or ''
                if keep_critical and _severity_rank(sev) >= 3:
                    keep_set.add(i)
                if always_keep.get('first_event_type_occurrence', False) and et and et not in first_occurrence:
                    first_occurrence.add(et)
                    keep_set.add(i)
                if always_keep.get('referenced_by_findings', False) and obj.get('event_id') in referenced_event_ids:
                    keep_set.add(i)
            elif kind == 'cluster':
                if always_keep.get('cluster_rows', True):
                    keep_set.add(i)

        # Downsample remaining by time buckets + per event_type limit
        buckets: Dict[Tuple[int, str], int] = {}  # (bucket_index, event_type)->item_index
        for i, (dt, kind, obj) in enumerate(items):
            if i in keep_set:
                continue
            if kind != 'event':
                continue
            et = obj.get('event_type') or 'unknown'
            b = int(dt.timestamp()) // bucket_seconds
            key = (b, et)
            if key not in buckets:
                buckets[key] = i

        selected_indices = sorted(set(keep_set) | set(buckets.values()), key=lambda idx: items[idx][0])

        # Enforce max_rows
        if len(selected_indices) > max_rows:
            # Keep earliest items; this is deterministic and aligns with "pick earliest".
            selected_indices = selected_indices[:max_rows]

        for idx in selected_indices:
            _dt, kind, obj = items[idx]
            if kind == 'cluster':
                timeline_rows.append(_cluster_row(obj))
            else:
                timeline_rows.append(_event_row(obj))

    # Report sections
    schema = (cfg_raw.get('outputs') or {}).get('schemas', {}).get('report', 'report-md-v1')
    generated_utc = _utc_now()
    lines: List[str] = []
    lines.append(f"<!-- tool={tool.get('name')} version={tool.get('version')} schema={schema} generated={generated_utc} -->")
    lines.append("# sos_triage Report")
    lines.append("")

    # Event stream summary
    lines.append("## Event stream summary")
    if evsum.get('type_rows'):
        lines.append("|     start                      |    end                         | event_type              | peer:port           | nm | cluster_id |")
        lines.append("|--------------------------------|--------------------------------|-------------------------|---------------------|---:|------------|")
        for r in evsum['type_rows'][:20]:
            peers = ", ".join(r.get('top_peers') or [])
            lines.append(f"| {r['event_type']} | {r['count']} | {r['first_ts']} | {r['last_ts']} | {peers} |")
        lines.append("")
        s = evsum.get('samples') or {}
        lines.append("High-value samples (first / worst / last):")
        if s.get('first'):
            lines.append(f"- first: {_event_row(s['first'])}")
        if s.get('worst'):
            lines.append(f"- worst: {_event_row(s['worst'])}")
        if s.get('last'):
            lines.append(f"- last:  {_event_row(s['last'])}")
    else:
        lines.append("- No timestamped events available (or event emission filtered everything out).")
    lines.append("")

    # Cluster summaries
    lines.append("## Cluster summaries")
    if clusters:
        clusters_sorted = sorted(
            clusters,
            key=lambda c: (
                str(c.get('start_ts') or ''),
                str(c.get('event_type') or ''),
                str(c.get('peer') or ''),
                int(c.get('port') or 0),
                str(c.get('cluster_id') or c.get('cluster_hash') or ''),
            ),
        )
        lines.append("| start | end | event_type | peer:port | count | cluster_id |")
        lines.append("|---|---|---|---|---:|---|")
        for c in clusters_sorted[:50]:
            start = c.get('start_ts') or ''
            end = c.get('end_ts') or ''
            et = c.get('event_type') or ''
            peer = c.get('peer') or ''
            port = c.get('port') or ''
            count = c.get('count') or 0
            cid = c.get('cluster_id') or c.get('cluster_hash') or ''
            lines.append(f"| {start} | {end} | {et} | {peer}:{port} | {count} | {cid} |")
        lines.append("")
        # Add quick implications (deterministic ordering)
        for c in clusters_sorted[:10]:
            et = str(c.get('event_type') or '')
            port = c.get('port')
            cid = c.get('cluster_id') or c.get('cluster_hash') or ''
            lines.append(f"- {cid}: {_cluster_implication(et, int(port) if port is not None else None)}")
    else:
        lines.append("- No clusters emitted (or clustering disabled).")

    lines.append("")


    # Findings summary
    lines.append("## Findings")
    if findings:
        for f in findings:
            fid = f.get('finding_id')
            title = f.get('title')
            sev = (f.get('severity') or '').upper()
            conf = f.get('confidence')
            w = f.get('window') or {}
            start = w.get('start_ts')
            end = w.get('end_ts')
            icon = SEV_ICON.get(sev, "")
            icon_prefix = (icon + " ") if icon else ""
            lines.append(f"- {icon_prefix}**{sev}** ({conf}) `{fid}` — {title} ({start} → {end})")
            causes = ((f.get('outputs') or {}).get('likely_causes') or [])
            if causes:
                for c in causes[:3]:
                    lines.append(f"  - Likely cause: {c}")
    else:
        lines.append("- No findings triggered (or findings.json not present).")

    lines.append("")
    lines.append("## What happened")
    lines.append("- (Autofill) Control-plane instability indicators detected (raft peer connectivity failures / memberlist timeouts), with potential leadership churn.")
    lines.append("- (Autofill) Docker daemon restarts, if present, can amplify raft instability when performed on managers.")
    lines.append("")
    lines.append("## Timeline of notable events")
    if timeline_rows:
        for r in timeline_rows:
            lines.append(f"- {r}")
    else:
        lines.append("- Timeline disabled or no timestamped events available.")

    lines.append("")
    lines.append("## Analysis conditions")
    parts = []
    if analysis_context.get('extract_mode'):
        parts.append(f"extract_mode={analysis_context.get('extract_mode')}")
    if analysis_context.get('max_bytes') is not None:
        parts.append(f"max_bytes={analysis_context.get('max_bytes')}")
    if analysis_context.get('max_events') is not None:
        parts.append(f"max_events={analysis_context.get('max_events')}")
    if analysis_context.get('bytes_read') is not None:
        parts.append(f"bytes_read={analysis_context.get('bytes_read')}")
    if analysis_context.get('scan_truncated'):
        parts.append('scan_truncated=true')
    if analysis_context.get('events_truncated'):
        parts.append('events_truncated=true')
    if analysis_context.get('allowed_severities'):
        parts.append(f"severities={','.join(analysis_context.get('allowed_severities'))}")
    if parts:
        lines.append('This report was generated with: ' + ', '.join(parts) + '.')
    else:
        lines.append('This report was generated with default analysis settings.')
    lines.append("")

    outputs = {}
    if isinstance(analysis_context, dict):
        outputs = analysis_context.get('outputs') or {}
    ev_fn = outputs.get('events') or 'events.jsonl'
    cl_fn = outputs.get('clusters') or 'clusters.json'
    fi_fn = outputs.get('findings') or 'findings.json'
    re_fn = outputs.get('report') or 'report.md'
    me_fn = outputs.get('meta') or 'meta.json'

    lines.append("## Evidence")
    lines.append(f"- Primary evidence is in `{ev_fn}` (line-level) and `{cl_fn}` (burst summaries).")
    if findings:
        lines.append(f"- Findings evidence samples are embedded in `{fi_fn}`.")

    # Final console output guide (mirrors CLI, but embedded for downstream tooling)
    lines.append("\n## Output guide")
    lines.append(f"- `{ev_fn}`   = raw normalized matches (one per emitted event)")
    lines.append(f"- `{cl_fn}`  = burst summaries for chatty patterns")
    lines.append(f"- `{fi_fn}`  = heuristics fired with evidence samples")
    lines.append(f"- `{re_fn}`      = RCA skeleton built from findings + timeline")
    lines.append(f"- `{me_fn}`      = truth ledger (scan coverage, limits, warnings, stats)")

    footer = {
        'tool': tool,
        'schema': schema,
        'generated_utc': generated_utc,
        'analysis_context': analysis_context,
    }
    lines.append(f"<!-- provenance: {json.dumps(footer, ensure_ascii=False)} -->")

    out_text = "\n".join(lines) + "\n"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(out_text, encoding='utf-8')

    stats = {
        'report_generated': True,
        'rows_emitted': len(timeline_rows),
        'events_considered': events_considered,
        'clusters_considered': clusters_considered,
        'findings_included': len(findings),
        'schema_version': schema,
    }
    return out_text, stats
