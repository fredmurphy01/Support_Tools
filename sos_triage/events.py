""" events.py version 1.1.0 """
from __future__ import annotations

import json
from pathlib import Path
from collections import defaultdict
from typing import Iterable

from .types import Config, EventCandidate, EventsWriteResult
from .errors import WriteError
from .util import sha1_hex, normalize_whitespace


def write_events_jsonl(out_path: Path, config: Config, candidates: Iterable[EventCandidate], *, max_events: int | None = None) -> EventsWriteResult:
    """
    Write events.jsonl (events-v1), assigning sequential event_id and stable event_hash.

    If max_events is set, stop emitting after N events and mark events_truncated in the result.
    """
    prefix = config.defaults.get('event_id', {}).get('sequential_prefix', 'evt_')
    width = int(config.defaults.get('event_id', {}).get('sequential_width', 6))
    hex_chars = int(config.defaults.get('event_id', {}).get('stable_hash', {}).get('hex_chars', 12))
    canon_fields = list(config.defaults.get('event_id', {}).get('stable_hash', {}).get('canonical_fields', []))

    sig_counts = defaultdict(int)
    emitted = 0
    with_ts = 0
    without_ts = 0
    truncated = False

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as out:
            for ev in candidates:
                if max_events is not None and emitted >= max_events:
                    truncated = True
                    break

                emitted += 1
                event_id = f"{prefix}{emitted:0{width}d}"

                ts_norm_or_raw = ev.ts or ev.ts_raw or ''
                if ev.ts:
                    with_ts += 1
                else:
                    without_ts += 1

                msg_norm = normalize_whitespace(ev.message)

                parts = []
                for f in canon_fields:
                    if f == 'source_relpath':
                        parts.append(ev.source_relpath)
                    elif f == 'line_number':
                        parts.append(str(ev.line_number))
                    elif f == 'signature_id':
                        parts.append(ev.signature_id)
                    elif f == 'ts_normalized_or_raw':
                        parts.append(ts_norm_or_raw)
                    elif f == 'event_type':
                        parts.append(ev.event_type)
                    elif f == 'peer':
                        parts.append(ev.peer or '')
                    elif f == 'port':
                        parts.append(str(ev.port or ''))
                    elif f == 'message_normalized':
                        parts.append(msg_norm)
                    else:
                        parts.append('')

                event_hash = sha1_hex('|'.join(parts))[:hex_chars]
                sig_counts[ev.signature_id] += 1

                obj = {
                    'schema_version': config.outputs.get('schemas', {}).get('events', 'events-v1'),
                    'event_id': event_id,
                    'event_hash': event_hash,
                    'signature_id': ev.signature_id,
                    'event_type': ev.event_type,
                    'severity': ev.severity,
                    'confidence': ev.confidence,
                    'ports': ev.ports,
                    'ts': ev.ts,
                    'ts_raw': ev.ts_raw,
                    'source_relpath': ev.source_relpath,
                    'line_number': ev.line_number,
                    'peer': ev.peer,
                    'port': ev.port,
                    'reason': ev.reason,
                    'message': ev.message,
                    'excerpt': ev.excerpt,
                    'context': {
                        'pre': ev.context_pre,
                        'post': ev.context_post,
                    },
                }
                out.write(json.dumps(obj, ensure_ascii=False) + '\n')

    except Exception as e:
        raise WriteError(stage='write', code='WRITE_EVENTS_FAILED', message=str(e), details={'out_path': str(out_path)})

    return EventsWriteResult(
        events_emitted=emitted,
        events_with_parsed_timestamps=with_ts,
        events_without_timestamps=without_ts,
        signatures_matched=dict(sig_counts),
        events_truncated=truncated,
    )
