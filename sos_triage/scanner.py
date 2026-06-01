""" scanner.py version 1.1.0 """
from __future__ import annotations
from collections import deque
from typing import Iterator
from .types import FileTarget, Config, EventCandidate
from .util import parse_timestamp_best_effort, truncate_line

def scan_files(files: list[FileTarget], config: Config, *, match_cap_per_line: int=3, max_bytes: int|None=None, runtime: dict|None=None, allowed_severities: set[str]|None=None) -> Iterator[EventCandidate]:
    dctx = config.defaults.get('context', {}) or {}
    pre_default = int(dctx.get('pre', 1))
    post_default = int(dctx.get('post', 2))
    max_line_length = int(dctx.get('max_line_length', 500))
    trim_ws = bool(dctx.get('trim_whitespace', True))
    excerpt_max = int((config.defaults.get('excerpt', {}) or {}).get('max_chars', 240))
    if runtime is None:
        runtime = {}
    runtime.setdefault('bytes_read', 0)
    runtime.setdefault('scan_truncated', False)

    for ft in files:
        prebuf = deque([], maxlen=max(1, pre_default))
        try:
            with open(ft.abspath, 'r', encoding=config.sources.get('read',{}).get('encoding','utf-8'),
                      errors=config.sources.get('read',{}).get('errors','ignore')) as f:
                for lineno, line in enumerate(f, start=1):
                    runtime['bytes_read'] += len(line.encode('utf-8', errors='ignore'))
                    if max_bytes is not None and runtime['bytes_read'] > max_bytes:
                        runtime['scan_truncated'] = True
                        return
                    raw_line = line.rstrip('\n')
                    msg = raw_line.strip() if trim_ws else raw_line
                    msg_trunc = truncate_line(msg, max_line_length)
                    # Evaluate signatures in the YAML list order for deterministic event emission.
                    matches = []
                    for sig in config.signatures:
                        sid = sig.id
                        comp = config.compiled.get(sid)
                        if not comp:
                            continue
                        for pat in comp['patterns']:
                            if pat.search(msg):
                                matches.append(sid)
                                break
                    if matches:
                        uniq=[]
                        for sid in matches:
                            if sid not in uniq:
                                uniq.append(sid)
                            if len(uniq) >= match_cap_per_line:
                                break
                        for sid in uniq:
                            sig = config.compiled[sid]['sig']
                            if allowed_severities is not None:
                                sev = (sig.severity or "").lower()
                                if sev not in allowed_severities:
                                    continue
                            ctx = sig.context or {}
                            pre_n = int(ctx.get('pre', pre_default))
                            post_n = int(ctx.get('post', post_default))
                            ctx_pre = list(prebuf)[-pre_n:]
                            ctx_post = []  # fast path: no lookahead; Step 3+ can add grouping anyway
                            ts, ts_raw = parse_timestamp_best_effort(msg)
                            excerpt = truncate_line(msg, excerpt_max)
                            peer=None; port=None; reason=None
                            caps = config.compiled[sid]['capture']
                            if caps:
                                if 'peer' in caps:
                                    m=caps['peer'].search(msg)
                                    if m: peer=m.group(1)
                                if 'port' in caps:
                                    m=caps['port'].search(msg)
                                    if m:
                                        try: port=int(m.group(1))
                                        except: port=None
                                if 'reason' in caps:
                                    m=caps['reason'].search(msg)
                                    if m: reason=m.group(1)
                            yield EventCandidate(
                                signature_id=sid,
                                event_type=sig.event_type,
                                severity=sig.severity,
                                confidence=float(sig.confidence_weight),
                                ports=list(sig.ports),
                                ts=ts,
                                ts_raw=ts_raw,
                                source_relpath=ft.relpath,
                                line_number=lineno,
                                message=msg_trunc,
                                excerpt=excerpt,
                                peer=peer,
                                port=port,
                                reason=reason,
                                context_pre=ctx_pre,
                                context_post=ctx_post
                            )
                    prebuf.append(msg_trunc)
        except Exception:
            continue
