""" discover.py version 1.1.0 """
from __future__ import annotations
import os, fnmatch
from pathlib import Path
from .types import FileTarget, ScanStats
from .errors import ScanError

def _match_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in patterns)

def discover_files(extracted_root: Path, sources: dict) -> tuple[list[FileTarget], ScanStats]:
    include_globs = list(sources.get('include_globs', []))
    exclude_globs = list(sources.get('exclude_globs', []))
    limits = sources.get('file_limits', {}) or {}
    max_files = int(limits.get('max_files', 5000))
    max_file_size = int(limits.get('max_file_size_bytes', 100*1024*1024))
    max_total = int(limits.get('max_total_size_bytes', 512*1024*1024))

    # Collect *and sort* file inventory so later include_glob matching is deterministic.
    # pathlib.rglob() order is filesystem-dependent.
    all_files = []
    for p in extracted_root.rglob('*'):
        if p.is_file():
            rel = str(p.relative_to(extracted_root))
            all_files.append((rel, p))
    all_files.sort(key=lambda rp: rp[0])
    stats=ScanStats(files_considered=len(all_files))
    # include in order, deterministic
    ordered=[]
    seen=set()
    for pat in include_globs:
        for rel,p in all_files:
            if rel in seen: 
                continue
            if fnmatch.fnmatch(rel, pat):
                ordered.append((rel,p)); seen.add(rel)
    stats.files_matched_includes=len(ordered)

    kept=[]
    total=0
    for rel,p in ordered:
        if _match_any(rel, exclude_globs):
            stats.files_excluded += 1
            stats.skip_reasons['excluded_by_glob']=stats.skip_reasons.get('excluded_by_glob',0)+1
            continue
        try:
            sz = p.stat().st_size
        except Exception:
            stats.files_skipped_unreadable += 1
            stats.skip_reasons['unreadable']=stats.skip_reasons.get('unreadable',0)+1
            continue
        if sz > max_file_size:
            stats.files_skipped_too_large += 1
            stats.bytes_skipped_too_large += sz
            stats.skip_reasons['too_large']=stats.skip_reasons.get('too_large',0)+1
            continue
        if len(kept) >= max_files:
            stats.skip_reasons['limit_max_files']=stats.skip_reasons.get('limit_max_files',0)+1
            continue
        if total + sz > max_total:
            stats.skip_reasons['limit_total_bytes']=stats.skip_reasons.get('limit_total_bytes',0)+1
            continue
        kept.append(FileTarget(relpath=rel, abspath=p, size_bytes=sz))
        total += sz
    stats.files_scanned=len(kept)
    stats.bytes_scanned=total

    if not kept:
        raise ScanError(stage='discover', code='NO_FILES_MATCHED', message='No files to scan after include/exclude/limits', details={'extracted_root': str(extracted_root)})
    return kept, stats
