""" meta.py version 1.1.0 """
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from .util import utc_now_rfc3339


def build_meta(
    *,
    config_path: str,
    sosreport_path: str,
    extracted_root: Optional[str],
    outdir: str,
    extract_dir: str,
    extract_mode: str,
    scan_stats: dict,
    events_stats: Optional[dict],
    clusters_stats: Optional[dict],
    findings_stats: Optional[dict],
    report_stats: Optional[dict],
    tool: dict,
    invocation: dict,
    errors: list,
    warnings: list,
    limits: Optional[dict] = None,
    filters: Optional[dict] = None,
    output_tag: Optional[str] = None,
    output_files: Optional[dict] = None,
) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        'schema_version': 'meta-v1',
        'analysis_time_utc': utc_now_rfc3339(),
        'tool': tool,
        'invocation': invocation,
        'artifact': {
            'type': 'sosreport',
            'input_path': sosreport_path,
        },
        'config': {
            'config_path': config_path,
        },
        'extraction': {
            'extract_dir': extract_dir,
            'extracted_root': extracted_root,
            'extract_mode': extract_mode,
        },
        'scan': scan_stats,
        'limits': limits or {},
        'filters': filters or {},
        'warnings': warnings,
        'errors': errors,
    }

    stats: Dict[str, Any] = {}
    if events_stats:
        stats.update(events_stats)
    if clusters_stats:
        stats['clusters'] = clusters_stats
    if findings_stats:
        stats['findings'] = findings_stats
    if report_stats:
        stats['report'] = report_stats
    meta['stats'] = stats

    # Outputs map: logical artifact name -> actual filename (basename).
    # When output_tag is provided, filenames may be suffixed.
    files = {}
    if output_files and isinstance(output_files, dict):
        # allow None values for conditional artifacts
        files = {k: v for k, v in output_files.items() if v}
    else:
        files = {
            'meta': 'meta.json',
            'events': 'events.jsonl',
        }
        if clusters_stats is not None:
            files['clusters'] = 'clusters.json'
        if findings_stats is not None:
            files['findings'] = 'findings.json'
        if report_stats is not None:
            files['report'] = 'report.md'

    meta['outputs'] = {
        'outdir': outdir,
        'output_tag': output_tag,
        'files': files,
    }
    return meta


def write_meta(out_path: Path, meta_obj: Dict[str, Any]) -> None:
    tmp = out_path.with_suffix('.tmp')
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(meta_obj, indent=2, ensure_ascii=False))
    tmp.replace(out_path)
