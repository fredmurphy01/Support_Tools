""" analyzer.py version 1.1.0 """
from __future__ import annotations

from pathlib import Path

from .config import load_config
from .extract import extract_sosreport
from .discover import discover_files
from .scanner import scan_files
from .events import write_events_jsonl
from .cluster import build_clusters
from .findings import generate_findings
from .report import generate_report
from .meta import build_meta, write_meta
from .util import default_run_id
from .errors import SosTriageError, WriteError


def analyze(
    sos_path: Path,
    config_path: Path,
    outdir: Path,
    extract_dir: Path,
    *,
    extract_mode: str = 'fast',
    keep_extracted: bool = False,
    cleanup_extracted: bool = False,
    no_overwrite: bool = False,
    tool_version: str = '0.1.0',
    case_id: str | None = None,
    run_id: str | None = None,
    verbose: bool = False,
    max_events: int | None = None,
    max_bytes: int | None = None,
    no_cluster: bool = False,
    allowed_severities: set[str] | None = None,
    output_tag: str | None = None,
):
    run_id = run_id or default_run_id()
    outdir.mkdir(parents=True, exist_ok=True)

    def _tagged(name: str, ext: str) -> str:
        return f"{name}-{output_tag}{ext}" if output_tag else f"{name}{ext}"

    events_path = outdir / _tagged('events', '.jsonl')
    clusters_path = outdir / _tagged('clusters', '.json')
    findings_path = outdir / _tagged('findings', '.json')
    meta_path = outdir / _tagged('meta', '.json')
    report_path = outdir / _tagged('report', '.md')

    if no_overwrite:
        existing = [p.name for p in (events_path, clusters_path, findings_path, report_path, meta_path) if p.exists()]
        if existing:
            raise WriteError(
                stage='write',
                code='OUTPUT_EXISTS',
                message='Output files exist and --no-overwrite set',
                details={'outdir': str(outdir), 'existing': existing},
            )

    errors: list = []
    warnings: list = []
    extracted_root = None
    scan_stats: dict = {}
    events_stats: dict | None = None
    clusters_stats: dict | None = None
    findings_stats: dict | None = None
    report_stats: dict | None = None
    scan_runtime = {'bytes_read': 0, 'scan_truncated': False}

    try:
        cfg = load_config(config_path)
        ext = extract_sosreport(sos_path, extract_dir, keep_extracted, extract_mode=extract_mode)
        extracted_root = ext.extracted_root

        files, stats = discover_files(extracted_root, cfg.sources)
        scan_stats = {
            'files': {
                'considered': stats.files_considered,
                'matched_includes': stats.files_matched_includes,
                'excluded': stats.files_excluded,
                'skipped_too_large': stats.files_skipped_too_large,
                'skipped_unreadable': stats.files_skipped_unreadable,
                'scanned': stats.files_scanned,
            },
            'bytes': {
                'scanned': stats.bytes_scanned,
                'skipped_too_large': stats.bytes_skipped_too_large,
            },
            'skip_reasons': stats.skip_reasons,
        }

        # coverage warning: journalctl stubs but no tailed targets
        journal_stubs = list(extracted_root.glob('**/sos_commands/logs/journalctl*'))
        tailed = list(extracted_root.glob('**/sos_strings/logs/journalctl*.tailed*'))
        if journal_stubs and not tailed and extract_mode != 'full':
            warnings.append('journalctl stubs detected but .tailed targets missing; try --extract-mode journal or full')

        candidates = scan_files(files, cfg, max_bytes=max_bytes, runtime=scan_runtime, allowed_severities=allowed_severities)
        ev_res = write_events_jsonl(events_path, cfg, candidates, max_events=max_events)

        if max_bytes is not None and scan_runtime.get('scan_truncated'):
            warnings.append(f'Scan stopped early due to --max-bytes limit ({max_bytes} bytes)')

        events_stats = {
            'events_emitted': ev_res.events_emitted,
            'events_with_parsed_timestamps': ev_res.events_with_parsed_timestamps,
            'events_without_timestamps': ev_res.events_without_timestamps,
            'signatures_matched': ev_res.signatures_matched,
            'events_truncated': ev_res.events_truncated,
        }
        if ev_res.events_truncated and max_events is not None:
            warnings.append(f'Event emission stopped early due to --max-events limit ({max_events})')
        if ev_res.events_emitted == 0:
            warnings.append('No events matched signatures; check source coverage and patterns.')

        # Step 3: clustering
        grouping = (cfg.raw.get('context_grouping', {}) or {})
        if grouping.get('enabled', False) and not no_cluster and ev_res.events_emitted > 0:
            _, cstats = build_clusters(events_path, clusters_path, cfg)
            clusters_stats = {
                'clusters_emitted': cstats.clusters_emitted,
                'clusters_by_event_type': cstats.clusters_by_event_type,
                'chatty_events_considered': cstats.chatty_events_considered,
            }
            if cstats.clusters_emitted == 0:
                warnings.append('Clustering enabled but no clusters met min_events threshold.')
        elif grouping.get('enabled', False) and no_cluster:
            warnings.append('Clustering disabled via --no-cluster')

        # Step 4: findings
        heuristics = cfg.raw.get('heuristics') or []
        if heuristics and ev_res.events_emitted > 0:
            _, fstats = generate_findings(events_path=events_path, out_path=findings_path, cfg_raw=cfg.raw)
            findings_stats = fstats
            if fstats.get('findings_emitted', 0) == 0:
                warnings.append('Heuristics evaluated but no findings triggered.')

        # Step 5: report.md
        tl_cfg = (cfg.raw.get('timeline') or {})
        if isinstance(tl_cfg, dict) and tl_cfg.get('enabled', False) and ev_res.events_emitted > 0:
            # report_path is computed above (may include output_tag)
            _, rstats = generate_report(
                cfg_raw=cfg.raw,
                events_path=events_path,
                clusters_path=clusters_path if clusters_path.exists() else None,
                findings_path=findings_path if findings_path.exists() else None,
                out_path=report_path,
                tool={'name': 'sos-swarm-triage', 'version': tool_version},
                analysis_context={
                    'extract_mode': extract_mode,
                    'max_events': max_events,
                    'max_bytes': max_bytes,
                    'bytes_read': scan_runtime.get('bytes_read'),
                    'scan_truncated': scan_runtime.get('scan_truncated'),
                    'events_truncated': (events_stats or {}).get('events_truncated') if events_stats else None,
                    'allowed_severities': sorted(list(allowed_severities)) if allowed_severities is not None else None,
                    'outputs': {
                        'events': events_path.name,
                        'clusters': clusters_path.name,
                        'findings': findings_path.name,
                        'report': report_path.name,
                        'meta': meta_path.name,
                        'output_tag': output_tag,
                    },
                },
            )
            report_stats = rstats

    except SosTriageError as e:
        errors.append({'stage': e.stage, 'code': e.code, 'message': e.message, 'details': e.details})
        raise
    except Exception as e:
        errors.append({'stage': 'unexpected', 'code': 'UNEXPECTED', 'message': str(e), 'details': {}})
        raise
    finally:
        # Post-run cleanup (recorded in meta)
        cleanup_performed = False
        cleanup_error = None
        if cleanup_extracted:
            try:
                import shutil
                if extract_dir.exists():
                    shutil.rmtree(extract_dir)
                cleanup_performed = True
            except Exception as cleanup_exc:
                cleanup_error = str(cleanup_exc)
                warnings.append(f"cleanup-extracted failed: {cleanup_error}")
                if verbose:
                    print(f"[WARN] cleanup-extracted failed: {cleanup_error}")

        # attempt meta write if possible
        try:
            meta_obj = build_meta(
                config_path=str(config_path),
                sosreport_path=str(sos_path),
                extracted_root=str(extracted_root) if extracted_root else None,
                outdir=str(outdir),
                extract_dir=str(extract_dir),
                extract_mode=extract_mode,
                scan_stats=scan_stats,
                events_stats=events_stats,
                clusters_stats=clusters_stats,
                findings_stats=findings_stats,
                report_stats=report_stats,
                tool={'name': 'sos-swarm-triage', 'version': tool_version},
                invocation={'argv': [], 'cwd': str(Path.cwd()), 'run_id': run_id, 'case_id': case_id},
                limits={
                    'max_events': max_events,
                    'max_bytes': max_bytes,
                    'bytes_read': scan_runtime.get('bytes_read'),
                    'scan_truncated': scan_runtime.get('scan_truncated'),
                    'events_truncated': (events_stats or {}).get('events_truncated') if events_stats else None,
                },
                filters={
                    'allowed_severities': sorted(list(allowed_severities)) if allowed_severities is not None else None,
                },
                output_tag=output_tag,
                output_files={
                    'meta': meta_path.name,
                    'events': events_path.name,
                    'clusters': clusters_path.name if clusters_stats is not None else None,
                    'findings': findings_path.name if findings_stats is not None else None,
                    'report': report_path.name if report_stats is not None else None,
                },
                errors=errors,
                warnings=warnings,
            )
            meta_obj.setdefault('extraction', {})
            meta_obj['extraction']['cleanup_requested'] = bool(cleanup_extracted)
            meta_obj['extraction']['cleanup_performed'] = bool(cleanup_performed)
            if cleanup_error:
                meta_obj['extraction']['cleanup_error'] = cleanup_error
            write_meta(meta_path, meta_obj)
        except Exception as meta_exc:
            if verbose:
                print(f"[WARN] failed to write meta.json: {meta_exc}")

    return {
        'events': events_path,
        'clusters': clusters_path,
        'findings': findings_path,
        'report': report_path,
        'meta': meta_path,
        'output_tag': output_tag,
    }
