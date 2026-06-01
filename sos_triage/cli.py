""" cli.py version 1.1.0 """
from __future__ import annotations

import argparse
import json
import re
import sys
import signal
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .analyzer import analyze
from .errors import ConfigError, ExtractionError, ScanError, WriteError, SosTriageError
from .util import sanitize_output_tag
from sos_triage import __version__



# Locked mapping: --level 1–4 maps to severities; --severity overrides --level.
LEVEL_TO_SEVERITIES: Dict[int, Set[str]] = {
    1: {"critical"},
    2: {"critical", "high"},
    3: {"critical", "high", "medium"},
    4: {"critical", "high", "medium", "info"},
}


def _parse_severity_list(value: Optional[str]) -> Optional[Set[str]]:
    if not value:
        return None
    parts = [p.strip().lower() for p in value.split(",") if p.strip()]
    if not parts:
        return None

    allowed = {"critical", "high", "medium", "info"}
    bad = [p for p in parts if p not in allowed]
    if bad:
        raise argparse.ArgumentTypeError(
            f"invalid severity: {', '.join(bad)} (allowed: critical,high,medium,info)"
        )
    return set(parts)

def _parse_bool(value: Optional[str]) -> bool:
    """Parse a user-supplied boolean for CLI flags.

    Accepts: true/false, yes/no, 1/0 (case-insensitive).
    """
    if value is None:
        return True
    v = str(value).strip().lower()
    if v in {"true", "t", "yes", "y", "1"}:
        return True
    if v in {"false", "f", "no", "n", "0"}:
        return False
    raise argparse.ArgumentTypeError("expected a boolean: true/false")



def _help_top() -> str:
    return (
        f"sos_triage {__version__} — Structured sosreport analysis for deterministic RCA\n\n"
        "Description:\n"
        "  Extracts and scans a sosreport archive, emitting structured\n"
        "  observations (events), compressing burst patterns (clusters),\n"
        "  deriving interpretive conclusions (findings), and generating\n"
        "  a human-readable report (report.md).\n\n"
        "Analysis pipeline:\n"
        "  events → clusters → findings → report\n"
        "  meta.json records execution conditions and scan limits.\n\n"
        "Commands:\n"
        "  analyze        Analyze a sosreport and generate outputs\n"
        "  lint-config    Validate sos-signatures.yaml configuration\n\n"
        "Run 'sos_triage <command> --help' for command-specific options."
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sos_triage",
        description=_help_top(),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    p.add_argument("--version", action="version", version=f"sos_triage {__version__}")


    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")

    # --- analyze ---
    a = sub.add_parser(
        "analyze",
        help="Analyze a sosreport archive and generate structured outputs",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    a.description = (
        "Analyze a sosreport archive and write:\n"
        "  events.jsonl   Atomic normalized observations\n"
        "  clusters.json  Burst compression of chatty patterns\n"
        "  findings.json  Heuristic conclusions with evidence\n"
        "  report.md      Human-readable RCA summary\n"
        "  meta.json      Execution ledger and scan conditions\n"
    )

    a.add_argument("sosreport", help="Path to sosreport archive (.tar, .tar.xz, etc.)")

    a.add_argument(
        "--configs-dir",
        default="./configs",
        help="Directory containing sos-signatures.yaml (default: ./configs)",
    )
    a.add_argument(
        "--config",
        default="sos-signatures.yaml",
        help="Signature configuration file name or path (default: sos-signatures.yaml)",
    )
    a.add_argument(
        "--outdir",
        default="./outdir",
        help="Output directory (default: ./outdir)",
    )

    a.add_argument(
        "--output-tag",
        default=None,
        help=(
            "Suffix tag to append to output filenames (written under --outdir).\n"
            "Example: --output-tag hostname123\n"
            "Produces: report-hostname123.md, findings-hostname123.json, etc."
        ),
    )
    a.add_argument(
        "--extract-dir",
        default=None,
        help="Extraction directory (default: <outdir>/extracted)",
    )

    # Extraction lifecycle
    a.add_argument(
        "--keep-extracted",
        action="store_true",
        default=False,
        help="Reuse existing extracted content (skip re-extract)",
    )
    a.add_argument(
        "--cleanup-extracted",
        action="store_true",
        default=False,
        help="Delete extracted content at end of run (success or failure)",
    )

    a.add_argument(
        "--no-overwrite",
        action="store_true",
        default=False,
        help="Fail if output files already exist",
    )
    a.add_argument(
        "--extract-mode",
        choices=["fast", "journal", "full"],
        default="fast",
        help=(
            "Control scan scope:\n"
            "  fast    = targeted high-value logs (default)\n"
            "  journal = journal-centric analysis\n"
            "  full    = full archive scan"
        ),
    )

    # Quick triage guardrails
    a.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Stop after emitting N events",
    )
    a.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="Stop scanning after reading N total bytes",
    )

    # Severity filtering
    a.add_argument(
        "--level",
        type=int,
        choices=[1, 2, 3, 4],
        default=4,
        help=(
            "Numeric severity level:\n"
            "  1 = critical\n"
            "  2 = critical + high\n"
            "  3 = critical + high + medium\n"
            "  4 = critical + high + medium + info\n"
            "(default: 4)"
        ),
    )
    a.add_argument(
        "--severity",
        type=_parse_severity_list,
        default=None,
        help="Comma-separated severities (overrides --level), e.g. critical,high",
    )

    a.add_argument(
        "--no-cluster",
        action="store_true",
        default=False,
        help="Disable clustering even if enabled in config",
    )

    a.add_argument(
        "--case-id",
        default=None,
        help="Case/ticket identifier to include in meta.json",
    )
    a.add_argument(
        "--run-id",
        default=None,
        help="Run identifier (defaults to UTC timestamp)",
    )
    a.add_argument(
        "--tool-version",
        default=__version__,
        help="Tool version string to stamp into meta.json",
    )

    g = a.add_mutually_exclusive_group()
    g.add_argument("--verbose", action="store_true", default=False, help="Verbose console output")
    g.add_argument("--quiet", action="store_true", default=False, help="Suppress console output except errors")

    a.add_argument(
        "--print-report",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool,
        metavar="{true|false}",
        help=(
            "Print the final report.md contents to the console (default: true).\n"
            "Use '--print-report false' to disable. Suppressed by --quiet."
        ),
    )

    a.epilog = (
        "Examples:\n"
        "  sos_triage analyze sosreport.tar.xz\n"
        "  sos_triage analyze sos.tar.xz --level 2\n"
        "  sos_triage analyze sos.tar.xz --severity critical,high\n"
        "  sos_triage analyze sos.tar.xz --extract-mode full --cleanup-extracted\n"
    )

    # --- lint-config ---
    l = sub.add_parser(
        "lint-config",
        help="Validate sos-signatures.yaml configuration",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    l.description = (
        "Validate sos-signatures.yaml for schema correctness, duplicate IDs, invalid regex\n"
        "patterns, and cross-reference consistency.\n\n"
        "Exit codes:\n"
        "  0 = Success (warnings allowed)\n"
        "  2 = Errors detected\n"
    )
    l.add_argument(
        "--config",
        required=True,
        help="Path to sos-signatures.yaml",
    )
    l.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit results as JSON",
    )

    return p


def _print_output_guide(outputs: Optional[Dict[str, str]] = None) -> None:
    # Keep this block intentionally stable; SupportConsole scrapes/relies on it.
    outputs = outputs or {}
    report_fn = outputs.get('report', 'report.md')
    findings_fn = outputs.get('findings', 'findings.json')
    meta_fn = outputs.get('meta', 'meta.json')
    clusters_fn = outputs.get('clusters', 'clusters.json')
    events_fn = outputs.get('events', 'events.jsonl')
    print("[INFO] Output guide:")
    print(f"[INFO] {report_fn:<13} = Report: high level built from findings + timelines: Summary of below output files")
    print(
        f"[INFO] {findings_fn:<13} = Heuristics as defined by sos-signatures.yaml which fired "
        "(e.g. “restart storm”, “repeated elections”, etc.) with evidence samples"
    )
    print(f"[INFO] {meta_fn:<13} = Source of truth ledger (what was scanned, limits, warnings, stats)")
    print(
        f"[INFO] {clusters_fn:<13} = Cluster representation of chatty patterns of signatures within a bounded time window "
        "(e.g. memberlist + raft peer errors)"
    )
    print(f"[INFO] {events_fn:<13} = RAW normalized “things we saw” (one per match); very large file")
    print("[INFO] Consumption order:")
    print(f"[INFO]   1) {report_fn} → Human-facing RCA summary")
    print(f"[INFO]   2) {findings_fn} → Structured reasoning that built the report")
    print(f"[INFO]   3) {clusters_fn} → Temporal burst compression feeding findings")
    print(f"[INFO]   4) {events_fn} → Atomic observations (full fidelity)")
    print(f"[INFO]   5) {meta_fn} → Execution ledger / scan conditions")
    print("[INFO] Pipeline: events → clusters → findings → report")
    print(f"[INFO]         {meta_fn}   ⇑ (records the execution conditions and feeds clusters pipeline above)")


# -------------------------
# Lint implementation
# -------------------------

def _load_yaml(path: Path) -> Any:
    try:
        import yaml  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError("PyYAML is required for lint-config") from e
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _emit_issue(issues: List[Dict[str, str]], code: str, level: str, message: str, path: str) -> None:
    issues.append({"code": code, "level": level, "message": message, "path": path})


def _lint_config(cfg: Any) -> Tuple[List[Dict[str, str]], int]:
    """Return (issues, exit_code). Exit code 0 on warnings-only, 2 on errors."""
    issues: List[Dict[str, str]] = []

    if not isinstance(cfg, dict):
        _emit_issue(issues, "CONFIG_NOT_MAPPING", "ERROR", "config root must be a mapping", "$")
        return issues, 2

    # Basic expected keys
    for key in ("signatures",):
        if key not in cfg:
            _emit_issue(issues, "MISSING_KEY", "ERROR", f"missing top-level key '{key}'", "$")

    sigs = cfg.get("signatures")
    if not isinstance(sigs, list):
        _emit_issue(issues, "SIGNATURES_NOT_LIST", "ERROR", "signatures must be a list", "signatures")
        return issues, 2

    # Collect event types for cross-reference checks
    event_types: Set[str] = set()
    sig_ids: Set[str] = set()

    allowed_sev = {"critical", "high", "medium", "info"}

    for i, s in enumerate(sigs):
        pfx = f"signatures[{i}]"
        if not isinstance(s, dict):
            _emit_issue(issues, "SIGNATURE_NOT_MAPPING", "ERROR", "signature must be a mapping", pfx)
            continue

        sid = s.get("id")
        if not isinstance(sid, str) or not sid.strip():
            _emit_issue(issues, "SIG_ID_INVALID", "ERROR", "signature.id must be a non-empty string", f"{pfx}.id")
        else:
            if sid in sig_ids:
                _emit_issue(issues, "SIG_ID_DUP", "ERROR", f"duplicate signature id '{sid}'", f"{pfx}.id")
            sig_ids.add(sid)

        et = s.get("event_type")
        if not isinstance(et, str) or not et.strip():
            _emit_issue(issues, "EVENT_TYPE_INVALID", "ERROR", "signature.event_type must be a non-empty string", f"{pfx}.event_type")
        else:
            event_types.add(et)

        sev = s.get("severity")
        if sev is not None:
            if not isinstance(sev, str) or sev.strip().lower() not in allowed_sev:
                _emit_issue(
                    issues,
                    "SEVERITY_INVALID",
                    "ERROR",
                    f"invalid severity '{sev}' (allowed: critical, high, medium, info)",
                    f"{pfx}.severity",
                )

        patterns = s.get("patterns")
        if not isinstance(patterns, list) or not patterns:
            _emit_issue(issues, "PATTERNS_INVALID", "ERROR", "signature.patterns must be a non-empty list", f"{pfx}.patterns")
        else:
            for j, pat in enumerate(patterns):
                if not isinstance(pat, str) or not pat:
                    _emit_issue(issues, "PATTERN_NOT_STRING", "ERROR", "pattern must be a non-empty string", f"{pfx}.patterns[{j}]")
                    continue
                try:
                    re.compile(pat)
                except re.error as e:
                    _emit_issue(issues, "REGEX_COMPILE", "ERROR", f"regex failed to compile: {e}", f"{pfx}.patterns[{j}]")

                # very lightweight generic-pattern warning
                if pat.strip().lower() in {"timeout", "error", "failed"}:
                    _emit_issue(issues, "PATTERN_TOO_GENERIC", "WARN", f"pattern '{pat}' is likely too generic", f"{pfx}.patterns[{j}]")

        capture = s.get("capture")
        if capture is not None:
            if not isinstance(capture, dict):
                _emit_issue(issues, "CAPTURE_NOT_MAPPING", "ERROR", "capture must be a mapping", f"{pfx}.capture")
            else:
                for k, v in capture.items():
                    if not isinstance(v, str):
                        _emit_issue(issues, "CAPTURE_REGEX_NOT_STRING", "ERROR", "capture regex must be a string", f"{pfx}.capture.{k}")
                        continue
                    try:
                        re.compile(v)
                    except re.error as e:
                        _emit_issue(issues, "CAPTURE_REGEX_COMPILE", "ERROR", f"capture regex failed to compile: {e}", f"{pfx}.capture.{k}")

    # Cross-reference checks (best-effort; schema may vary)
    referenced: Set[str] = set()

    # timeline.include_event_types
    timeline = cfg.get("timeline")
    if isinstance(timeline, dict):
        inc = timeline.get("include_event_types")
        if isinstance(inc, list):
            referenced |= {x for x in inc if isinstance(x, str)}

    # context_grouping.chatty_event_types
    cg = cfg.get("context_grouping")
    if isinstance(cg, dict):
        chatty = cg.get("chatty_event_types")
        if isinstance(chatty, list):
            referenced |= {x for x in chatty if isinstance(x, str)}

    # heuristics thresholds/supports
    heur = cfg.get("heuristics")
    if isinstance(heur, list):
        for hi, h in enumerate(heur):
            if not isinstance(h, dict):
                continue
            th = h.get("thresholds")
            if isinstance(th, list):
                for ti, t in enumerate(th):
                    if isinstance(t, dict) and isinstance(t.get("event_type"), str):
                        referenced.add(t["event_type"])
            sup = h.get("supports")
            if isinstance(sup, list):
                for si, s in enumerate(sup):
                    if isinstance(s, dict) and isinstance(s.get("event_type"), str):
                        referenced.add(s["event_type"])

    # Unknown references
    for et in sorted(referenced):
        if et not in event_types:
            _emit_issue(
                issues,
                "EVENT_TYPE_UNKNOWN_REFERENCE",
                "ERROR",
                f"event_type '{et}' is referenced but not defined in signatures",
                "$",
            )

    # Unreferenced event types (warning)
    for et in sorted(event_types):
        if et not in referenced:
            _emit_issue(
                issues,
                "EVENT_TYPE_UNREFERENCED",
                "WARN",
                f"event_type '{et}' is not referenced by clustering, heuristics, or timeline include list (may be intentional)",
                "signatures[*].event_type",
            )

    has_err = any(x["level"] == "ERROR" for x in issues)
    return issues, (2 if has_err else 0)


def _run_lint_config(path: Path, as_json: bool) -> int:
    cfg = _load_yaml(path)
    issues, code = _lint_config(cfg)

    if as_json:
        print(json.dumps(issues, indent=2))
        return code

    for it in issues:
        lvl = it.get("level", "INFO")
        print(f"[{lvl}] {it.get('code')}: {it.get('message')} ({it.get('path')})")

    return code


def _handle_sigterm(signum, frame):
    raise KeyboardInterrupt


def _handle_top_level_interrupt() -> int:
    print("\n[sos_triage] interrupted — exiting gracefully")
    return 130

def main(argv: Optional[Sequence[str]] = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)

    if args.cmd == "lint-config":
        try:
            return _run_lint_config(Path(args.config), bool(args.json))
        except Exception as e:
            print(f"[ERROR] lint-config failed: {e}")
            return 2

    if args.cmd != "analyze":
        return 2

    sos_path = Path(args.sosreport)
    configs_dir = Path(args.configs_dir)
    cfg_path = Path(args.config)
    if not cfg_path.is_absolute() and not cfg_path.exists():
        cfg_path = configs_dir / cfg_path

    outdir = Path(args.outdir)
    extract_dir = Path(args.extract_dir) if args.extract_dir else outdir / "extracted"

    output_tag = sanitize_output_tag(args.output_tag)

    allowed_severities = args.severity if args.severity is not None else LEVEL_TO_SEVERITIES.get(args.level, LEVEL_TO_SEVERITIES[4])

    try:
        if not args.quiet:
            print(f"[INFO] sos={sos_path}")
            print(f"[INFO] config={cfg_path}")
            print(f"[INFO] outdir={outdir}")
            print(f"[INFO] extract_dir={extract_dir} mode={args.extract_mode}")
            if args.max_events is not None:
                print(f"[INFO] max_events={args.max_events}")
            if args.max_bytes is not None:
                print(f"[INFO] max_bytes={args.max_bytes}")
            if args.severity is not None:
                print(f"[INFO] severity={','.join(sorted(allowed_severities))} (override)")
            else:
                print(f"[INFO] level={args.level} severities={','.join(sorted(allowed_severities))}")
            if output_tag:
                print(f"[INFO] output_tag={output_tag}")
            elif args.output_tag:
                print(f"[WARN] output_tag sanitized to empty; ignoring (raw={args.output_tag!r})")
            if args.cleanup_extracted:
                print("[INFO] cleanup_extracted=true")

        result = analyze(
            sos_path,
            cfg_path,
            outdir,
            extract_dir,
            extract_mode=args.extract_mode,
            keep_extracted=args.keep_extracted,
            cleanup_extracted=args.cleanup_extracted,
            no_overwrite=args.no_overwrite,
            tool_version=args.tool_version,
            case_id=args.case_id,
            run_id=args.run_id,
            verbose=args.verbose,
            max_events=args.max_events,
            max_bytes=args.max_bytes,
            no_cluster=args.no_cluster,
            allowed_severities=set(allowed_severities),
            output_tag=output_tag,
        )

        # Print written artifacts + a compact stats summary from meta.json
        meta_path = Path(result.get('meta')) if isinstance(result, dict) and result.get('meta') else (outdir / (f"meta-{output_tag}.json" if output_tag else "meta.json"))
        if not args.quiet:
            files: List[str] = []
            stats_line: Optional[str] = None

            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8", errors="ignore"))
                    out_files = (meta.get("outputs") or {}).get("files") or {}
                    order = ["report", "findings", "meta", "clusters", "events"]
                    for k in order:
                        fn = out_files.get(k)
                        if fn:
                            files.append(str(outdir / fn))
                    if not files:
                        for fn in ["report.md", "findings.json", "meta.json", "clusters.json", "events.jsonl"]:
                            if (outdir / fn).exists():
                                files.append(str(outdir / fn))

                    st = meta.get("stats") or {}
                    clusters = (st.get("clusters") or {}).get("clusters_emitted") if isinstance(st.get("clusters"), dict) else None
                    findings = (st.get("findings") or {}).get("findings_emitted") if isinstance(st.get("findings"), dict) else None
                    events = st.get("events_emitted")
                    lim = meta.get("limits") or {}
                    trunc_b = bool(lim.get("scan_truncated"))
                    trunc_e = bool(lim.get("events_truncated"))
                    stats_line = (
                        f"[INFO] stats: events={events} clusters={clusters} findings={findings} "
                        f"truncated_bytes={trunc_b} truncated_events={trunc_e}"
                    )
                except Exception:
                    pass

            if files:
                print("[INFO] wrote:")
                for f in files:
                    print(f"[INFO]   {f}")
            else:
                print(f"[INFO] wrote {outdir/'events.jsonl'} {outdir/'meta.json'}")

            if stats_line:
                print(stats_line)

            outputs = None
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8", errors="ignore"))
                    outputs = (meta.get("outputs") or {}).get("files") or None
                except Exception:
                    outputs = None
            _print_output_guide(outputs)

            # Print report.md to console (optional; suppressed by --quiet)
            if bool(getattr(args, "print_report", True)):
                report_fn = None
                if isinstance(outputs, dict):
                    report_fn = outputs.get("report")
                report_path = (outdir / report_fn) if report_fn else (outdir / (f"report-{output_tag}.md" if output_tag else "report.md"))
                if report_path.exists():
                    print("=" * 60)
                    try:
                        print(report_path.read_text(encoding="utf-8", errors="replace"))
                    except Exception as e:
                        print(f"[WARN] could not read report for console output: {e}")
                else:
                    print(f"[WARN] report file not found for console output: {report_path}")

        return 0

    except KeyboardInterrupt:
        print("\n[sos_triage] interrupted — exiting gracefully")
        return 130
    except ConfigError as e:
        print(f"[ERROR] {e}")
        return 2
    except WriteError as e:
        print(f"[ERROR] {e}")
        return 2
    except ExtractionError as e:
        print(f"[ERROR] {e}")
        return 3
    except ScanError as e:
        print(f"[ERROR] {e}")
        return 4
    except SosTriageError as e:
        print(f"[ERROR] {e}")
        return 5
    except Exception as e:
        print(f"[ERROR] unexpected: {e}")
        return 5


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(_handle_top_level_interrupt())
