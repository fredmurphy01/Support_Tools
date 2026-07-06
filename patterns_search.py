#!/usr/bin/env python3
"""
patterns_search VERSION: 1.12

Fast multi-pattern scan of a support bundle directory tree.

Key features:
- Single-pass scan of files; each file checked against all patterns (fast).
- Multiprocessing via ProcessPoolExecutor (optional; default uses CPU count - 1).
- Progress updates to stderr (not written to output report).
- Report output is "tee'd" to BOTH console (stdout) and an output .txt file.
- Clean Ctrl+C handling: exits without stack traces.
- Optional external patterns.txt via --patterns
- Optional date filter via --date and +/- window via --date-window-days
"""


from __future__ import annotations

import argparse
import os
import re
import json
import sys
import signal
import time
import subprocess
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Default patterns (used if no patterns.txt is provided or it is empty/missing)
PATTERNS: List[str] = [
    r"left gossip cluster",
    r"healthscore:[2-9] \(connectivity issues\)",
    r'with result "error:context canceled" took too long',
    r"unsynchronized systime with swarm",
    r"the clock difference against peer .* is too high",
    r"has prevented the request from succeeding \(get secrets\)",
    r"level.*error.* Cannot connect to the Docker daemon at tcp:",
    r"Error from leadership election follower",
    r"Cluster leadership lost",
    r"heartbeat to manager .* failed",
    r"dispatcher is stopped",
    r"cni config uninitialized",
    r'level=error msg="periodic bulk sync failure for network',
    r'": rejected connection from .* tcp "',
    r"memberlist: Failed fallback ping: read tcp .* read: connection reset by peer",
    r"memberlist: Marking .* as failed, suspect timeout reached",
    r"but other probes failed, network may be misconfigured",
    r"Some RethinkDB data on this server has been placed into swap",
    r"is in state down: heartbeat failure for node in",
    r"is in state down: Unhealthy UCP manager: ERROR: RethinkDB Health check timed out",
    r"is in state down: Awaiting healthy status in classic node inventory - current status: Unhealthy",
    r"etcd cluster is unavailable or misconfigured",
    r"martian source",
    r"Failed to execute iptables-[rs].* segmentation fault",
    r"Failed to create existing container",
    r"failed to allocate network IP for task",
    r"Failed to allocate address: Invalid address space",
    r"Failed to delegate: Failed to allocate address: No available addresses",
    r"fatal task error.*starting container failed: Address already in use",
    r"deleteServiceInfoFromCluster NetworkDB DeleteEntry failed for",
    r"Failed to start certificate controller: error reading CA cert file",
    r"Failed to load config file",
    r"failed to re-resolve dtr-rethinkdb-",
    r"unable to query [dD][bB]: rethinkdb",
    r"unable to create event in database: rethinkdb: Cannot perform write:",
    r"unable to create job: unable to insert job into db: rethinkdb: Cannot perform write:",
    r"RethinkDB Health check timed out",
    r"failed to complete security handshake from",
    r'Err :connection error: desc = "transport: authentication handshake failed: read tcp',
    r"http: TLS handshake error from .* tls: client didn't provide a certificate",
    r"tls: failed to verify client's certificate: x509: certificate has expired or is not yet valid",
    r"level=error .* x509: certificate signed by unknown authority",
    r"error.* x509: certificate has expired or is not yet valid: current time",
    r": rejected connection from .* tls: .* certificate\", ServerName",
    r": rejected connection from .* tls: .* certificate: x509: certificate has",
    r": rejected connection from .* \"tls: .* does not match any of DNSNames",
    r"OOMKilled\":true",
    r"invoked oom-killer",
    r"[Cc]onnection refused",
    r"HTTP error: Unable to reach primary cluster manager",
    r"nfs: server  not responding, still trying",
    r":53: no such host",
    r"port .* is already in use",
    r"bind: address already in use",
    r"No installed keys could decrypt the message",
    r"[Nn]o space left on device",
    r"cannot allocate memory",
    r"error detaching from network .*: could not find network attachment for container .* to network",
    r'FieldPath:"spec.containers{calico-node}"}, Reason:"Unhealthy", Message:"Liveness probe failed:',
    r'FieldPath:"spec.containers{calico-node}"}, Reason:"Unhealthy", Message:"Readiness probe failed:',
    r"Unable to route request",
    r"Legacy license failure",
    r'level=error msg="agent: session failed" backoff=.* error="rpc error: code = Unavailable desc = all SubConns are in TransientFailure',
    r'"level":"fatal"',
    r"LOG_LEVEL=debug",
    r"OVERLAP on Network",
    r"iptables: Resource temporarily unavailable",
    r"unable to look up Node Feature Discovery",
]

# ---------------------------------------------------------------------------
# Output tee writer
# ---------------------------------------------------------------------------

class TeeWriter:
    """Write to multiple file-like objects."""
    def __init__(self, *streams):
        self._streams = streams

    def write(self, s: str) -> None:
        for st in self._streams:
            try:
                st.write(s)
            except Exception:
                pass

    def flush(self) -> None:
        for st in self._streams:
            try:
                st.flush()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Optional integration: run sdnodes.py first and prepend its output to report
# ---------------------------------------------------------------------------

def _run_bundle_view(report_path: Path, bundle_path: str, *, verbose: bool = False, sdnodes_path: str | None = None) -> None:
    """Run sdnodes.py and prepend its output to the report.

    Behavior (v1):
    - Default sdnodes location is the same directory as this script (tools/).
    - Optional override via --sdnodes-path.
    - In non-verbose mode, suppress subprocess console output.
    - Always deletes the intermediate tmp file on completion.
    """
    script_name = "sdnodes.py"
    tools_dir = Path(__file__).resolve().parent
    script_path = Path(sdnodes_path).expanduser().resolve() if sdnodes_path else (tools_dir / script_name)

    report_path = report_path.resolve()

    def vprint(*args, **kwargs) -> None:
        if verbose:
            print(*args, **kwargs)

    vprint(f"-------- scriptname: {script_name}  scriptpath: {script_path}----------------------")

    if not script_path.exists():
        vprint(f"[warn] bundle_view integration skipped: {script_name} not found at {script_path}", file=sys.stderr)
        with report_path.open("w", encoding="utf-8", errors="ignore") as out_fh:
            out_fh.write("=== BUNDLEVIEW (cluster/node summary) ===\n")
            out_fh.write(f"[sdnodes] not found at: {script_path}\n")
            out_fh.write("=== END BUNDLEVIEW ===\n\n")
        return

    tmp_path = report_path.parent / (report_path.stem + "_sdnodes.tmp.txt")

    cmd = [
        str(sys.executable),
        str(script_path),
        f"--bundlepath={bundle_path}",
        "--filesave=1",
        "--extended-output=1",
        f"--outputfile={str(tmp_path)}",
    ]

    try:
        vprint(f"[info] running bundleview: {' '.join(cmd)}", file=sys.stderr)

        proc = subprocess.run(
            cmd,
            stdout=(sys.stderr if verbose else subprocess.DEVNULL),
            stderr=(sys.stderr if verbose else subprocess.DEVNULL),
            text=True,
            check=False,
            env=os.environ,
        )

        if verbose and proc.returncode != 0:
            print(f"[warn] bundleview exited with status {proc.returncode}", file=sys.stderr)

        if tmp_path.exists() and tmp_path.is_file():
            sdnodes_text = tmp_path.read_text(encoding="utf-8", errors="ignore")
            try:
                size = tmp_path.stat().st_size
            except Exception:
                size = -1
            print(f"[info] bundleview wrote tmp output: {tmp_path} ({size} bytes)", file=sys.stderr)
        else:
            sdnodes_text = ""
            if verbose:
                print(f"[warn] bundleview did not produce expected output file: {tmp_path}", file=sys.stderr)

        with report_path.open("w", encoding="utf-8", errors="ignore") as out_fh:
            out_fh.write("=== BUNDLEVIEW (cluster/node summary) ===\n")
            if sdnodes_text.strip():
                out_fh.write(sdnodes_text)
                if not sdnodes_text.endswith("\n"):
                    out_fh.write("\n")
            else:
                out_fh.write("[sdnodes] ran but produced no output\n")
            out_fh.write("=== END BUNDLEVIEW ===\n\n")

    except KeyboardInterrupt:
        if verbose:
            print("\n[info] Ctrl+C received while running sdnodes; exiting...", file=sys.stderr)
        raise
    except Exception as e:
        if verbose:
            print(f"[warn] sdnodes integration failed: {e}", file=sys.stderr)
        with report_path.open("w", encoding="utf-8", errors="ignore") as out_fh:
            out_fh.write("=== BUNDLEVIEW (cluster/node summary) ===\n")
            out_fh.write(f"[sdnodes] failed: {e}\n")
            out_fh.write("=== END BUNDLEVIEW ===\n\n")
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass
_WORKER_REGEXES: List[re.Pattern] = []
_WORKER_DATE_RX: Optional[re.Pattern] = None

def _init_worker(patterns: List[str], date_rx_pat: str | None) -> None:
    """Compile regexes once per worker process."""
    global _WORKER_REGEXES, _WORKER_DATE_RX
    _WORKER_REGEXES = [re.compile(p) for p in patterns]
    _WORKER_DATE_RX = re.compile(date_rx_pat) if date_rx_pat else None

@dataclass
class FileMatch:
    count: int = 0
    first_line: Optional[str] = None
    last_line: Optional[str] = None
    date_counts: Optional[Dict[str, int]] = None  # only populated when --date is used

def _scan_one_file(path_str: str, patterns: List[str] | None = None, date_rx_pat: str | None = None) -> Tuple[str, Dict[str, FileMatch]]:
    """
    Scan one file and return {pattern: FileMatch} for patterns that matched.
    In multiprocessing mode, patterns/date filter are already compiled via globals.
    In single-process mode (workers=1), caller may pass patterns + date_rx_pat.
    """
    global _WORKER_REGEXES, _WORKER_DATE_RX

    if patterns is not None:
        _WORKER_REGEXES = [re.compile(p) for p in patterns]
        _WORKER_DATE_RX = re.compile(date_rx_pat) if date_rx_pat else None

    results: Dict[str, FileMatch] = {}

    try:
        with open(path_str, "r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n")
                date_hit: Optional[str] = None
                if _WORKER_DATE_RX:
                    m = _WORKER_DATE_RX.search(line)
                    if not m:
                        continue
                    date_hit = m.group(0)

                for i, rx in enumerate(_WORKER_REGEXES):
                    if rx.search(line):
                        p = rx.pattern
                        fm = results.get(p)
                        if fm is None:
                            fm = FileMatch()
                            results[p] = fm
                        fm.count += 1
                        if date_hit is not None:
                            if fm.date_counts is None:
                                fm.date_counts = {date_hit: 1}
                            else:
                                fm.date_counts[date_hit] = fm.date_counts.get(date_hit, 0) + 1
                        if fm.first_line is None:
                            fm.first_line = line
                        fm.last_line = line
    except Exception:
        # Ignore unreadable/binary files
        pass

    return path_str, results

# ---------------------------------------------------------------------------
# Patterns loading / date filter building
# ---------------------------------------------------------------------------

def _load_patterns_from_path(patterns_path: str | None) -> List[str]:
    """
    User passes --patterns=<path>.
    - If <path> is a directory: use <path>/patterns.txt
    - If <path> is a file: use that file (often patterns.txt)
    If missing/unreadable/empty -> fallback to built-in PATTERNS.
    Lines starting with '#' and blank lines are ignored.
    """
    if not patterns_path:
        return list(PATTERNS)

    p = Path(patterns_path)
    if p.exists() and p.is_dir():
        p = p / "patterns.txt"
    else:
        if p.suffix.lower() != ".txt":
            p = p / "patterns.txt"

    try:
        if not p.exists() or not p.is_file():
            return list(PATTERNS)
        loaded: List[str] = []
        with p.open("r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                s = raw.strip()
                if not s or s.startswith("#"):
                    continue
                loaded.append(s)
        return loaded if loaded else list(PATTERNS)
    except Exception:
        return list(PATTERNS)

def _build_date_rx_pat(date_filter: str | None, window_days: int) -> Tuple[str | None, List[str]]:
    """
    Build a regex pattern that matches any of the allowed YYYY-MM-DD strings.
    window_days=0 -> only date_filter
    window_days=2 -> date-2 ... date+2
    """
    if not date_filter:
        return None, []

    base = datetime.strptime(date_filter, "%Y-%m-%d").date()
    days = abs(int(window_days or 0))
    date_strs = [(base + timedelta(days=off)).strftime("%Y-%m-%d") for off in range(-days, days + 1)]
    return r"(?:%s)" % "|".join(re.escape(s) for s in date_strs), date_strs

# ---------------------------------------------------------------------------
# Main search
# ---------------------------------------------------------------------------

def _iter_files(root: Path) -> List[str]:
    out: List[str] = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            out.append(str(Path(dirpath) / fn))
    return out

def search_patterns(root_dir: str, *, workers: int = 0, out=None, patterns_path: str | None = None,
                  date_filter: str | None = None, date_window_days: int = 0, verbose: bool = False) -> Dict[str, object]:
    root = Path(root_dir)
    patterns = _load_patterns_from_path(patterns_path)

    # Informative notes (stderr only)
    if patterns_path:
        pnote = Path(patterns_path)
        if pnote.exists() and pnote.is_dir():
            pnote = pnote / "patterns.txt"
        elif pnote.suffix.lower() != ".txt":
            pnote = pnote / "patterns.txt"
        if pnote.exists() and pnote.is_file():
            if verbose:
                print(f"[info] loaded {len(patterns)} patterns from: {pnote}", file=sys.stderr)
        else:
            if verbose:
                print(f"[info] patterns file not found at: {pnote} (using built-in patterns)", file=sys.stderr)

    date_rx_pat, date_window_dates = _build_date_rx_pat(date_filter, date_window_days)
    if date_filter:
        if date_window_days:
            print(f"[info] filtering matches to dates in window: {date_filter} +/- {abs(date_window_days)} days", file=sys.stderr)
        else:
            print(f"[info] filtering matches to lines containing date: {date_filter}", file=sys.stderr)

    if out is None:
        out = sys.stdout

    files = _iter_files(root)
    total_files = len(files)
    patterns_preview = ", ".join(patterns[:3]) + (" ..." if len(patterns) > 3 else "")
    print(f"[info] scanning {total_files} files; each file checked against {len(patterns)} patterns (e.g., {patterns_preview})", file=sys.stderr)

    # Aggregate: pattern -> file -> match stats
    agg: Dict[str, Dict[str, FileMatch]] = {p: {} for p in patterns}

    # Progress printing (stderr only)
    last_progress_time = 0.0
    next_progress_count = 1

    def maybe_progress(done: int) -> None:
        nonlocal last_progress_time, next_progress_count
        now = time.time()
        # print on first completion, then every 200 files or every 15s
        if done == 1 or done >= next_progress_count or (now - last_progress_time) >= 15:
            print(f"[progress] [workers: {workers}] scanned {done}/{total_files} files (checking {len(patterns)} patterns; e.g., {patterns_preview})...", file=sys.stderr)
            last_progress_time = now
            if done >= next_progress_count:
                next_progress_count = ((done // 200) + 1) * 200

    # Choose workers
    if workers <= 0:
        cpu = os.cpu_count() or 2
        workers = max(1, cpu - 1)

    # Single-process path (useful for debugging)
    if workers == 1:
        done = 0
        for f in files:
            done += 1
            maybe_progress(done)
            _, res = _scan_one_file(f, patterns=patterns, date_rx_pat=date_rx_pat)
            for pat, fm in res.items():
                agg[pat][f] = fm
    else:
        done = 0
        try:
            with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker, initargs=(patterns, date_rx_pat)) as ex:
                futures = [ex.submit(_scan_one_file, f) for f in files]
                for fut in as_completed(futures):
                    done += 1
                    maybe_progress(done)
                    fpath, res = fut.result()
                    for pat, fm in res.items():
                        agg[pat][fpath] = fm
        except KeyboardInterrupt:
            # Quiet, user-friendly exit; keep whatever already written
            if verbose:
                print("\n[info] Ctrl+C received; exiting...", file=sys.stderr)
            return

    # Emit report
    for pat in patterns:
        out.write(f"\n\tThe pattern {pat!r} appears:\n")
        if date_filter and date_window_dates:
            # Aggregate per-date counts across all files for this pattern
            totals: Dict[str, int] = {d: 0 for d in date_window_dates}
            for _fm in agg[pat].values():
                if _fm.date_counts:
                    for d, c in _fm.date_counts.items():
                        if d in totals:
                            totals[d] += c
            out.write("\tDate breakdown:\n")
            for d in date_window_dates:
                out.write(f"\t  {d}: {totals[d]}\n")
        if not agg[pat]:
            out.write("------\n")
            continue

        for fpath, fm in agg[pat].items():
            out.write(f" -->> {fm.count} times in file: {fpath}, with first/last line:\n")
            if fm.first_line is not None:
                out.write(f"  {fm.first_line}\n")
                out.write(f"  {fm.last_line}\n")
            out.write("------\n")

    # Keep your certdump scan behavior
    out.write("\nLooking for lines that end in (EXPIRED) inside */dsinfo/certdump.txt :\n")
    for cert_path in root.rglob("dsinfo/certdump.txt"):
        try:
            with cert_path.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if line.rstrip().endswith("(EXPIRED)"):
                        out.write(f"{cert_path}: {line}")
        except Exception:
            pass

    # Build a JSON-serializable report structure (used when --json is requested).
    def _fm_to_dict(fm: FileMatch) -> Dict[str, object]:
        return {
            'count': fm.count,
            'first_line': fm.first_line,
            'last_line': fm.last_line,
            'date_counts': fm.date_counts or {},
        }

    patterns_out: List[Dict[str, object]] = []
    for pat in patterns:
        pat_entry: Dict[str, object] = {
            'pattern': pat,
            'total_matches': sum(fm.count for fm in agg[pat].values()),
            'date_breakdown': {},
            'files': [],
        }
        if date_filter and date_window_dates:
            totals: Dict[str, int] = {d: 0 for d in date_window_dates}
            for fm in agg[pat].values():
                if fm.date_counts:
                    for d, c in fm.date_counts.items():
                        if d in totals:
                            totals[d] += c
            pat_entry['date_breakdown'] = totals

        for fpath in sorted(agg[pat].keys()):
            pat_entry['files'].append({
                'path': fpath,
                'match': _fm_to_dict(agg[pat][fpath]),
            })
        patterns_out.append(pat_entry)

    report: Dict[str, object] = {
        'root_dir': str(root),
        'patterns_source': None,
        'pattern_count': len(patterns),
        'file_count': total_files,
        'date_filter': date_filter,
        'date_window_days': int(date_window_days or 0),
        'date_window_dates': date_window_dates,
        'patterns': patterns_out,
    }
    if patterns_path:
        pnote = Path(patterns_path)
        if pnote.is_dir():
            pnote = pnote / 'patterns.txt'
        elif pnote.suffix.lower() != '.txt':
            pnote = pnote / 'patterns.txt'
        report['patterns_source'] = str(pnote)

    return report


def _parse_bundleview_table(report_txt_path: Path) -> dict:
    """Parse the BUNDLEVIEW table from the top of the .txt report and return summary stats."""
    try:
        txt = report_txt_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {}

    m = re.search(r"=== BUNDLEVIEW \(cluster/node summary\) ===\n(.*?)\n=== END BUNDLEVIEW ===", txt, re.DOTALL)
    if not m:
        return {}

    section = m.group(1).strip().splitlines()
    if len(section) < 2:
        return {}

    header = section[0].rstrip()
    rows = [ln.rstrip() for ln in section[1:] if ln.strip() and not ln.strip().startswith("[sdnodes]")]

    split_re = re.compile(r"\s{2,}")
    header_cols = split_re.split(header.strip())

    def idx(col: str) -> int | None:
        try:
            return header_cols.index(col)
        except ValueError:
            return None

    i_cluster = idx("CLUSTER-ID")
    i_role = idx("ROLE")
    i_type = idx("TYPE")
    i_mcrv = idx("MCRv")
    i_mkev = idx("MKEv")
    i_msrv = idx("MSRv")

    parsed = []
    for r in rows:
        parsed.append(split_re.split(r.strip()))

    if not parsed:
        return {}

    cluster_id = parsed[0][i_cluster] if i_cluster is not None and len(parsed[0]) > i_cluster else None

    def count_by(i: int | None) -> dict:
        if i is None:
            return {}
        out = {}
        for cols in parsed:
            if len(cols) <= i:
                continue
            v = cols[i]
            out[v] = out.get(v, 0) + 1
        return out

    def unique_vals(i: int | None) -> list[str]:
        if i is None:
            return []
        seen = set()
        out = []
        for cols in parsed:
            if len(cols) <= i:
                continue
            v = cols[i]
            if v in ("-.-.--", "", None):
                continue
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    return {
        "cluster_id": cluster_id,
        "node_count": len(parsed),
        "role_counts": count_by(i_role),
        "type_counts": count_by(i_type),
        "mcr_versions": unique_vals(i_mcrv),
        "mke_versions": unique_vals(i_mkev),
        "msr_versions": unique_vals(i_msrv),
    }


def _write_patsrc_markdown(*, report_dict: dict, txt_report_path: Path, md_path: Path) -> None:
    """Write report-patsrc.md alongside the other artifacts (hybrid format with density bars)."""
    bv = _parse_bundleview_table(txt_report_path)

    pats = list(report_dict.get("patterns", []) or [])
    pats_sorted = sorted(pats, key=lambda p: int(p.get("total_matches") or 0), reverse=True)
    top = [p for p in pats_sorted if int(p.get("total_matches") or 0) > 0][:7]

    def find_kw(*kws: str) -> list[dict]:
        out = []
        for p in pats_sorted:
            pat = (p.get("pattern") or "").lower()
            if any(kw in pat for kw in kws) and int(p.get("total_matches") or 0) > 0:
                out.append(p)
        return out

    # Control-plane keyword bucket (still keyword-based; hybrid report keeps it modest)
    control_hits = []
    control_hits += find_kw("etcd")
    control_hits += find_kw("leadership", "leader")
    control_hits += find_kw("election")
    control_hits += find_kw("unsynchronized", "unsynchronised", "clock", "systime")

    seen = set()
    control_unique = []
    for p in control_hits:
        s = p.get("pattern")
        if s not in seen:
            seen.add(s)
            control_unique.append(p)
    control_unique = control_unique[:10]

    root_dir = report_dict.get("root_dir", "")
    patterns_source = report_dict.get("patterns_source") or "Built-in"
    file_count = report_dict.get("file_count", "")
    pattern_count = report_dict.get("pattern_count", "")
    date_filter = report_dict.get("date_filter") or "None"
    date_window_days = report_dict.get("date_window_days", 0)

    gen_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def fmt_counts(d: dict) -> str:
        if not d:
            return "N/A"
        return ", ".join([f"{k}: {v}" for k, v in sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))])

    def green_bar(value: int, max_value: int, width: int = 20) -> str:
        if max_value <= 0:
            return ""
        filled = int((value / max_value) * width)
        if filled < 0:
            filled = 0
        if filled > width:
            filled = width
        return "🟩" * filled

    md: list[str] = []
    md.append("# Pattern Search Summary Report")
    md.append("")
    # Try to display just the last path segment as bundle name, while keeping full root as a code path
    bundle_name = str(root_dir).rstrip("/").split("/")[-1] if root_dir else ""
    if bundle_name:
        md.append(f"**Bundle:** `{bundle_name}`  ")
    else:
        md.append(f"**Bundle:** `{root_dir}`  ")
    if bv.get("cluster_id"):
        md.append(f"**Cluster ID:** `{bv['cluster_id']}`  ")
    md.append(f"**Generated:** {gen_ts}  ")
    md.append("")
    md.append("| Scope | Value |")
    md.append("|-------|-------|")
    md.append(f"| Files Scanned | **{file_count}** |")
    md.append(f"| Patterns Evaluated | **{pattern_count}** |")
    if date_filter != "None":
        md.append(f"| Date Filter | {date_filter} (window days: {date_window_days}) |")
    else:
        md.append("| Date Filter | None |")
    md.append(f"| Patterns Source | {patterns_source} |")
    md.append("")
    md.append("---")
    md.append("")

    # Cluster snapshot
    if bv:
        md.append("## 🧭 Cluster Snapshot")
        md.append("")
        md.append(f"**Nodes:** {bv.get('node_count', 'N/A')} total  ")

        rc = bv.get("role_counts", {}) or {}
        # Default to 0 if missing
        leader = int(rc.get("leader", 0) or 0)
        manager = int(rc.get("manager", 0) or 0)
        worker = int(rc.get("worker", 0) or 0)

        md.append(f"- 🟢 Leader: {leader}  ")
        md.append(f"- 🔵 Managers: {manager}  ")
        md.append(f"- ⚙ Workers: {worker}  ")
        md.append("")

        tc = bv.get("type_counts", {}) or {}
        if tc:
            md.append("**Node Types**  ")
            # Keep stable ordering when present
            for k in ("MCR", "MKE", "MSR"):
                if k in tc:
                    md.append(f"- {k}: {tc[k]}  ")
            # Any other types
            for k, v in sorted(tc.items()):
                if k not in ("MCR", "MKE", "MSR"):
                    md.append(f"- {k}: {v}  ")
            md.append("")

        vers = []
        if bv.get("mcr_versions"):
            vers.append(("MCR", bv["mcr_versions"]))
        if bv.get("mke_versions"):
            vers.append(("MKE", bv["mke_versions"]))
        if bv.get("msr_versions"):
            vers.append(("MSR", bv["msr_versions"]))
        if vers:
            md.append("**Versions**  ")
            for name, vals in vers:
                md.append(f"- {name} `{', '.join(vals)}`  ")
            md.append("")

        md.append("---")
        md.append("")

    # High-volume findings
    md.append("## 🔎 High-Volume Findings")
    md.append("")
    md.append("> Ranked by total match count across the bundle.")
    md.append("")

    emoji_numbers = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"]

    if not top:
        md.append("_No matches found._")
        md.append("")
    else:
        for i, p in enumerate(top, 0):
            title = p.get("name") or ""  # name may not exist; keep pattern only
            pat = p.get("pattern", "")
            total = int(p.get("total_matches") or 0)
            files = p.get("files") or []
            badge = emoji_numbers[i] if i < len(emoji_numbers) else f"{i+1}."
            # Use a friendly title if we have one; otherwise use a compact generic label
            heading = title.strip() if title else "Finding"
            md.append(f"### {badge}  {heading}")
            md.append(f"**{total:,} matches** • {len(files)} files  ")
            md.append(f"`{pat}`")
            md.append("")

    md.append("---")
    md.append("")

    # Density bars
    md.append("## 📊 Finding Density")
    md.append("")
    md.append("Relative match volume (scaled):")
    md.append("")

    max_matches = int(top[0].get("total_matches") or 0) if top else 0
    for p in top:
        label = (p.get("name") or "").strip()
        if not label:
            # derive a short label from pattern
            label = (p.get("pattern") or "")[:35].strip()
        total = int(p.get("total_matches") or 0)
        bar = green_bar(total, max_matches, width=20)
        md.append(f"{label:<35} {bar} **{total:,}**")

    md.append("")
    md.append("---")
    md.append("")

    # Control plane section
    md.append("## ⚙ Control Plane & Stability Signals")
    md.append("")
    if control_unique:
        md.append("| Signal | Matches |")
        md.append("|--------|---------|")
        for p in control_unique:
            md.append(f"| {p.get('pattern','')} | **{int(p.get('total_matches') or 0):,}** |")
        md.append("")
        md.append("**Observation:**  ")
        md.append("Leadership churn + etcd instability + time skew signals are present concurrently. Correlate timestamps in the full report to confirm sequencing.")
        md.append("")
    else:
        md.append("_No obvious control-plane keywords matched in pattern set._")
        md.append("")

    md.append("---")
    md.append("")
    md.append("## 📦 Generated Artifacts")
    md.append("")
    md.append(f"- `{txt_report_path.name}`")
    md.append(f"- `{txt_report_path.with_suffix('.json').name}`")
    md.append(f"- `{md_path.name}`")
    md.append("")
    md.append("_End of Summary_")
    md.append("")

    md_path.write_text("\n".join(md), encoding="utf-8")



def _default_output_filename() -> str:
    """Return default output filename based on current timestamp."""
    from datetime import datetime
    ts = datetime.now().strftime("%d%b%Y-%H-%M")
    return f"support_bundle_{ts}.txt"


def _handle_sigterm(signum, frame):
    raise KeyboardInterrupt


def _handle_top_level_interrupt() -> int:
    print("\n[patterns_search] interrupted — exiting gracefully", file=sys.stderr)
    return 130


def main() -> int:
    parser = argparse.ArgumentParser(description="PATTERNS_SEARCH: Version 1.12  Fast multi-pattern search across a support bundle.")
    parser.add_argument("-d", "--directory", required=True, help="Root directory to scan")
    parser.add_argument("--workers", type=int, default=0, help="Worker processes (0=auto, 1=single-process)")
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output report file. Default: support_bundle_<date-time>.txt"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose console output (sdnodes live output + pattern scan output + progress). Default prints only report-patsrc.md."
    )
    parser.add_argument(
        "--sdnodes-path",
        default=None,
        help="Optional full path to sdnodes.py. Default: tools/sdnodes.py (same directory as patterns_search.py)."
    )
    parser.add_argument(
        "--patterns",
        default=None,
        help="Optional path to a directory containing patterns.txt (or a direct .txt file). If missing, built-in PATTERNS are used."
    )
    parser.add_argument(
        "--date",
        default=None,
        help="Optional date filter (YYYY-MM-DD). If set, only matching lines containing this date/window are counted/output."
    )
    parser.add_argument(
        "--date-window-days",
        type=int,
        default=0,
        help="Optional +/- day window around --date (e.g., 2 means match date-2 through date+2). Default: 0."
    )


    args = parser.parse_args()

    if args.sdnodes_path is not None:
        sp = Path(args.sdnodes_path).expanduser()
        if not sp.exists():
            parser.error(f"--sdnodes-path not found: {sp}")

    if args.date is None and args.date_window_days:
        parser.error("--date-window-days requires --date")

    if args.date is not None:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
            parser.error("--date must be in YYYY-MM-DD format (e.g., 2025-11-14)")

    out_path = Path(args.output) if args.output else Path(_default_output_filename())

    start_time = time.time()
    report: Dict[str, object] | None = None
    try:
        # Run sdnodes first so its output is at the top of the report file.
        _run_bundle_view(out_path, args.directory, verbose=args.verbose, sdnodes_path=args.sdnodes_path)
        # Append the pattern search report after the sdnodes section.
        with out_path.open("a", encoding="utf-8", errors="ignore") as out_fh:
            tee = TeeWriter(sys.stdout, out_fh) if args.verbose else TeeWriter(out_fh)
            report = search_patterns(
                args.directory,
                workers=args.workers,
                out=tee,
                patterns_path=args.patterns,
                date_filter=args.date,
                date_window_days=args.date_window_days,
                verbose=args.verbose,
            )
            #if args.json and report is not None:
            if report is not None:
                json_path = out_path.with_suffix('.json')
                try:
                    with json_path.open('w', encoding='utf-8') as jh:
                        json.dump(report, jh, indent=2, sort_keys=False)
                    if args.verbose:
                        print(f"[info] JSON report written to: {json_path}", file=sys.stderr)
                except Exception as e:
                    print(f"[warn] failed to write JSON report: {e}", file=sys.stderr)

                # Write markdown summary alongside the other artifacts
                md_path = out_path.parent / "report-patsrc.md"
                try:
                    _write_patsrc_markdown(report_dict=report, txt_report_path=out_path, md_path=md_path)
                except Exception as e:
                    # Keep default output clean; only complain in verbose mode
                    if args.verbose:
                        print(f"[warn] failed to write markdown summary: {e}", file=sys.stderr)

                # Always print the markdown summary to stdout at end of run
                try:
                    md_text = md_path.read_text(encoding="utf-8", errors="ignore")
                    print(md_text, end="" if md_text.endswith("\n") else "\n")
                except Exception as e:
                    if args.verbose:
                        print(f"[warn] failed to read markdown summary for console output: {e}", file=sys.stderr)

    except KeyboardInterrupt:
        # Main-level guard (in case Ctrl+C hits outside the executor loop)
        print("\n[info] Ctrl+C received; exiting...", file=sys.stderr)
        return 130
    finally:
        elapsed = time.time() - start_time
        if args.verbose:
            print(f"[info] done in {elapsed:.1f}s; report: {out_path}", file=sys.stderr)
    return 0


'''
python3 patterns_search.py --help
usage: patterns_search.py [-h] -d DIRECTORY [--workers WORKERS] [-o OUTPUT] [--verbose] [--sdnodes-path SDNODES_PATH] [--patterns PATTERNS] [--date DATE] [--date-window-days DATE_WINDOW_DAYS]

PATTERNS_SEARCH: Version 1.12 Fast multi-pattern search across a support bundle.

options:
  -h, --help            show this help message and exit
  -d, --directory DIRECTORY
                        Root directory to scan
  --workers WORKERS     Worker processes (0=auto, 1=single-process)
  -o, --output OUTPUT   Output report file. Default: support_bundle_<date-time>.txt
  --verbose             Verbose console output (sdnodes live output + pattern scan output + progress). Default prints only report-patsrc.md.
  --sdnodes-path SDNODES_PATH
                        Optional full path to sdnodes.py. Default: tools/sdnodes.py (same directory as patterns_search.py).
  --patterns PATTERNS   Optional path to a directory containing patterns.txt (or a direct .txt file). If missing, built-in PATTERNS are used.
  --date DATE           Optional date filter (YYYY-MM-DD). If set, only matching lines containing this date/window are counted/output.
  --date-window-days DATE_WINDOW_DAYS
                        Optional +/- day window around --date (e.g., 2 means match date-2 through date+2). Default: 0.
'''


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(_handle_top_level_interrupt())