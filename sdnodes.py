#!/usr/bin/env python3
#
# Purpose:
#   Display node inventory and platform details from Docker / Mirantis
#   support bundles, supporting:
#
#     - Cluster-wide support bundles (ucp-nodes.txt)
#     - Single-node support bundles (root-level dsinfo evidence)
#     - Compressed support bundle archives (.zip/.tgz/.tar.gz/.tar.xz)
#
#   The tool is designed to operate as a standalone engineering utility
#   with no external package dependencies, while also supporting
#   structured output suitable for future Salesforce ingestion.
#
# Primary audiences:
#   1. Engineers
#        - Human-readable terminal table
#        - Optional debug output
#        - Summary statistics
#
#   2. Ticket / Salesforce ingestion
#        - Clean semicolon-delimited output
#        - Optional JSON output
#        - No visual summary or console noise
#
# Major enhancements completed:
#
#   Bundle support
#   --------------
#   1. Added support for both cluster-wide and single-node support bundles.
#   2. Bundle detection now identifies:
#          - cluster bundles
#          - single-node bundles
#          - unsupported layouts
#      with debug evidence describing the decision.
#   3. Added support for compressed support bundle archives:
#          .zip
#          .tgz
#          .tar.gz
#          .tar.xz
#      including automatic secure extraction to a temporary directory.
#   4. Archive extraction is hardened against path traversal
#      (Zip Slip / Tar Slip) attacks.
#
#   Robustness
#   ----------
#   5. Added BundleLoadError and centralized bundle loading.
#   6. Added safe_read_json_file() and safe_int().
#   7. getddcver() hardened against:
#          - missing files
#          - malformed JSON
#          - missing Config/Env
#          - malformed environment entries
#          - missing version keys
#   8. full_os_details_v1() hardened against malformed or missing:
#          - uptime
#          - OS release
#          - kernel
#          - hypervisor
#          - manufacturer
#          - interface/subnet information
#   9. process_nodes() skips malformed node records instead of aborting
#      the entire run whenever possible.
#  10. Invalid or unsupported bundles now terminate cleanly with exit code 2.
#
#   Architecture
#   ------------
#  11. Path handling migrated toward pathlib and bundle_root_path()
#      instead of fragile string concatenation.
#  12. Bundle loading centralized through:
#          load_cluster_nodes()
#          load_single_node()
#          cli_main()
#  13. Archive preparation is isolated behind prepare_bundle_input(),
#      allowing callers to supply either an extracted directory or a
#      compressed archive transparently.
#
#   Output
#   ------
#  14. Output modes added:
#
#          engineer
#              Human-oriented table with summary information.
#
#          ticket
#              Clean ingestion output only.
#
#  15. Output formats added:
#
#          table
#              Existing aligned / semicolon renderer.
#
#          json
#              Structured machine-readable output.
#
# CLI options:
#
#   --pretty {0,1}
#       1 = human-readable aligned table.
#       0 = semicolon-delimited rows.
#       In --output-mode ticket, pretty is forced off.
#
#   --output-mode {engineer,ticket}
#       engineer = terminal-friendly output with summary block.
#       ticket   = clean ingestion output only; suppresses summary/noise.
#
#   --output-format {table,json}
#       table = existing aligned/semicolon table renderer.
#       json  = structured machine-readable JSON renderer.
#
#   --filesave {0,1}
#       0 = write to stdout only.
#       1 = also write output to --outputfile.
#
#   --outputfile OUTPUTFILE
#       Output filename/path when --filesave=1.
#       Default:
#           nodes_output.csv
#           nodes_output.json
#
#   --accountname ACCOUNTNAME
#       Optional account name column.
#
#   --ticketnumber TICKETNUMBER
#       Optional ticket/case number column.
#
#   --bundlepath BUNDLEPATH
#       Path to an extracted support bundle.
#
#   --bundlefile BUNDLEFILE
#       Path to a compressed support bundle archive.
#
#   --bundledate DD/MM/YYYY
#       Scan / bundle date.
#
#   --bundlecreatedate STRING
#       Original bundle creation timestamp.
#
#   --extended-output {0,1,2,3,4}
#       Extended output level.
#
#   --debug {0,1,2,3,4}
#       Debug verbosity.
#
# Exit behaviour:
#
#   0   Success.
#   2   Invalid, unreadable or unsupported bundle.
#   130 Interrupted by user.
#


import json
import os
import fnmatch
from operator import itemgetter
from functools import reduce
import re
from pathlib import Path
import signal
import sys 
from pathlib import Path
import argparse
import time
import zipfile
import tarfile
from datetime import datetime
from dataclasses import dataclass, replace
from pathlib import Path
import  tempfile


@dataclass(frozen=True)
class Options:
    pretty: bool
    filesave: bool
    outputfile: str
    accountname: str
    ticketnumber: str
    bundlepath: str
    bundlefile: str
    bundledate: str
    extended_output: int
    debug: int
    output_mode: str
    output_format: str


@dataclass(frozen=True)
class NodeRowsResult:
    header_cols: list[str]
    rows: list[tuple]
    stats: dict
    bundle_mode: str

#------------------------------------------------------------
# Purpose:
#   Write debug or warning messages to stderr only when the
#   selected debug level is high enough.
#------------------------------------------------------------
def debug_print(level_required: int, current_level: int, msg: str) -> None:
    """Print debug message to stderr if current_level >= level_required."""
    if current_level >= level_required:
        print(msg, file=sys.stderr)

ucp_nodes = 'ucp-nodes.txt'
BUNDLE_MODE_CLUSTER = "cluster"
BUNDLE_MODE_SINGLE = "single"
BUNDLE_MODE_UNKNOWN = "unknown"
VERSION = "1.25"
TOOL_NAME = "SDNODES"

#------------------------------------------------------------
# Purpose:
#   Detect whether the supplied support bundle is a cluster-wide
#   bundle, single-node bundle, or an unsupported layout.
#
# Returns:
#   BUNDLE_MODE_CLUSTER
#   BUNDLE_MODE_SINGLE
#   BUNDLE_MODE_UNKNOWN
#------------------------------------------------------------
def detect_bundle_mode(bundle_path: str, debug_level: int = 0) -> str:
    root = bundle_root_path(bundle_path)

    if not root.exists() or not root.is_dir():
        debug_print(1, debug_level, f"[warn] bundle path does not exist or is not a directory: {root}")
        return BUNDLE_MODE_UNKNOWN

    has_ucp_nodes = (root / "ucp-nodes.txt").is_file()
    has_root_dsinfo_json = (root / "dsinfo" / "dsinfo.json").is_file()
    has_root_dsinfo_txt = (root / "dsinfo" / "dsinfo.txt").is_file()
    has_root_inspect = (root / "dsinfo" / "inspect").is_dir()

    if has_ucp_nodes:
        debug_print(2, debug_level, f"[info] detected cluster bundle: found {root / 'ucp-nodes.txt'}")
        return BUNDLE_MODE_CLUSTER

    single_score = sum([
        has_root_dsinfo_json,
        has_root_dsinfo_txt,
        has_root_inspect,
    ])

    if has_root_dsinfo_json and single_score >= 2:
        debug_print(2, debug_level, f"[INFO] detected single-node bundle: dsinfo evidence score={single_score}/3")
        return BUNDLE_MODE_SINGLE

    if has_root_dsinfo_json:
        debug_print(1, debug_level, f"[WARN] dsinfo.json found but single-node evidence is weak: score={single_score}/3")
        return BUNDLE_MODE_SINGLE

    debug_print(2, debug_level, f"[WARN] unsupported bundle layout: {root}")
    return BUNDLE_MODE_UNKNOWN

#------------------------------------------------------------
# Purpose:
#   Normalize the user-supplied bundle path into a Path object
#   so later code can build paths safely and consistently.
#
# Returns:
#   Path object for the bundle root.
#------------------------------------------------------------
def bundle_root_path(bundle_path: str) -> Path:
    """
    Normalize bundle_path into a Path object.

    Keeps legacy '.' behavior, but gives the rest of the code one safe
    path-joining style instead of string concatenation.
    """
    return Path(bundle_path or ".")

class BundleLoadError(Exception):
    pass

#------------------------------------------------------------
# Purpose:
#   Determine whether a supplied bundle file is a supported
#   archive type.
#
# Returns:
#   "zip"
#   "tar"
#   "unknown"
#------------------------------------------------------------
def detect_archive_type(path: Path) -> str:

    if zipfile.is_zipfile(path):
        return "zip"

    if tarfile.is_tarfile(path):
        return "tar"

    return "unknown"

#------------------------------------------------------------
# Purpose:
#   Validate that an archive member can be safely extracted
#   under the intended extraction directory.
#
#   This protects against archive entries such as:
#     ../../etc/passwd
#     /absolute/path/file
#
# Returns:
#   True if safe, False otherwise.
#------------------------------------------------------------
def is_safe_archive_member(member_name: str, extract_root: Path) -> bool:

    if not member_name:
        return False

    member_path = Path(member_name)

    if member_path.is_absolute():
        return False

    target_path = (extract_root / member_path).resolve()
    extract_root_resolved = extract_root.resolve()

    try:
        target_path.relative_to(extract_root_resolved)
    except ValueError:
        return False

    return True

#------------------------------------------------------------
# Purpose:
#   Detect ZIP entries that represent symbolic links by reading
#   the Unix file mode stored in external_attr when present.
#
# Returns:
#   True when the ZIP member appears to be a symbolic link.
#------------------------------------------------------------
def is_zip_symlink(member: zipfile.ZipInfo) -> bool:

    unix_mode = member.external_attr >> 16
    return (unix_mode & 0o170000) == 0o120000
#------------------------------------------------------------
# Purpose:
#   Safely extract a ZIP archive into the supplied extraction
#   directory after validating every member path.
#
# Returns:
#   None
#
# Raises:
#   BundleLoadError if the archive contains an unsafe path or
#   extraction fails.
#------------------------------------------------------------
def safe_extract_zip(archive_path: Path, extract_root: Path) -> int:

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            members = zf.infolist()

            for member in members:
                if not is_safe_archive_member(member.filename, extract_root):
                    raise BundleLoadError(
                        f"Unsafe path found in ZIP archive: {member.filename}"
                    )

                if is_zip_symlink(member):
                    raise BundleLoadError(
                        f"Unsafe symbolic link found in ZIP archive: {member.filename}"
                    )

            zf.extractall(extract_root)
            return len(members)

    except BundleLoadError:
        raise

    except Exception as e:
        raise BundleLoadError(
            f"Failed to extract ZIP archive {archive_path}: {e}"
        )
#------------------------------------------------------------
# Purpose:
#   Safely extract a TAR archive into the supplied extraction
#   directory after validating every member path.
#   automatically detects:
#   .tar
#   .tar.gz
#   .tgz
#   .tar.bz2
#   .tbz
#   .tar.xz
#   .txz
#   So we don't need to care what extension the customer used. Python just inspects the archive itself.
#
# Returns:
#   None
#
# Raises:
#   BundleLoadError if the archive contains an unsafe path or
#   extraction fails.
#------------------------------------------------------------
def safe_extract_tar(archive_path: Path, extract_root: Path) -> int:

    try:
        with tarfile.open(archive_path, "r:*") as tf:
            members = tf.getmembers()

            for member in members:
                if not is_safe_archive_member(member.name, extract_root):
                    raise BundleLoadError(
                        f"Unsafe path found in TAR archive: {member.name}"
                    )

                if member.issym() or member.islnk():
                    raise BundleLoadError(
                        f"Unsafe link found in TAR archive: {member.name} -> {member.linkname}"
                    )

            tf.extractall(extract_root)
            return len(members)

    except BundleLoadError:
        raise

    except Exception as e:
        raise BundleLoadError(
            f"Failed to extract TAR archive {archive_path}: {e}"
        )
#------------------------------------------------------------
# Purpose:
#   Extract a supported bundle archive into a controlled
#   extraction directory.
#
# Returns:
#   Path object for the directory that received extracted content.
#
# Raises:
#   BundleLoadError if archive type is unsupported or extraction
#   fails.
#------------------------------------------------------------
def extract_bundle_archive(archive_path: Path, extract_root: Path) -> int:

    archive_type = detect_archive_type(archive_path)

    if archive_type == "zip":
        return safe_extract_zip(archive_path, extract_root)

    if archive_type == "tar":
        return safe_extract_tar(archive_path, extract_root)

    raise BundleLoadError(
        f"Unsupported bundle archive format: {archive_path}"
    )
#------------------------------------------------------------
# Purpose:
#   Locate the actual support bundle root after archive extraction.
#
#   Archives may extract as:
#     extracted/ucp-nodes.txt
#     extracted/docker-support-abc/ucp-nodes.txt
#     extracted/dsinfo/dsinfo.json
#     extracted/docker-support-abc/dsinfo/dsinfo.json
#
# Returns:
#   Path object for the detected bundle root.
#
# Raises:
#   BundleLoadError if no supported bundle root is found.
#------------------------------------------------------------
def find_extracted_bundle_root(extract_root: Path, debug_level: int = 0) -> Path:

    candidate_roots = [extract_root]

    for path in extract_root.rglob("*"):
        if path.is_dir():
            candidate_roots.append(path)

    valid_roots = []

    for candidate in candidate_roots:
        mode = detect_bundle_mode(str(candidate), debug_level)

        if mode in (BUNDLE_MODE_CLUSTER, BUNDLE_MODE_SINGLE):
            valid_roots.append((candidate, mode))

    if not valid_roots:
        raise BundleLoadError(
            f"No supported bundle root found after archive extraction: {extract_root}"
        )

    if len(valid_roots) > 1:
        root_list = ", ".join(str(path) for path, _mode in valid_roots)
        raise BundleLoadError(
            f"Multiple supported bundle roots found after archive extraction; refusing to choose arbitrarily: {root_list}"
        )

    bundle_root, mode = valid_roots[0]
    debug_print(
        1,
        debug_level,
        f"[info] detected extracted bundle root: {bundle_root} ({mode})"
    )
    return bundle_root
#------------------------------------------------------------
# Purpose:
#   Prepare the supplied support bundle input for processing.
#
#   Directory input is returned as-is after path normalization.
#   Archive input is extracted into the supplied temporary root,
#   then normalized to the actual bundle root directory.
#
# Returns:
#   Path object representing the bundle root directory.
#
# Raises:
#   BundleLoadError when archive input cannot be extracted or
#   no supported bundle root can be found after extraction.
#------------------------------------------------------------
def prepare_bundle_input(opts: Options, temp_root: Path | None = None) -> Path:

    if opts.bundlefile:

        if temp_root is None:
            raise BundleLoadError(
                "Internal error: archive input requires a temporary extraction directory."
            )

        archive_path = Path(opts.bundlefile)

        if not archive_path.is_file():
            raise BundleLoadError(
                f"Bundle archive does not exist or is not a file: {archive_path}"
            )

        archive_type = detect_archive_type(archive_path)

        if archive_type == "unknown":
            raise BundleLoadError(
                f"Unsupported bundle archive format: {archive_path}"
            )

        extract_root = temp_root / "extracted"
        extract_root.mkdir(parents=True, exist_ok=True)

        member_count = extract_bundle_archive(archive_path, extract_root)

        bundle_root = find_extracted_bundle_root(extract_root, opts.debug)

        debug_print(
            1,
            opts.debug,
            f"[info] archive input: type={archive_type} file={archive_path.name} members={member_count} extraction_dir={extract_root} bundle_root={bundle_root}"
        )

        return bundle_root

    return bundle_root_path(opts.bundlepath)
#------------------------------------------------------------
# Purpose:
#   Read a JSON file safely, report failures through debug output,
#   and optionally treat the file as required.
#
# Returns:
#   Parsed JSON data, or the supplied default value.
#
# Raises:
#   BundleLoadError when required=True and the file cannot be read
#   or parsed.
#------------------------------------------------------------
def safe_read_json_file(path: Path, debug_level: int = 0, required: bool = False, default=None):
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as r:
            return json.load(r)
    except Exception as e:
        debug_print(1, debug_level, f"[warn] failed to read JSON {path}: {e}")
        if required:
            raise BundleLoadError(f"Required JSON file is missing or invalid: {path}")
        return default

#------------------------------------------------------------
# Purpose:
#   Convert a value to an integer without allowing bad or missing
#   data to interrupt bundle processing.
#
# Returns:
#   Converted integer, or the supplied default value.
#------------------------------------------------------------
def safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default

#------------------------------------------------------------
# Purpose:
#   Search a directory tree for the first file matching the
#   supplied filename or wildcard pattern.
#
# Returns:
#   Full matching path as a string, or None if not found.
#------------------------------------------------------------
def findfile(topdir, f_glob):
    for d_name, sd_name, f_list in os.walk(topdir):
        for f_name in f_list:
            if fnmatch.fnmatch(f_name, f_glob):
                return os.path.join(d_name, f_name)

#------------------------------------------------------------
# Purpose:
#   Read a Docker inspect JSON file and extract a specific
#   environment variable such as IMAGE_VERSION or DTR_VERSION.
#
# Returns:
#   Requested version string, or '-' if unavailable.
#------------------------------------------------------------
def getddcver(nodename, f_glob, k, debug_level=0):
    """
    Return container image/env version value from docker inspect JSON.

    Expected shape:
      [
        {
          "Config": {
            "Env": [
              "IMAGE_VERSION=3.8.14",
              "DTR_VERSION=2.9.23"
            ]
          }
        }
      ]

    Safe fallback:
      '-' for missing file, invalid JSON, unexpected shape, missing Env,
      missing key, or malformed env entries.
    """
    f = findfile(nodename, f_glob)
    if not f:
        debug_print(2, debug_level, f"[warn] getddcver: no file found for {f_glob} under {nodename}")
        return "-"

    try:
        with open(f, "r", encoding="utf-8", errors="ignore") as r:
            j = json.load(r)
    except Exception as e:
        debug_print(1, debug_level, f"[warn] getddcver: failed to read/parse JSON {f}: {e}")
        return "-"

    if not isinstance(j, list) or not j:
        debug_print(1, debug_level, f"[warn] getddcver: unexpected JSON shape in {f}; expected non-empty list")
        return "-"

    first = j[0]
    if not isinstance(first, dict):
        debug_print(1, debug_level, f"[warn] getddcver: first JSON item is not an object in {f}")
        return "-"

    config = first.get("Config")
    if not isinstance(config, dict):
        debug_print(1, debug_level, f"[warn] getddcver: Config missing/not object in {f}")
        return "-"

    env = config.get("Env")
    if not isinstance(env, list):
        debug_print(1, debug_level, f"[warn] getddcver: Config.Env missing/not list in {f}")
        return "-"

    prefix = f"{k}="
    for item in env:
        if not isinstance(item, str):
            continue
        if item.startswith(prefix):
            value = item.split("=", 1)[1].strip()
            return value if value else "-"

    debug_print(2, debug_level, f"[warn] getddcver: {k}= not found in {f}")
    return "-"

#------------------------------------------------------------
# Purpose:
#   Render one output row to stdout and, when requested, also
#   write that same row to the configured output file.
#------------------------------------------------------------
def row_print2(row, widths, outfile=None, *, pretty: bool = True, sep: str = "  "):
    """Render one row to stdout, and optionally to a file handle.

    This preserves the original behavior:
      - pretty=True uses two spaces between columns.
      - pretty=False uses semicolon delimiter.
      - each column is padded to the computed width list.
    """
    # Ensure we always stringify values (None-safe)
    cells = ["" if v is None else str(v) for v in row]
    if pretty:
        # Pad each cell (left-aligned) to its column width for terminal readability.
        padded = [f"{cells[i]:<{widths[i]}}" for i in range(min(len(cells), len(widths)))]
        # If for some reason there are more cells than widths, append unpadded.
        if len(cells) > len(widths):
            padded.extend(cells[len(widths):])
        line = sep.join(padded)
    else:
        # Machine/spreadsheet output: no visual padding inside delimited fields.
        line = ";".join(cell.strip() for cell in cells)

    print(line, flush=True)
    if outfile is not None:
        outfile.write(line + "\n")
        outfile.flush()

#------------------------------------------------------------
# Purpose:
#   Safely extract text that appears after a known marker within
#   a line of text.
#
# Returns:
#   Text after the marker, or the supplied default value.
#------------------------------------------------------------
def value_after_marker(line: str, marker: str, default: str = "") -> str:
    """
    Return text after marker if present, else default.
    Safe replacement for split(marker)[1].
    """
    if marker not in line:
        return default
    return line.split(marker, 1)[1].strip()

#------------------------------------------------------------
# Purpose:
#   Safely extract text that appears after the first colon in a
#   line of text.
#
# Returns:
#   Text after the colon, or the supplied default value.
#------------------------------------------------------------
def value_after_colon(line: str, default: str = "") -> str:
    """
    Return text after the first colon.
    Handles both ': ' and ':' safely.
    """
    if ":" not in line:
        return default
    return line.split(":", 1)[1].strip()

#------------------------------------------------------------
# Purpose:
#   Parse Linux os-release assignment lines such as NAME= or
#   VERSION= while handling quoted and unquoted values.
#
# Returns:
#   Parsed value, or the supplied default value.
#------------------------------------------------------------
def parse_os_release_assignment(line: str, key: str, default: str = "") -> str:
    """
    Safely parse NAME=..., VERSION=..., VERSION_ID=... style lines.
    Handles quoted and unquoted values.
    """
    prefix = f"{key}="
    if not line.startswith(prefix):
        return default

    value = line.split("=", 1)[1].strip()
    value = value.strip('"').strip("'").strip()
    return value or default

#------------------------------------------------------------
# Purpose:
#   Extract the first whitespace-delimited token from a string.
#
# Returns:
#   First token, or the supplied default value.
#------------------------------------------------------------
def first_token(value: str, default: str = "") -> str:
    """
    Return first whitespace-delimited token from a string.
    """
    parts = value.split()
    return parts[0] if parts else default

#------------------------------------------------------------
# Purpose:
#   Inspect kube-describe-nodes output for one node and determine
#   whether it reports an allocated nvidia.com/gpu resource.
#
# Returns:
#   1 when GPU allocation is detected, 0/None otherwise.
#------------------------------------------------------------
def parse_node_gpu_flag(path: str, target_nodename: str):
    """
    Scan a kubectl-describe-nodes output file and, for the section whose
    hostname matches `target_nodename`, return (hostname, gpu_flag),
    where gpu_flag is 1 if 'nvidia.com/gpu' is under its Allocated resources.
    """
    if not os.path.isfile(path):
        return
    
    with open(path, 'r') as f:
        lines = f.readlines()

    # Find the indices of all sections (lines starting with "Name:")
    section_starts = [i for i, line in enumerate(lines) if line.startswith("Name:")]
    # Append end-of-file to make slicing easier
    section_starts.append(len(lines))

    
    for idx in range(len(section_starts) - 1):
        start = section_starts[idx]
        end = section_starts[idx + 1]
        section = lines[start:end]

        # 1) Extract hostname (up to first dot) from the "Name:" line
        name_line = section[0]  # guaranteed to start with "Name:"
        full_name = name_line.split("Name:")[1].strip()
        hostname = full_name.split('.', 1)[0]

        # 2) If it’s not our target, skip it
        if hostname != target_nodename:
            continue
        
        # 3) Scan this section for "Allocated resources:"
        gpu_flag = 0
        for i, line in enumerate(section):
            if line.strip().startswith("Allocated resources:"):
                # look at the lines immediately following until blank line
                for sub in section[i+1:]:
                    sub = sub.strip()
                    if not sub:
                        break
                    if "nvidia.com/gpu" in sub:
                        gpu_flag = 1
                        break
                break

        return gpu_flag

#------------------------------------------------------------
# Purpose:
#   Read dsinfo.txt for a node and derive operating system,
#   hypervisor, uptime, subnet mask, kernel and hardware details.
#
# Returns:
#   Tuple of OS text, hypervisor, uptime, subnet mask, kernel,
#   manufacturer, product name and family.
#------------------------------------------------------------
def full_os_details_v1(hostname, ip_add, bundle_path, debug_level, bundle_mode):
    dsi_os = "NoInfo "
    os_type = "?"
    os_version = "NA"
    uptime = "NoInfo"
    hpv = mask = " ??   "
    manu = fam = pname = "...Unknown..."
    node_kernel = ""
    kernel_version = ""

    root = bundle_root_path(bundle_path)

    if bundle_mode == BUNDLE_MODE_SINGLE:
        node_dsinfo_filename = root / "dsinfo" / "dsinfo.txt"
    else:
        node_dsinfo_filename = root / hostname / "dsinfo" / "dsinfo.txt"

    full_os_text = os_type + "-" + os_version + " / " + dsi_os
    ip_match = " inet " + str(ip_add)

    try:
        with open(node_dsinfo_filename, "r", encoding="utf-8", errors="ignore") as inf:
            for raw_line in inf:
                line = raw_line.lstrip()

                if line.startswith("Operating System:"):
                    parsed = value_after_colon(line, dsi_os)
                    if parsed:
                        dsi_os = parsed

                    dsi_os_lower = dsi_os.lower()

                    if dsi_os_lower.startswith("windows"):
                        parts = dsi_os.split()
                        if parts:
                            dsi_os = parts[-1].strip(")")
                        break

                    if dsi_os_lower.startswith("suse"):
                        dsi_os = dsi_os.replace(" Linux Enterprise Server ", "-")
                    elif dsi_os_lower.startswith("red hat"):
                        if "." in dsi_os:
                            dot_pos = dsi_os.find(".")
                            if dot_pos > 0 and dot_pos + 1 < len(dsi_os):
                                version = dsi_os[dot_pos - 1] + dsi_os[dot_pos + 1]
                                dsi_os = "RHEL" + version
                            else:
                                dsi_os = "RHEL"
                        else:
                            dsi_os = "RHEL"
                    elif dsi_os_lower.startswith("rhel"):
                        dsi_os = "RHEL"
                    elif dsi_os_lower.startswith("centos"):
                        dsi_os = dsi_os.replace(" Linux ", "").rstrip("(Core)")
                    elif dsi_os_lower.startswith("ubuntu"):
                        dsi_os = dsi_os.rstrip("LTS").strip()
                    elif dsi_os_lower.startswith("oracle"):
                        dsi_os = dsi_os.replace(" Linux Server ", "")
                    elif dsi_os_lower.startswith("openshift"):
                        dsi_os = "OpenShift"

                    continue

                if line.startswith("Kernel Version:"):
                    kernel_version = value_after_colon(line, kernel_version)
                    continue

                if line.startswith("Linux version "):
                    parts = line.split()
                    if len(parts) >= 3:
                        node_kernel = parts[2]
                    else:
                        debug_print(2, debug_level, f"[warn] full_os_details: malformed Linux version line in {node_dsinfo_filename}: {line.strip()}")
                    continue

                if "load average:" in line:
                    if "up " in line:
                        uptime = value_after_marker(line, "up ", uptime)
                        uptime = uptime.split(",", 1)[0].strip()
                        if re.fullmatch(r"\d+:\d{2}", uptime):
                            uptime = f"0 days {uptime}"
                    else:
                        debug_print(2, debug_level, f"[warn] full_os_details: load average line has no 'up ' marker in {node_dsinfo_filename}")
                    continue

                if line.startswith("NAME="):
                    parsed = parse_os_release_assignment(line, "NAME", os_type)
                    if parsed:
                        os_type = parsed
                        if os_type.startswith("Red"):
                            os_type = "RHEL"
                    continue

                if line.startswith("VERSION="):
                    parsed = parse_os_release_assignment(line, "VERSION", os_version)
                    if parsed:
                        os_version = first_token(parsed, os_version)
                    continue

                if line.startswith("CentOS Linux release "):
                    parts = line.split()
                    if len(parts) >= 4:
                        os_type = "Centos"
                        os_version = parts[3]
                    else:
                        debug_print(2, debug_level, f"[warn] full_os_details: malformed CentOS release line in {node_dsinfo_filename}: {line.strip()}")
                    continue

                if line.startswith("Red Hat Enterprise Linux release "):
                    parts = line.split()
                    if len(parts) >= 6:
                        os_type = "Rhel"
                        os_version = parts[5]
                    else:
                        debug_print(2, debug_level, f"[warn] full_os_details: malformed RHEL release line in {node_dsinfo_filename}: {line.strip()}")
                    continue

                if line.startswith("Hypervisor vendor:"):
                    hpv = value_after_colon(line, hpv)
                    continue

                if line.startswith("Manufacturer:"):
                    manu = value_after_colon(line, manu)
                    continue

                if line.startswith("Product Name:"):
                    pname = value_after_colon(line, pname)
                    continue

                if line.startswith("Family:"):
                    fam = value_after_colon(line, fam)
                    continue

                if ip_match in line:
                    parts = line.split()
                    if len(parts) >= 4 and "/" in parts[3]:
                        mask_candidate = parts[3].split("/", 1)[1].strip()
                        if mask_candidate:
                            mask = mask_candidate
                    else:
                        debug_print(2, debug_level, f"[warn] full_os_details: malformed interface line for {ip_add} in {node_dsinfo_filename}: {line.strip()}")
                    break

        full_os_text = os_type + "-" + os_version + "/ " + dsi_os
        debug_print(2, debug_level, f"...kernel_version={kernel_version}  node_kernel={node_kernel}")
        return full_os_text, hpv, uptime, mask, kernel_version, manu, pname, fam

    except FileNotFoundError:
        debug_print(1, debug_level, f"[warn] full_os_details: dsinfo.txt not found: {node_dsinfo_filename}")
        return full_os_text, hpv, uptime, mask, node_kernel, manu, pname, fam

    except Exception as e:
        debug_print(1, debug_level, f"[warn] full_os_details: failed reading {node_dsinfo_filename}: {e}")
        return full_os_text, hpv, uptime, mask, node_kernel, manu, pname, fam

#------------------------------------------------------------
# Purpose:
#   Load the cluster node inventory from ucp-nodes.txt and verify
#   that the parsed JSON is a list.
#
# Returns:
#   List of cluster node records.
#
# Raises:
#   BundleLoadError if the inventory is missing, invalid or not a
#   JSON list.
#------------------------------------------------------------
def load_cluster_nodes(f: str, debug_level: int = 0) -> list:
    path = Path(f)

    data = safe_read_json_file(path, debug_level, required=True, default=[])

    if not isinstance(data, list):
        raise BundleLoadError(f"Cluster node inventory is not a JSON list: {path}")

    return data

#------------------------------------------------------------
# Purpose:
#   Load a single-node support bundle and construct a synthetic
#   node record compatible with the cluster processing pipeline.
#
# Returns:
#   List containing one synthetic node record.
#
# Raises:
#   BundleLoadError if required single-node JSON is missing or
#   malformed.
#------------------------------------------------------------
def load_single_node(bundle_path: str, debug_level: int = 0) -> list:

    root = Path(bundle_path)
    dsinfo_json_path = root / "dsinfo" / "dsinfo.json"

    dsinfo = safe_read_json_file(dsinfo_json_path, debug_level, required=True, default={})
    if not isinstance(dsinfo, dict):
        raise BundleLoadError(f"Single-node dsinfo.json is not a JSON object: {dsinfo_json_path}")
    
    node_id = "single-node"
    is_manager = False
    node_ip = "0.0.0.0"
    cluster_id ="0000000000"

    dsinfo_txt_path = root / "dsinfo" / "dsinfo.txt"
    
    if dsinfo_txt_path.is_file():
        with dsinfo_txt_path.open("r", encoding="utf-8", errors="ignore") as r:
            for line in r:
                if "NodeID:" in line:
                    node_id = line.split("NodeID:", 1)[1].strip()
                
                if "Is Manager:" in line:
                    is_manager = line.split("Is Manager:", 1)[1].strip().lower() == "true"

                if "Node Address:" in line:
                    node_ip = line.split("Node Address:", 1)[1].strip()
                
                if "com.docker.ucp.InstanceID" in line:
                    match = re.search(r'"com\.docker\.ucp\.InstanceID"\s*:\s*"([^"]+)"', line)
                    if match:
                        cluster_id = match.group(1)

    mke_version = "?.?.??"
    mke_found = getddcver(str(root / "dsinfo" / "inspect"), "ucp-proxy.txt", "IMAGE_VERSION", debug_level)
    if mke_found != "-":
        mke_version = mke_found


    docker_info = dsinfo.get("docker_info", {})
    docker_version = dsinfo.get("docker_version", {})

    hostname_list = dsinfo.get("hostname", [])
    hostname = hostname_list[0] if hostname_list else "single-node"

    server_version = docker_version.get("Server", {})
    engine_version = server_version.get("Version", "?.?.????")

    arch = docker_info.get("Architecture", "unknown")

    ncpu = safe_int(docker_info.get("NCPU", 0), 0)
    mem_total = safe_int(docker_info.get("MemTotal", 0), 0)

    nano_cpus = ncpu * 1_000_000_000
    memory_bytes = mem_total

    role_value = "manager" if is_manager else "worker"

    node = {
        "ID": node_id,
        "Description": {
            "Hostname": hostname,
            "Resources": {
                "NanoCPUs": nano_cpus,
                "MemoryBytes": memory_bytes,
            },
            "Platform": {
                "Architecture": arch,
                "OS": "linux",
            },
            "Engine": {
                "EngineVersion": engine_version,
            },
        },
        "Spec": {
            "Role": role_value,
            "Labels": {
                "com.docker.ucp.orchestrator.swarm": "true",
                "com.docker.ucp.orchestrator.kubernetes": "true",
                "_sdnodes_single_mke_version": mke_version,
                "_sdnodes_single_cluster_id": cluster_id,
            },
            "Availability": "Unknown",
        },
        "Status": {
            "State": "unknown",
            "Addr": node_ip,
            "Message": "No Status Avail",
        },
        "CreatedAt": "(NoDateAvail",
        "UpdatedAt": "NoDateAvail)",
    }

    return [node]

#------------------------------------------------------------
# Purpose:
#   Extract a short node ID from a node dictionary for warnings
#   and diagnostics.
#
# Returns:
#   First 10 characters of the node ID, or a default fallback.
#------------------------------------------------------------
def safe_node_id(node: dict, default: str = "UNKNOWN-ID") -> str:
    if isinstance(node, dict):
        node_id = node.get("ID")
        if isinstance(node_id, str) and node_id.strip():
            return node_id[:10]
    return default

#------------------------------------------------------------
# Purpose:
#   Process every discovered node, collect operating system,
#   platform, hardware and version information, then generate
#   the output rows for the selected output mode.
#------------------------------------------------------------
def collect_node_rows(sd: list, opts: Options, bundle_mode: str) -> NodeRowsResult:
    node_tuples = []
    kernels_of_nodes = set()
    cnt_mke_nodes = 0
    cnt_mcr_nodes = 0
    cnt_msr_nodes = 0
    cnt_gpu_nodes = 0
    cnt_vcpus = 0
    skipped_nodes = 0

    account_name = opts.accountname
    ticket_number = opts.ticketnumber
    bundle_path = opts.bundlepath
    bundle_date = opts.bundledate
    ticket_mode = (opts.output_mode == "ticket")
    pretty = False if ticket_mode else opts.pretty
    file_save = opts.filesave
    outputFile = opts.outputfile
    debug_level = opts.debug
    extended_output = opts.extended_output
    root = bundle_root_path(bundle_path)

    has_account = (account_name != '<undefined account name>')
    has_ticket = (ticket_number != '00000000')
    include_hw = (extended_output >= 1)

    if has_account and has_ticket:
        header = 'ACCOUNT TICKET CLUSTER-ID HOSTNAME NODE-ID ROLE TYPE MCRv MKEv MSRv SWARM? KUBE? OS OSver ARCH HYPERV CPUs RAM GPU UPTIME AVAIL STATE IP/MASK COLLECT CREATED/UPDATED STATUS_MESSAGE -SCANDATE-'
        if include_hw:
            header += ' MANUFACTURER PRODUCT_NAME FAMILY'
        sort_getter = itemgetter(5, 6, 3, 10)

        def build_row(**kw):
            return (
                kw['account_name'], kw['ticket_number'], kw['cluster_id'], kw['hostname'], kw['id'],
                kw['role'], kw['role_type'], kw['engver'], kw['ucpver'], kw['dtrver'],
                kw['o_swarm'], kw['o_kube'], kw['os'], kw['os_string'], kw['arch'],
                kw['hypervisor'], kw['cpus'], kw['ram'], kw['gpu_mode'], kw['node_uptime'],
                kw['avail'], kw['state'], kw['addr'], kw['collect'], kw['t_stamps'],
                kw['stsmsg'], kw['bundle_date']
            ) + ((kw['manu'], kw['pname'], kw['fam']) if include_hw else ())

    elif has_account and not has_ticket:
        header = 'ACCOUNT CLUSTER-ID HOSTNAME NODE-ID ROLE TYPE MCRv MKEv MSRv SWARM? KUBE? OS OSver ARCH HYPERV CPUs RAM GPU UPTIME AVAIL STATE IP/MASK COLLECT CREATED/UPDATED STATUS_MESSAGE -SCANDATE-'
        if include_hw:
            header += ' MANUFACTURER PRODUCT_NAME FAMILY'
        sort_getter = itemgetter(4, 5, 2, 9)

        def build_row(**kw):
            return (
                kw['account_name'], kw['cluster_id'], kw['hostname'], kw['id'],
                kw['role'], kw['role_type'], kw['engver'], kw['ucpver'], kw['dtrver'],
                kw['o_swarm'], kw['o_kube'], kw['os'], kw['os_string'], kw['arch'],
                kw['hypervisor'], kw['cpus'], kw['ram'], kw['gpu_mode'], kw['node_uptime'],
                kw['avail'], kw['state'], kw['addr'], kw['collect'], kw['t_stamps'],
                kw['stsmsg'], kw['bundle_date']
            ) + ((kw['manu'], kw['pname'], kw['fam']) if include_hw else ())

    elif (not has_account) and has_ticket:
        header = 'TICKET CLUSTER-ID HOSTNAME NODE-ID ROLE TYPE MCRv MKEv MSRver SWARM? KUBE? OS OSver ARCH HYPERV CPUs RAM GPU UPTIME AVAIL STATE IP/MASK COLLECT CREATED/UPDATED STATUS_MESSAGE -SCANDATE-'
        if include_hw:
            header += ' MANUFACTURER PRODUCT_NAME FAMILY'
        sort_getter = itemgetter(4, 5, 2, 9)

        def build_row(**kw):
            return (
                kw['ticket_number'], kw['cluster_id'], kw['hostname'], kw['id'],
                kw['role'], kw['role_type'], kw['engver'], kw['ucpver'], kw['dtrver'],
                kw['o_swarm'], kw['o_kube'], kw['os'], kw['os_string'], kw['arch'],
                kw['hypervisor'], kw['cpus'], kw['ram'], kw['gpu_mode'], kw['node_uptime'],
                kw['avail'], kw['state'], kw['addr'], kw['collect'], kw['t_stamps'],
                kw['stsmsg'], kw['bundle_date']
            ) + ((kw['manu'], kw['pname'], kw['fam']) if include_hw else ())

    else:
        header = 'CLUSTER-ID HOSTNAME NODE-ID ROLE TYPE MCRv MKEv MSRv SWARM? KUBE? OS OSver ARCH HYPERV CPUs RAM GPU UPTIME AVAIL STATE IP/MASK COLLECT CREATED/UPDATED STATUS_MESSAGE -SCANDATE-'
        if include_hw:
            header += ' MANUFACTURER PRODUCT_NAME FAMILY'
        sort_getter = itemgetter(3, 4, 1, 8)

        def build_row(**kw):
            return (
                kw['cluster_id'], kw['hostname'], kw['id'],
                kw['role'], kw['role_type'], kw['engver'], kw['ucpver'], kw['dtrver'],
                kw['o_swarm'], kw['o_kube'], kw['os'], kw['os_string'], kw['arch'],
                kw['hypervisor'], kw['cpus'], kw['ram'], kw['gpu_mode'], kw['node_uptime'],
                kw['avail'], kw['state'], kw['addr'], kw['collect'], kw['t_stamps'],
                kw['stsmsg'], kw['bundle_date']
            ) + ((kw['manu'], kw['pname'], kw['fam']) if include_hw else ())

    header_cols = header.split(' ')

    for node_index, node in enumerate(sd, start=1):
        try:
            if not isinstance(node, dict):
                skipped_nodes += 1
                debug_print(1, debug_level, f"[warn] process_nodes: skipped node #{node_index}; expected object, got {type(node).__name__}")
                continue

            hostname = "????"
            arch = "????"
            os = "????"
            os_string = "????"
            addr = "???.???.???.???"
            node_uptime = "????"
            cpus = "     "
            ram = "    "
            kernel_of_node = ""
            hypervisor = "-"
            role = "       "
            role_type = "    "
            node_id_short = "          "
            subnet_mask = "??"
            manu = pname = fam = "...Unknown..."
            avail = "unknown"
            state = "unknown"
            collect = "unknown"
            stsmsg = "N/A"
            o_swarm = "------"
            o_kube = "------"
            gpu_mode = "... "
            engver = "?.?.????"
            ucpver = "?.?.??"
            dtrver = "-.-.--"

            desc = node.get("Description", {})
            if not isinstance(desc, dict):
                desc = {}

            spec = node.get("Spec", {})
            if not isinstance(spec, dict):
                spec = {}

            status = node.get("Status", {})
            if not isinstance(status, dict):
                status = {}

            labels = spec.get("Labels", {})
            if not isinstance(labels, dict):
                labels = {}

            manager_status = node.get("ManagerStatus", {})
            if not isinstance(manager_status, dict):
                manager_status = {}

            platform = desc.get("Platform", {})
            if not isinstance(platform, dict):
                platform = {}

            resources = desc.get("Resources", {})
            if not isinstance(resources, dict):
                resources = {}

            engine = desc.get("Engine", {})
            if not isinstance(engine, dict):
                engine = {}

            hostname = desc.get("Hostname", hostname)
            if not hostname and "ID" in node:
                hostname = f"!!! {str(node['ID'])[:10]} ID!!!>>"

            if "ID" in node and isinstance(node["ID"], str) and node["ID"].strip():
                node_id_short = node["ID"][:10]
            else:
                skipped_nodes += 1
                debug_print(1, debug_level, f"[warn] process_nodes: skipped node #{node_index}; missing node ID")
                continue

            spec_role = spec.get("Role")
            if spec_role == "manager":
                if manager_status:
                    if manager_status.get("Leader") is True:
                        role = "leader"
                    else:
                        role = "manager"
                    role_type = "MKE "
                else:
                    role = "BAD-Manager"
                    role_type = "MKE "
            elif spec_role:
                role = "worker"
                role_type = "MCR "

            nano_cpus = resources.get("NanoCPUs")
            if isinstance(nano_cpus, (int, float)):
                cpu_count = int(nano_cpus / 1e9)
                cpus = str(cpu_count)
                cnt_vcpus += cpu_count

            memory_bytes = resources.get("MemoryBytes")
            if isinstance(memory_bytes, (int, float)):
                ram = str(round(memory_bytes / (1024 ** 3), 2))

            cpus += "     "
            ram += "    "

            arch = platform.get("Architecture", arch)

            avail = spec.get("Availability", avail)
            state = status.get("State", state)

            if "Addr" in status:
                addr = status.get("Addr") or addr
                if addr in ("127.0.0.1", "0.0.0.0"):
                    mgr_addr = manager_status.get("Addr")
                    if isinstance(mgr_addr, str) and mgr_addr:
                        addr = mgr_addr.replace(":2377", "")

            if "OS" in platform:
                os = platform.get("OS", os)
                os_string, hypervisor, node_uptime, subnet_mask, kernel_of_node, manu, pname, fam = full_os_details_v1(
                    hostname, addr, bundle_path, debug_level, bundle_mode
                )
                addr = " / ".join([addr, subnet_mask])
                if kernel_of_node:
                    kernels_of_nodes.add(kernel_of_node)

            if "EngineVersion" in engine:
                engver = engine.get("EngineVersion", engver)

            collect = labels.get("com.docker.ucp.access.label", collect)

            if labels.get("com.docker.ucp.orchestrator.swarm") == "true":
                o_swarm = "swarm "

            if labels.get("com.docker.ucp.orchestrator.kubernetes") == "true":
                o_kube = "kube  "

            if "Message" in status:
                stsmsg = status.get("Message", stsmsg)

            if bundle_mode == BUNDLE_MODE_SINGLE:
                dir_to_search2 = root / "dsinfo" / "inspect"
            else:
                dir_to_search2 = root / hostname / "dsinfo" / "inspect"

            ucpver_found = getddcver(str(dir_to_search2), "ucp-proxy.txt", "IMAGE_VERSION", debug_level)
            if ucpver_found != "-":
                ucpver = ucpver_found
            elif bundle_mode == BUNDLE_MODE_SINGLE:
                ucpver = labels.get("_sdnodes_single_mke_version", ucpver)

            dtrver_found = getddcver(str(dir_to_search2), "dtr-registry-*.txt", "DTR_VERSION", debug_level)
            if dtrver_found != "-":
                dtrver = dtrver_found

            if dtrver != "-.-.--":
                role_type = "MSR "

            file_path = root / "ucp-instance-id.txt"
            cluster_id = "0000000000"

            if file_path.is_file():
                try:
                    cluster_id = file_path.read_text(encoding="utf-8").strip()
                except Exception as e:
                    debug_print(1, debug_level, f"[warn] process_nodes: failed reading cluster id file {file_path}: {e}")
                    cluster_id = "00-??-000"

            if bundle_mode == BUNDLE_MODE_SINGLE:
                cluster_id = labels.get("_sdnodes_single_cluster_id", "0000000000")

            cluster_id = str(cluster_id)[:10]

            c_at = "1970-01-01T00:00:00.0000000Z"
            u_at = "1970-01-01T00:00:00.0000000Z"

            if isinstance(node.get("CreatedAt"), str):
                c_at = node["CreatedAt"].split(".", 1)[0].replace("T", "_")

            if isinstance(node.get("UpdatedAt"), str):
                u_at = node["UpdatedAt"].split(".", 1)[0].replace("T", "_")

            t_stamps = " / ".join([c_at, u_at])

            disp_ver = engver
            match role_type:
                case "MKE ":
                    disp_ver = ucpver
                case "MCR ":
                    disp_ver = engver
                case "MSR ":
                    disp_ver = dtrver

            debug_print(2, debug_level, f"role_type={role_type}, engver={engver}    ucpver={ucpver}    dtrver={dtrver}")

            kubedescribe_file = root / "kube-describe-nodes.txt"
            nodehostname = str(hostname).split(".", 1)[0]

            gpu = parse_node_gpu_flag(str(kubedescribe_file), nodehostname)

            if not gpu and bundle_mode == BUNDLE_MODE_SINGLE:
                try:
                    dsinfo_json_file = root / "dsinfo" / "dsinfo.json"
                    if dsinfo_json_file.is_file():
                        if "nvidia.com/gpu" in dsinfo_json_file.read_text(encoding="utf-8", errors="ignore"):
                            gpu = 1
                except Exception:
                    pass

            if gpu:
                gpu_mode = "GPU "

            node_tuples.append(build_row(
                account_name=account_name,
                ticket_number=ticket_number,
                cluster_id=cluster_id,
                hostname=hostname,
                id=node_id_short,
                role=role,
                role_type=role_type,
                disp_ver=disp_ver,
                engver=engver,
                ucpver=ucpver,
                dtrver=dtrver,
                o_swarm=o_swarm,
                o_kube=o_kube,
                os=os,
                os_string=os_string,
                arch=arch,
                hypervisor=hypervisor,
                cpus=cpus,
                ram=ram,
                gpu_mode=gpu_mode,
                node_uptime=node_uptime,
                avail=avail,
                state=state,
                addr=addr,
                collect=collect,
                t_stamps=t_stamps,
                stsmsg=stsmsg,
                bundle_date=bundle_date,
                manu=manu,
                pname=pname,
                fam=fam
            ))

            match role_type:
                case "MKE ":
                    cnt_mke_nodes += 1
                case "MCR ":
                    cnt_mcr_nodes += 1
                case "MSR ":
                    cnt_msr_nodes += 1

            if gpu:
                cnt_gpu_nodes += 1

        except Exception as e:
            skipped_nodes += 1
            node_hint = safe_node_id(node)
            debug_print(1, debug_level, f"[warn] process_nodes: skipped node #{node_index} ({node_hint}) due to error: {e}")
            continue

    sorted_rows = sorted(node_tuples, key=sort_getter) if node_tuples else []
    total_nodes = cnt_mke_nodes + cnt_mcr_nodes + cnt_msr_nodes

    stats = {
        "total_nodes": total_nodes,
        "mke_nodes": cnt_mke_nodes,
        "mcr_nodes": cnt_mcr_nodes,
        "msr_nodes": cnt_msr_nodes,
        "gpu_nodes": cnt_gpu_nodes,
        "vcpus": cnt_vcpus,
        "skipped_nodes": skipped_nodes,
        "unique_kernels": sorted(kernels_of_nodes),
    }

    return NodeRowsResult(
        header_cols=header_cols,
        rows=sorted_rows,
        stats=stats,
        bundle_mode=bundle_mode,
    )

#------------------------------------------------------------
# Purpose:
#   Render collected node rows using the existing table/CSV
#   behavior, including optional file output and engineer-mode
#   summary information.
#------------------------------------------------------------
def render_table(result: NodeRowsResult, opts: Options) -> None:
    ticket_mode = (opts.output_mode == "ticket")
    pretty = False if ticket_mode else opts.pretty
    file_save = opts.filesave
    outputFile = opts.outputfile
    debug_level = opts.debug

    if result.rows:
        widths = []
        for i in range(len(result.rows[0])):
            longest_value_in_col_i = max(result.rows, key=lambda row: len(str(row[i])))[i]
            widths.append(len(str(longest_value_in_col_i)))
    else:
        widths = [len(c) for c in result.header_cols]

    if file_save:
        with open(outputFile, "w") as outfile:
            row_print2(result.header_cols, widths, outfile=outfile, pretty=pretty)
            for row in result.rows:
                row_print2(row, widths, outfile=outfile, pretty=pretty)
    else:
        row_print2(result.header_cols, widths, outfile=None, pretty=pretty)
        for row in result.rows:
            row_print2(row, widths, outfile=None, pretty=pretty)

    total_nodes = result.stats["total_nodes"]
    cnt_mke_nodes = result.stats["mke_nodes"]
    cnt_mcr_nodes = result.stats["mcr_nodes"]
    cnt_msr_nodes = result.stats["msr_nodes"]
    cnt_vcpus = result.stats["vcpus"]
    skipped_nodes = result.stats["skipped_nodes"]
    kernels_of_nodes = set(result.stats["unique_kernels"])

    if not ticket_mode:
        print(f"--------------------------------------------------------------------------\n🔶🔶 SUMMARY INFORMATION 🔶🔶", flush=True)
        print(f"Node Counts: TOTAL:[{total_nodes}]  MKE:[{cnt_mke_nodes}]   MCR:[{cnt_mcr_nodes}]   MSR:[{cnt_msr_nodes}]   vCPU:[{cnt_vcpus}]\n", flush=True)

        if skipped_nodes:
            print(f"Skipped Nodes: [{skipped_nodes}] — run with --debug 1 for details\n", flush=True)

        print(f"Unique OS kernels discovered [{len(kernels_of_nodes)}]\n{format(kernels_of_nodes)}\n---------------------------------------------------", flush=True)
    else:
        debug_print(1, debug_level, f"[info] Node Counts: TOTAL:[{total_nodes}] MKE:[{cnt_mke_nodes}] MCR:[{cnt_mcr_nodes}] MSR:[{cnt_msr_nodes}] vCPU:[{cnt_vcpus}]")
        if skipped_nodes:
            debug_print(1, debug_level, f"[warn] Skipped Nodes: [{skipped_nodes}]")
        debug_print(2, debug_level, f"[info] Unique OS kernels discovered [{len(kernels_of_nodes)}] {format(kernels_of_nodes)}")

#------------------------------------------------------------
# Purpose:
#   Future JSON renderer. Present as a v1.23 seam only; no CLI
#   option calls this yet.
#------------------------------------------------------------
def render_json(result: NodeRowsResult, opts: Options) -> None:
    """
    Render collected node rows as structured JSON.

    JSON output is intentionally based on the same collected rows used by
    render_table(), so parser behavior remains unchanged.
    """
    row_objects = []
    for row in result.rows:
        row_objects.append({
            str(header): ("" if value is None else str(value).strip())
            for header, value in zip(result.header_cols, row)
        })

    payload = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "output_format": "json",
        "output_mode": opts.output_mode,
        "bundle_mode": result.bundle_mode,
        "schema": result.header_cols,
        "rows": row_objects,
        "stats": result.stats,
    }

    json_text = json.dumps(payload, indent=2, sort_keys=False)

    print(json_text, flush=True)

    if opts.filesave:
        with open(opts.outputfile, "w", encoding="utf-8") as outfile:
            outfile.write(json_text + "\n")

#------------------------------------------------------------
# Purpose:
#   Process every discovered node through the new collection seam,
#   then render using the existing table/CSV behavior.
#------------------------------------------------------------
def process_nodes(sd: list, opts: Options, bundle_mode: str):
    result = collect_node_rows(sd, opts, bundle_mode)

    if opts.output_format == "json":
        render_json(result, opts)
    else:
        render_table(result, opts)

#------------------------------------------------------------
# Purpose:
#   Normalize a date/time string into DD/MM/YYYY, hh:mm form,
#   defaulting the time to 00:00 when missing or invalid.
#
# Returns:
#   Normalized timestamp string.
#------------------------------------------------------------
def normalize_timestamp(ts: str) -> str:
    """
    Ensure ts is in the form 'DD/MM/YYYY, hh:mm'.
    If no ', hh:mm' is present or time is invalid, append/fix to '00:00'.
    """
    parts = ts.split(",", 1)
    date_part = parts[0].strip()

    # see if there's a time fragment
    if len(parts) == 2:
        time_candidate = parts[1].strip()
        if re.fullmatch(r"\d{2}:\d{2}", time_candidate):
            return f"{date_part}, {time_candidate}"
        else:
            print(f"Warning: time '{time_candidate}' is invalid, defaulting to '00:00'")
    # if we fell through (no time or bad time)…
    return f"{date_part}, 00:00"

#------------------------------------------------------------
# Purpose:
#   Validate that a string is a real calendar date in DD/MM/YYYY
#   format.
#
# Returns:
#   True when valid, otherwise False.
#------------------------------------------------------------
def validate_date(date_str: str) -> bool:
    """Return True if date_str is a valid calendar date in DD/MM/YYYY."""
    if not re.fullmatch(r"\d{2}/\d{2}/\d{4}", date_str):
        print("❌ Error: Date must be in DD/MM/YYYY format (e.g. 07/03/2025).")
        return False

    day_s, mon_s, yr_s = date_str.split("/")
    day, mon, yr = int(day_s), int(mon_s), int(yr_s)

    if not (1 <= day <= 31):
        print(f"❌ Error: Day '{day_s}' is out of range (01–31).")
        return False
    if not (1 <= mon <= 12):
        print(f"❌ Error: Month '{mon_s}' is out of range (01–12).")
        return False

    try:
        datetime(yr, mon, day)
    except ValueError as e:
        print(f"❌ Error: Invalid calendar date: {e}")
        return False

    return True

#------------------------------------------------------------
# Purpose:
#   Normalize a timestamp and validate the DD/MM/YYYY date
#   portion.
#
# Returns:
#   True when the date portion is valid, otherwise False.
#------------------------------------------------------------
def validate_timestamp(ts: str) -> bool:
    """
    Normalize ts → 'DD/MM/YYYY, hh:mm', then validate the date portion.
    """
    norm = normalize_timestamp(ts)
    date_part = norm.split(",", 1)[0].strip()
    return validate_date(date_part)

#------------------------------------------------------------
# Purpose:
#   Validate that a string is a real calendar date in DD/MM/YYYY
#   format.
#
# Returns:
#   True when valid, otherwise False.
#------------------------------------------------------------
def validate_ddmmyyyy(date_str: str) -> bool:
    """
    Return True if date_str (DD/MM/YYYY) is valid.
    """
    if not re.fullmatch(r"\d{2}/\d{2}/\d{4}", date_str):
        print("❌ Error: Date must be DD/MM/YYYY.")
        return False

    day, mon, yr = map(int, date_str.split("/"))
    if not (1 <= day <= 31):
        print(f"❌ Error: Day {day:02d} out of range.")
        return False
    if not (1 <= mon <= 12):
        print(f"❌ Error: Month {mon:02d} out of range.")
        return False

    try:
        datetime(yr, mon, day)
    except ValueError as e:
        print(f"❌ Error: Invalid date: {e}")
        return False

    return True

#------------------------------------------------------------
# Purpose:
#   Ensure a date string includes a valid HH:MM time, appending
#   or replacing the time with 00:00 when needed.
#
# Returns:
#   Timestamp string with a valid time component.
#------------------------------------------------------------
def ensure_timestamp(ts: str) -> str:
    """
    Ensure ts contains a time.  
    - If there is no comma/time, append ', 00:00'.  
    - If there *is* a comma but the hh:mm is malformed, overwrite with ', 00:00'.  
    Returns the normalized string.
    """
    if "," not in ts:
        return f"{ts.strip()}, 00:00"

    date_part, time_part = ts.split(",", 1)
    time_part = time_part.strip()

    # valid time is exactly HH:MM
    if re.fullmatch(r"[0-2]\d:[0-5]\d", time_part):
        return f"{date_part.strip()}, {time_part}"
    else:
        # malformed time
        return f"{date_part.strip()}, 00:00"

#------------------------------------------------------------
# Purpose:
#   Normalize a timestamp and raise an error if the date portion
#   is not valid.
#
# Returns:
#   Normalized timestamp string.
#
# Raises:
#   ValueError when the date portion is invalid.
#------------------------------------------------------------
def normalize_and_validate(ts: str) -> str:
    """
    Normalize ts to include time and validate the date portion.
    Returns the normalized timestamp on success, or raises ValueError.
    """
    
    normalized = ensure_timestamp(ts)
    
    date_part = normalized.split(",", 1)[0].strip()

    if not validate_ddmmyyyy(date_part):
        raise ValueError(f"❌ Invalid date portion: '{date_part}'")

    return normalized

#------------------------------------------------------------
# Purpose:
#   Convert a SIGTERM signal into KeyboardInterrupt so the normal
#   interrupt handling path can be reused.
#------------------------------------------------------------
def _handle_sigterm(signum, frame):
    raise KeyboardInterrupt

#------------------------------------------------------------
# Purpose:
#   Print a clean interruption message and return the standard
#   interrupted exit code.
#
# Returns:
#   130.
#------------------------------------------------------------
def _handle_top_level_interrupt() -> int:
    print("\n[sdnodes] interrupted — exiting gracefully")
    return 130

#------------------------------------------------------------
# Purpose:
#   Parse command-line options, detect and load the support bundle,
#   invoke node processing and return the correct process exit code.
#
# Returns:
#   0 for successful output, 2 for invalid/unsupported bundles,
#   or 130 when interrupted.
#------------------------------------------------------------
def cli_main() -> int:
    # Set up argument parser
    parser = argparse.ArgumentParser(description="{TOOL_NAME} Version: {VERSION}  Command line input enabled with:")
    parser.add_argument("--pretty", type=int, choices=[0, 1], default=1, help="Set pretty level: 1=On (Default: no delimiters) 0=Off(Use a semicolon (;) as delimiter to enable import to spreadsheet)")
    parser.add_argument("--outputfile", type=str, default=None, help="Output file name/path. Default: nodes_output.csv for table output, nodes_output.json for JSON output. Can include a full path for placement; directory must already exist.")
    parser.add_argument("--filesave", type=int, choices=[0,1], default=0, help="Turn on saving to output file. Default=0 disabled. If enabled see --outputfile")
    parser.add_argument("--accountname", type=str, default='<undefined account name>', help="Used to supply an Account Name if desired. Default = <undefined account name>. If using spaces in the Account Name be sure to enclose them in double quotes ")
    parser.add_argument("--ticketnumber", type=str, default='00000000', help="Used if you want to show output associated specifically with a ticket number. Default = 00000000" )
    parser.add_argument("--bundlepath", type=str, default='.', help="Path to where support bundle resides. Default = .  ")
    parser.add_argument("--bundlefile", type=str, default="", help="Path to where compressed (e.g. zip..) support bundle resides. Default = .  ")
    parser.add_argument("--bundledate", type=str, default=None, help="Simple date of support bundle. Format: dd/mm/YYYY   Default=today")
    parser.add_argument("--bundlecreatedate", type=str, default='', help="Extended date of support bundle. Any string, preferred style: 2025-07-21T06:51:40.000Z  Default = '' ")
    parser.add_argument("--debug", type=int, choices=[0,1,2,3,4], default=0, help="Debug level: 0=off (default) up to 4=very verbose")
    parser.add_argument("--extended-output", type=int, choices=[0, 1, 2, 3, 4], default=1, help="Extended output level: 0=baseline (default) up to 4=most detailed, for now if >= 1 then displays hardware info")
    parser.add_argument("--output-mode", choices=["engineer", "ticket"], default="engineer", help="Output mode: engineer=human terminal output with summary; ticket=clean semicolon-delimited ingestion output, useful for ingestion to such as Salesforce")
    parser.add_argument("--output-format", choices=["table", "json"], default="table", help="Output format: table=existing aligned/semicolon output; json=structured machine-readable JSON")

    args = parser.parse_args()

    #------------------------------------------------------------
    # Validate mutually exclusive input options.
    # If invalid error out exit with 2
    #------------------------------------------------------------
    if args.bundlefile and args.bundlepath != ".":
        parser.error( "Specify either --bundlepath or --bundlefile, not both." )

    # time.sleep(7) just a simple test to delay so I can test the multiapp functions within the console tab windows... 
    debug_level = args.debug
    output_mode = args.output_mode
    output_format = args.output_format
    ticket_mode = (output_mode == "ticket")
    json_format = (output_format == "json")

    extended_output = args.extended_output
    pretty = 0 if ticket_mode else args.pretty
    if pretty == 0 and not ticket_mode and not json_format:
        print("Pretty = False, using semicolon delimiter")

    outputFile = args.outputfile
    if outputFile is None:
        outputFile = "nodes_output.json" if json_format else "nodes_output.csv"

    file_save = args.filesave
    if file_save == 1 and not ticket_mode and not json_format:
        print(f"Saving output to: {outputFile}")
    elif file_save == 1 and json_format:
        debug_print(1, debug_level, f"[info] Saving JSON output to: {outputFile}")

    account_name = args.accountname
    if account_name != '<undefined account name>':
        account_name = f"{account_name:<9}" #pad it out with spaces to a minimum of 9 chars, will make pretty output lineup.
        if not ticket_mode and not json_format:
            print(f"Using AccountName: {account_name}")

    ticket_number = args.ticketnumber
    if ticket_number != '00000000':
        ticket_number = f"{ticket_number:<9}" #pad it out with spaces to be minimum of 9 chars, will make pretty output line up.
        if not ticket_mode and not json_format:
            print(f"Using Ticket Number: {ticket_number}")

    bundle_date = datetime.now().strftime("%d/%m/%Y")
    if args.bundledate is not None:
        bundle_date = args.bundledate
    elif args.bundlecreatedate != "":
        bundle_date = args.bundlecreatedate

    opts = Options(
        pretty=(pretty != 0),
        filesave=(file_save == 1),
        outputfile=outputFile,
        accountname=account_name,
        ticketnumber=ticket_number,
        bundlepath=args.bundlepath,
        bundlefile=args.bundlefile,
        bundledate=bundle_date,
        debug=debug_level,
        extended_output=extended_output,
        output_mode=output_mode,
        output_format=output_format,
    )

    try:
        if opts.bundlefile:
            with tempfile.TemporaryDirectory(prefix="sdnodesall-") as tmpdir:
                temp_root = Path(tmpdir)

                debug_print(
                    1,
                    debug_level,
                    f"[info] using temporary extraction directory: {temp_root}"
                )

                bundle_root = prepare_bundle_input(opts, temp_root)
                bundle_path = str(bundle_root)
                opts_for_run = replace(opts, bundlepath=bundle_path)

                bundle_file = bundle_root / ucp_nodes

                bundle_mode = detect_bundle_mode(bundle_path, debug_level)

                if bundle_mode == BUNDLE_MODE_CLUSTER:
                    sd = load_cluster_nodes(str(bundle_file), debug_level)
                elif bundle_mode == BUNDLE_MODE_SINGLE:
                    sd = load_single_node(bundle_path, debug_level)
                else:
                    if not ticket_mode:
                        print(f"❌ Unsupported or invalid support bundle: {bundle_root}", file=sys.stderr)
                        print("Expected either ucp-nodes.txt or dsinfo/dsinfo.json", file=sys.stderr)
                    return 2

                process_nodes(sd, opts_for_run, bundle_mode)
                return 0

        else:
            bundle_root = prepare_bundle_input(opts)
            bundle_path = str(bundle_root)
            opts_for_run = replace(opts, bundlepath=bundle_path)

            bundle_file = bundle_root / ucp_nodes

            if opts.bundlepath != "." and not ticket_mode:
                print(f"Using Bundle Path: {bundle_root}")

            bundle_mode = detect_bundle_mode(bundle_path, debug_level)

            if bundle_mode == BUNDLE_MODE_CLUSTER:
                sd = load_cluster_nodes(str(bundle_file), debug_level)
            elif bundle_mode == BUNDLE_MODE_SINGLE:
                sd = load_single_node(bundle_path, debug_level)
            else:
                if not ticket_mode:
                    print(f"❌ Unsupported or invalid support bundle: {bundle_root}", file=sys.stderr)
                    print("Expected either ucp-nodes.txt or dsinfo/dsinfo.json", file=sys.stderr)
                return 2

            process_nodes(sd, opts_for_run, bundle_mode)
            return 0

    except BundleLoadError as e:
        if not ticket_mode:
            print(f"❌ {e}", file=sys.stderr)
        return 2
    
    # stop duration timer
    #end_time = time.time()
    #elapsed_time = end_time - start_time
    #hours = int(elapsed_time // 3600)
    #minutes = int((elapsed_time % 3600) // 60)
    #seconds = int(elapsed_time % 60)
    #print(f"Elapsed Time: {hours} hours, {minutes} minutes, and {seconds} seconds")
    # print("⚠️  (warning sign)\n❗  (heavy exclamation)\n🚧  (construction)\n🔶  (large orange diamond)\n[!] (ASCII warning)\n(!) (ASCII warning)")



if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        raise SystemExit(cli_main())
    except KeyboardInterrupt:
        raise SystemExit(_handle_top_level_interrupt())
