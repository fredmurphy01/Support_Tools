# =================================================================
# Support_Tools
# =================================================================
This suite of tools is intended to be a single run/ execution to examine and analyse support bundles, sosreports, etcd behaviour, and search for patterns.

Strongly recommended; Python version 3.9 minimum

# =================================================================

1) sdnodes.py -- Display similar output as sdnodes but with enhancements and guardrails to prevent failures.

2) patterns_search.py -- Search all support bundle directories for patterns and display, similar in principle to sd_handle.

3) bundle_sanitize.py -- Take a cluster support bundle and sanitize with depths, removing all customer sensitive data and replacing with different values.

4) etcd_analysis -- Parses etcd-related artifacts from support bundles (multi-node mode) or a single etcd log (single-node mode), detects abnormal behavior, and produces duration- and storm-aware incident windows.

5) sos_triage -- Evaluates sosreports with a strong emphasis on Mirantis-related product issues and produces a structured, deterministic RCA view into events.


# ========================================================================================================================================
# ========================================================================================================================================
## SDNODES.PY
# 
# This tool is a carry over from much earlier versions with better guardrails and outputs.
# This tool currently only operates upon MKE3 cluster wide support bundles
# 
python3 tools/sdnodes.py -h
usage: sdnodes.py [-h] [--pretty {0,1}] [--outputfile OUTPUTFILE] [--filesave {0,1}] [--accountname ACCOUNTNAME] [--ticketnumber TICKETNUMBER] [--bundlepath BUNDLEPATH] [--bundledate BUNDLEDATE] [--bundlecreatedate BUNDLECREATEDATE]
                  [--debug {0,1,2,3,4}] [--extended-output {0,1,2,3,4}]

SDNODES Version: 1.14 Command line input enabled with:

options:
  -h, --help            show this help message and exit
  --pretty {0,1}        Set pretty level: 1=On (Default: no delimiters) 0=Off(Use a semicolon (;) as delimiter to enable import to spreadsheet)
  --outputfile OUTPUTFILE
                        Output file name (e.g., test.csv) -- (default = nodes_output.csv), can have a fully qualified path and filename for placement (directory MUST exist), else placed into pwd
  --filesave {0,1}      Turn on saving to output file. Default=0 disabled. If enabled see --outputfile
  --accountname ACCOUNTNAME
                        Used to supply an Account Name if desired. Default = <undefined account name>. If using spaces in the Account Name be sure to enclose them in double quotes
  --ticketnumber TICKETNUMBER
                        Used if you want to show output associated specifically with a ticket number. Default = 00000000
  --bundlepath BUNDLEPATH
                        Path to where support bundle resides. Default = .
  --bundledate BUNDLEDATE
                        Simple date of support bundle. Format: dd/mm/YYYY Default=today
  --bundlecreatedate BUNDLECREATEDATE
                        Extended date of support bundle. Any string, preferred style: 2025-07-21T06:51:40.000Z Default = ''
  --debug {0,1,2,3,4}   Debug level: 0=off (default) up to 4=very verbose
  --extended-output {0,1,2,3,4}
                        Extended output level: 0=baseline (default) up to 4=most detailed, for now if >= 1 then displays hardware info

# Example-1: Basic output (default is pretty)
python3 tools/sdnodes.py --bundlepath tickets/12345678/docker-support-20260303-19_51_11

# Example-2: Extended output showing hardware (default is pretty)
python3 tools/sdnodes.py --bundlepath tickets/12345678/docker-support-20260303-19_51_11 --extended-output 1

# Example-3: Output to console in csv style
python3 tools/sdnodes.py --bundlepath tickets/12345678/docker-support-20260303-19_51_11 --pretty 0

# Example-4: Output to a file (Typically used for output in csv format so the file can be imported to spreadsheet. Default file = nodes_output.csv)
python3 tools/sdnodes.py --bundlepath tickets/12345678/docker-support-20260303-19_51_11 --pretty 0 --filesave 1 --outputfile outputdir/nodes_output_file.csv

# Example-5: Add columns Accountname & Ticket number to console output first two columns. Particularly useful if saving output file for later use.
python3 tools/sdnodes.py --bundlepath tickets/12345678/docker-support-20260303-19_51_11 --accountname CORP-ABC --ticketnumber 12345678

# ========================================================================================================================================
# ========================================================================================================================================
## PATTERNS_SEARCH.PY
# 
# While this tool was intended to work initially on MKE3 support bundles, it will work on any support bundle, or directory for that matter.
# 
# By default this will create three (3) output files:
#  1 - report-patsrc.md
#  2 - support_bundle_ddmmmyyyy-hh-mm.json
#  3 - support_bundle_ddmmmyyyy-hh-mm.txt
# 
# All output is delivered to the console (terminal) window with a heatmap of findings at the end.
#
python3 tools/patterns_search.py -h
usage: patterns_search.py [-h] -d DIRECTORY [--workers WORKERS] [-o OUTPUT] [--verbose] [--sdnodes-path SDNODES_PATH] [--patterns PATTERNS] [--date DATE] [--date-window-days DATE_WINDOW_DAYS]

PATTERNS_SEARCH: Version 1.12 Fast multi-pattern search across a support bundle.

options:
  -h, --help            show this help message and exit
  -d, --directory DIRECTORY
                        Root directory to scan
  -o, --output OUTPUT   Output report file. Default: support_bundle_<date-time>.txt
  --verbose             Verbose console output (sdnodes live output + pattern scan output + progress). Default prints only report-patsrc.md.
  --sdnodes-path SDNODES_PATH
                        Optional full path to sdnodes.py. Default: tools/sdnodes.py (same directory as patterns_search.py).
  --patterns PATTERNS   Optional path to a directory containing patterns.txt (or a direct .txt file). If missing, built-in PATTERNS are used.
  --date DATE           Optional date filter (YYYY-MM-DD). If set, only matching lines containing this date/window are counted/output.
  --date-window-days DATE_WINDOW_DAYS
                        Optional +/- day window around --date (e.g., 2 means match date-2 through date+2). Default: 0.

# Example-1: Performs a pattern scan using built-in patterns of a specific bundle directory (can be cluster wide or single node)
python3 tools/patterns_search.py --directory tickets/12345678/docker-support-20260303-19_51_11

# Example-2: Verbose pattern search to console window (Shows sdnodes output first then performs scanning)
python3 tools/patterns_search.py --directory tickets/12345678/docker-support-20260303-19_51_11 --verbose

# Example-3: Perform a pattern search using external file of search items (extension of .txt is to be used, the filename can be other than default in github "patterns.txt" which is in the tools-signatures directory)
python3 tools/patterns_search.py --directory tickets/12345678/docker-support-20260303-19_51_11 --verbose --patterns tools/tool-signatures/patterns.txt

# Example-4: Perform a pattern search within a specific date and within +/- days around
python3 tools/patterns_search.py --directory tickets/12345678/docker-support-20260303-19_51_11 --date 2026-06-01 --date-window-days 2

# ========================================================================================================================================
# ========================================================================================================================================
## BUNDLE_SANITIZE.PY
# 
# This tool is to sanitize an MKE3 cluster wide support bundle. It will remove sensitive customer information such as but not limited to:
#          * IP Addresses
#          * Hostnames (unique short hostnames, complex hostnames)
#          * SHA values
#          * Cluster ID's
#          * Node ID's
#          * Email addresses
#          * Container ID's
#          * Cluster short ID's
#          * MAC addresses
#          * Node names
# 
# By default this will create:
#  1 - Sanitized bundle directory
#  2 - What was changed:
#    2a - sanitize_changed_details.json
#    2a - sanitize_changed_details.txt
# 
#  3 - What files were changed:
#    3a - sanitize_changed_files.json
#    3a - sanitize_changed_files.txt
# 
#  4 - Report outputs:
#    4a - sanitize_report.html
#    4a - sanitize_report.json
#    4c - sanitize_report.md
# 
#  5 - Json Mapping file of what maps to what from original to sanitized: Created with "--mapping" argv
#    5a - sanitize_mapping.json
#
#  6 - SDNODE Before Sanitize and After Sanitize:
#    6a - nodes_output.csv
#    6a - sanitized_node_info.csv
# 
# 
python3 tools/bundle_sanitize.py -h
usage: bundle_sanitize.py [-h] --bundle BUNDLE --outdir OUTDIR [--mapping] [--workers WORKERS]
Unified bundle sanitizer v9.7
options:
  -h, --help         show this help message and exit
  --bundle BUNDLE    Extracted bundle directory to sanitize
  --outdir OUTDIR    Output directory for artifacts and sanitized bundle
  --mapping          Write sanitize_mapping.json
# 
# Example-1: Sanitize the bundle "tickets/12345678/docker-support-20260303-19_51_11", create additional json mapping file, and place sanitized bundle into "tickets/12345678" which will be called "docker-support-20260303-19_51_11-sanitized"
python3 tools/bundle_sanitize.py --bundle tickets/12345678/docker-support-20260303-19_51_11 --mapping --outdir tickets/12345678
# 
# ========================================================================================================================================
# ========================================================================================================================================
## ETCD_ANALYSIS
# 
# Parse etcd logs and related signals (JSON-per-line and/or plain text), classify lines into event types, extract timestamps + durations, assign duration-aware + storm-aware severity.
# 
# A) Detect bursts/storms (many events of same kind in a small window) and surface them as explicit "storm" events.
# B) Collapse correlated events into a concise incident narrative per window.
#
# C) This groups into an >>Incident<< a contiguous period of abnormal etcd behaviour -
#     A time window where the system is >>meaningfully degraded<< not just noisy.
#
# D) An Incident Window is a group of detected etcd events that occur close enough in
#     time to be considered part of the same underlying degradation episode.
#     Meaning, it is essentially a gap-based clustering of events.
#     If the time gap between consecutive events exceeds a threshold then start a new incident otherwise its the same incident.
#     So, essentially, an incident is fundamentally a time-bounded degradation episode.
#     Each Incident answers:
#        "Something was wrong during this period"
#        "Multiple symptoms appeared together"
#        "This was not just one-off noise"
#    That's why an Incident Window includes:
#        time range
#        severity rollup
#        event counts
#        storm detection
#        a narrative summary
#
#    What an Incident is not
#    ❌ Not a root cause
#    ❌ Not a single failure
#    ❌ Not guaranteed to be unique (you can have many incidents with similar patterns)
#    An Incident is observational, not explanatory. 
# 
# 
# This etcd_analysis makes use of a signature file to allow for expansion.
# The file is called "etcd-signatures.yaml" located in the tool-signatures directory by default.
#   By having a signature file we can add more content to the overall analysis rather than making code changes.
# 
# By default this will create the following output files:
#  1 - etcd_analysis_report.md
#  2 - etcd_analysis.json
#  3 - A csv file for each leader found, e.g.
#    3a - managerhost01_ucp-kv.log.events.csv
# 
# -------------------------------------------
# - What is PYTHONPATH doing?
#   - Telling Python to treat the tools/ directory as a top-level module search path.
#   - Without this Python would not know where to find the "tools/sos_triage"
#   - We are saying here: The package root lives inside /tools
# 
# - What does the -m mean?
#   - This is very important and tells python to run a module as a script, which effectively is this entire package sos_triage.
# -------------------------------------------
# 
# Example-1: Analyze bundle using typical etcd-signatures.yaml file with outputs going to tickets/12345678, which happens to be where the support bundle is located
PYTHONPATH=tools python3 -m etcd_analysis analyze --bundle-path tickets/12345678/docker-support-20260303-19_51_11 --config tools/tool-signatures/etcd-signatures.yaml --output-dir tickets/123456787
# 
# Example-2: Same as Example 1 but with a specific date (YYYY-MM-DD) and a +/- of two (2) days to analyze
PYTHONPATH=tools python3 -m etcd_analysis analyze --bundle-path tickets/12345678/docker-support-20260303-19_51_11 --config tools/tool-signatures/etcd-signatures.yaml --output-dir tickets/123456787 --date 2026-06-01 --days 2
# 
# Example-3: Interactive mode to query individual leader nodes for individual analysis
#            Useful to query individual leaders and their data.
PYTHONPATH=tools python3 -m etcd_analysis analyze --bundle-path tickets/12345678/docker-support-20260303-19_51_11 --config tools/tool-signatures/etcd-signatures.yaml --output-dir tickets/123456787 --interactive
# 
# Example-4: Same as Example 1 but with a specific date (YYYY-MM-DD) and a +/- of two (2) days to analyze looking for a specific time and a timeframe around that time.
#               --time: Filter events to a point-in-time window centered on the given minute (format: YYYY-MM-DDThh:mm). Example: --time=2026-01-28T06:20
#               --time-window Time window half-width in hours when used with --time. The effective range is ±hours around --time. 0 means only that minute.
PYTHONPATH=tools python3 -m etcd_analysis analyze --bundle-path tickets/12345678/docker-support-20260303-19_51_11 --config tools/tool-signatures/etcd-signatures.yaml --output-dir tickets/123456787 --date 2026-06-01 --days 2 --time=2026-01-28T06:20 --time-window 10
# 
# ========================================================================================================================================
# ========================================================================================================================================
## SOS_TRIAGE
# 
# 
# This sos_analysis makes use of a signature file to allow for expansion.
# The file is called "sos-signatures.yaml" located in the tool-signatures directory by default.
#   By having a signature file we can add more content to the overall analysis rather than making code changes.
# 
# There are different "profiles" with different intent of behaviour.
# PROFILE A: Quick Triage (most common). This is what a support engineer runs first. This will probably be 80–90% of runs.
# PROFILE B: Deep Analysis (default, no limits). Same tool, just no guardrails.
# PROFILE C: One-shot Forensics / Weird Bundle
# 
# 
## 1. Purpose
# 
# `sos_triage` evaluates sosreports for Mirantis-related product issues and produces a structured, deterministic RCA view into events.
# 
# The goal is to provide:
# 
# -   A single pane of glass (`report.md`) via definitions driven by `sos-signatures.yaml`
# -   Structured intermediate artifacts for reasoning
# -   Deterministic, configuration-driven analysis
# -   Reproducible execution metadata
# 
# `sos-signatures.yaml` is the brain of sos_triage, and is a single, versioned, configuration file that defines:
# - What we scan inside an extracted sosreport (include/exclude globs, limits, encoding)
# - What we consider “interesting” (signatures: regex patterns + metadata)
# - How we interpret patterns into higher-level conclusions (heuristics)
# - How we compress noisy bursts (context_grouping / clustering policy)
# - How we build the report timeline (timeline rules)
# 
# ------------------------------------------------------------------------
# You will see "cluster" referenced in the outputs.
# What a “cluster” Means in sos_triage:
# A cluster is a burst of semantically identical or near-identical events occurring close together in time.
# - It is NOT:
#   - a Kubernetes cluster
#   - a node group
#   - a distributed system concept
# 
# It is a temporal aggregation construct.
# Think:
#  - “This thing happened 137 times in 4 minutes.”
# Instead of emitting 137 lines into report.md, we collapse that into one summarized object.
# 
# So:
#   - CLUSTER: 137 x raft peer connection failures in 00:04:13
# This is about signal compression.
# 
# 
# -------------------------------------------
# - What is PYTHONPATH doing?
#   - Telling Python to treat the tools/ directory as a top-level module search path.
#   - Without this Python would not know where to find the "tools/sos_triage"
#   - We are saying here: The package root lives inside /tools
# 
# - What does the -m mean?
#   - This is very important and tells python to run a module as a script, which effectively is this entire package sos_triage.
# -------------------------------------------
# 
# 
## 2. Mental Model
# 
# sos_triage transforms raw logs into layered artifacts:
# 
#     Raw logs
#       ↓
#     events.jsonl   (atomic observations)
#       ↓
#     clusters.json  (temporal compression)
#       ↓
#     findings.json  (interpretive reasoning)
#       ↓
#     report.md      (human-readable narrative)
# 
# `meta.json` records execution conditions and scan limits.
# 
# ------------------------------------------------------------------------
# 
## 3. Architecture Summary
# 
# Core principle:
# 
# -   Scan everything
# -   Filter at event emission
# -   Cluster after filtering
# -   Derive findings from structured signal
# -   Render narrative from findings + timeline
# 
# CLI controls scope and limits.\
# YAML config defines logic.
# 
# ------------------------------------------------------------------------
# 
## 4. Output Artifacts
# 
# All outputs are written to `--outdir`.
# 
#   File            Purpose
#   --------------- --------------------------------------
#   events.jsonl    Atomic normalized observations
#   clusters.json   Burst compression of chatty patterns
#   findings.json   Heuristic conclusions with evidence
#   report.md       Human-readable RCA summary
#   meta.json       Execution ledger and scan conditions
# 
# ------------------------------------------------------------------------
# 
## 5. sos-signatures.yaml
# 
# Defines:
# 
# -   Signatures (event detection)
# -   Clustering rules
# -   Heuristics
# -   Timeline inclusion
# 
## 6. Operational Guidance
# 
# When reviewing output:
# 
# 1.  Read report.md
# 2.  Review findings.json for reasoning detail
# 3.  Inspect clusters.json for burst patterns
# 4.  Trace to events.jsonl if deeper context required
# 5.  Always check meta.json for limits and severity filtering
# 
# Example-1: 
PYTHONPATH=tools python3 -m sos_triage analyze tickets/12345678/sosreport-sl73fbrapq106-2026-03-05-uileqsh.tar.xz --extract-mode journal --max-bytes 8000000 --max-events 2000 --verbose --outdir tickets/12345678/sosanalysis --extract-mode journal --configs-dir tools/tool-signatures --cleanup-extracted

# If you want to KEEP the extracted sosreport remove the argument to the command line below:
--cleanup-extracted

