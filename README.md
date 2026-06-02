# Support Tools

A collection of support-engineering utilities for analyzing support bundles, sosreports, ETCD behavior, and cluster-wide operational issues.

**Recommended Python Version:** 3.9+

---

## Available Tools

| Tool                 | Purpose                                                       |
| -------------------- | ------------------------------------------------------------- |
| `sdnodes.py`         | Cluster node inventory, validation, and hardware reporting    |
| `patterns_search.py` | Multi-pattern scanning across support bundles                 |
| `bundle_sanitize.py` | Sanitizes customer-sensitive information from support bundles |
| `etcd_analysis`      | Detects abnormal ETCD behavior and builds incident narratives |
| `sos_triage`         | Deterministic sosreport analysis with structured RCA outputs  |

---

# SDNODES.PY

Displays baseline cluster information from an MKE3 cluster-wide support bundle with additional validation, guardrails, and reporting enhancements.

| CLUSTER-ID | HOSTNAME | NODE-ID | ROLE | TYPE | MCRv | MKEv | MSRv | SWARM? | KUBE? | OS | OSver | ARCH | HYPERV | CPUs | RAM | GPU | UPTIME | AVAIL | STATE | IP/MASK | COLLECT | CREATED | UPDATED | STATUS_MESSAGE | BUNDLEDATE |

> Note: This tool currently operates on MKE3 cluster-wide support bundles.

<details>
<summary>SDNODES Examples</summary>

### Example-1: Basic output (default is pretty)
```bash
python3 tools/sdnodes.py \
    --bundlepath tickets/12345678/docker-support-20260303-19_51_11
```

### Example-2: Extended output showing hardware (default is pretty)
```bash
python3 tools/sdnodes.py \
    --bundlepath tickets/12345678/docker-support-20260303-19_51_11 \
    --extended-output 1
```
### Example-3: Output to console in csv style
```bash
python3 tools/sdnodes.py \
    --bundlepath tickets/12345678/docker-support-20260303-19_51_11 \
    --pretty 0
```

### Example-4: Output to a file (Typically used for output in csv format so the file can be imported to spreadsheet. Default file = nodes_output.csv)
```bash
python3 tools/sdnodes.py --bundlepath \
    tickets/12345678/docker-support-20260303-19_51_11 \
    --pretty 0 \
    --filesave 1 \
    --outputfile outputdir/nodes_output_file.csv
```

### Example-5: Add columns Accountname & Ticket number to console output first two columns. Particularly useful if saving output file for later use.
```bash
python3 tools/sdnodes.py \
    --bundlepath tickets/12345678/docker-support-20260303-19_51_11 \
    --accountname CORP-ABC \
    --ticketnumber 12345678
```
</details>

<details>
<summary>SDNODES Command Help</summary>

```text
python3 tools/sdnodes.py -h

usage: sdnodes.py [-h] [--pretty {0,1}] [--outputfile OUTPUTFILE]
                  [--filesave {0,1}]
                  ...

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
  --extended-output {0,1}
                        Extended output level: 0=baseline (default) up to 4=most detailed, for now if >= 1 then displays hardware info

```
</details>

---

# PATTERNS_SEARCH.PY

Searches support bundles for known patterns and produces summarized reports.
While this tool was intended to work initially on MKE3 support bundles, it will work on any support bundle, or directory for that matter.
Output is delivered to the console window and output files (see below) with a heatmap of findings at the end.

## Output Artifacts

By default the tool creates:

* report-patsrc.md
* support_bundle_ddmmmyyyy-hh-mm.json
* support_bundle_ddmmmyyyy-hh-mm.txt

<details>
<summary>PATTERNS_SEARCH Examples</summary>

### Example-1: Performs a pattern scan using built-in patterns of a specific bundle directory (can be cluster wide or single node)
```bash
python3 tools/patterns_search.py \
    --directory tickets/12345678/docker-support-20260303-19_51_11
```

### Example-2: Verbose pattern search to console window (Shows sdnodes output first then performs scanning)
```bash
python3 tools/patterns_search.py \
    --directory tickets/12345678/docker-support-20260303-19_51_11 \
    --verbose
```

### Example-3: Perform a pattern search using external file of search items (extension of .txt is to be used, the filename can be other than default in github "patterns.txt" which is in the tools-signatures directory)
```bash
python3 tools/patterns_search.py \
    --directory tickets/12345678/docker-support-20260303-19_51_11 \
    --verbose \
    --patterns tools/tool-signatures/patterns.txt
```

### Example-4: Perform a pattern search within a specific date and within +/- days around
```bash
python3 tools/patterns_search.py \
    --directory tickets/12345678/docker-support-20260303-19_51_11 \
    --date 2026-06-01 \
    --date-window-days 2
```
</details>


<details>
<summary>PATTERNS_SEARCH Command Help</summary>

```text
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
```
</details>

<details>
<summary>PATTERNS_SEARCH default built-in</summary>
```text
left gossip cluster
"healthscore:[2-9] \(connectivity issues\)"
with result "error:context canceled" took too long
unsynchronized systime with swarm
the clock difference against peer .* is too high
has prevented the request from succeeding \(get secrets\)
level.*error.* Cannot connect to the Docker daemon at tcp:
Error from leadership election follower
Cluster leadership lost
"heartbeat to manager .* failed"
dispatcher is stopped
cni config uninitialized
level=error msg="periodic bulk sync failure for network
": rejected connection from .* tcp "
"memberlist: Failed fallback ping: read tcp .* read: connection reset by peer"
"memberlist: Marking .* as failed, suspect timeout reached"
but other probes failed, network may be misconfigured
Some RethinkDB data on this server has been placed into swap
is in state down: heartbeat failure for node in
is in state down: Unhealthy UCP manager: ERROR: RethinkDB Health check timed out
is in state down: Awaiting healthy status in classic node inventory - current status: Unhealthy
etcd cluster is unavailable or misconfigured
martian source
Failed to execute iptables-[rs].* segmentation fault
Failed to create existing container
failed to allocate network IP for task
Failed to allocate address: Invalid address space
Failed to delegate: Failed to allocate address: No available addresses
"fatal task error" error="starting container failed: Address already in use"
deleteServiceInfoFromCluster NetworkDB DeleteEntry failed for
Failed to start certificate controller: error reading CA cert file
Failed to load config file
failed to re-resolve dtr-rethinkdb-
unable to query [dD][bB]: rethinkdb
unable to create event in database: rethinkdb: Cannot perform write:
unable to create job: unable to insert job into db: rethinkdb: Cannot perform write:
RethinkDB Health check timed out
failed to complete security handshake from
Err :connection error: desc = "transport: authentication handshake failed: read tcp
"http: TLS handshake error from .* tls: client didn't provide a certificate"
"tls: failed to verify client's certificate: x509: certificate has expired or is not yet valid"
level=error .* x509: certificate signed by unknown authority
error.* x509: certificate has expired or is not yet valid: current time
: rejected connection from .* tls: .* certificate", ServerName
: rejected connection from .* tls: .* certificate: x509: certificate has
: rejected connection from .* "tls: .* does not match any of DNSNames
"OOMKilled":true
invoked oom-killer
[Cc]onnection refused
HTTP error: Unable to reach primary cluster manager
nfs: server  not responding, still trying
:53: no such host
port .* is already in use
bind: address already in use
No installed keys could decrypt the message
[Nn]o space left on device
cannot allocate memory
error detaching from network .*: could not find network attachment for container .* to network
FieldPath:"spec.containers{calico-node}"}, Reason:"Unhealthy", Message:"Liveness probe failed:
FieldPath:"spec.containers{calico-node}"}, Reason:"Unhealthy", Message:"Readiness probe failed:
"Unable to route request"
"Legacy license failure"
level=error msg="agent: session failed" backoff=.* error="rpc error: code = Unavailable desc = all SubConns are in TransientFailure
"level":"fatal"
LOG_LEVEL=debug
OVERLAP on Network
iptables: Resource temporarily unavailable
unable to look up Node Feature Discovery
````
</details>
---

# BUNDLE_SANITIZE.PY

Sanitizes extracted MKE3 support bundles and replaces customer-sensitive data with generated values.

## Data Sanitized
It will remove sensitive customer information such as but not limited to:

* IP Addresses
* Hostnames
* SHA Values
* Cluster IDs
* Node IDs
* Email Addresses
* Container IDs
* MAC Addresses
* Node Names

## Generated Artifacts
By default this will create:
###  1 - Sanitized bundle directory
###  2 - What was changed:
####    2a - sanitize_changed_details.json
####    2a - sanitize_changed_details.txt

###  3 - What files were changed:
####    3a - sanitize_changed_files.json
####    3a - sanitize_changed_files.txt
 
###  4 - Report outputs:
####    4a - sanitize_report.html
####    4a - sanitize_report.json
####    4c - sanitize_report.md

###  5 - Json Mapping file of what maps to what from original to sanitized: Created with "--mapping" argv
####    5a - sanitize_mapping.json

###  6 - SDNODE Before Sanitize and After Sanitize:
####    6a - nodes_output.csv
####    6a - sanitized_node_info.csv
### Sanitized Content

<details>
<summary>BUNDLE_SANITIZE Command Help</summary>
```text
python3 tools/bundle_sanitize.py -h
usage: bundle_sanitize.py [-h] --bundle BUNDLE --outdir OUTDIR [--mapping] [--workers WORKERS]
Unified bundle sanitizer v9.7
options:
  -h, --help         show this help message and exit
  --bundle BUNDLE    Extracted bundle directory to sanitize
  --outdir OUTDIR    Output directory for artifacts and sanitized bundle
  --mapping          Write sanitize_mapping.json
```
</detail>

### Example-1: Sanitize the bundle "tickets/12345678/docker-support-20260303-19_51_11", create additional json mapping file, and place sanitized bundle into "tickets/12345678" which will be called "docker-support-20260303-19_51_11-sanitized"
```bash
python3 tools/bundle_sanitize.py \
    --bundle tickets/12345678/docker-support-20260303-19_51_11 \
    --mapping \
    --outdir tickets/12345678
```

---

# ETCD_ANALYSIS

Analyzes ETCD logs and related artifacts to identify abnormal behavior and construct incident narratives.
For example:
* Parse etcd logs and related signals (JSON-per-line and/or plain text)
* classify lines into event types
* extract timestamps + durations
* assign duration-aware + storm-aware severity

## Key Capabilities

* Detect event storms
* Correlate related events
* Build incident windows
* Generate severity-aware summaries
* Produce structured output artifacts

<detail>
<summary>Conceptual Model</summary>

### A) Detect bursts/storms (many events of same kind in a small window) and surface them as explicit "storm" events.
### B) Collapse correlated events into a concise incident narrative per window.
###
### C) This groups into an >>Incident<< a contiguous period of abnormal etcd behaviour -
###     A time window where the system is >>meaningfully degraded<< not just noisy.
###
### D) An Incident Window is a group of detected etcd events that occur close enough in
###     time to be considered part of the same underlying degradation episode.
###     Meaning, it is essentially a gap-based clustering of events.
###     If the time gap between consecutive events exceeds a threshold then start a new incident otherwise its the same incident.
###     So, essentially, an incident is fundamentally a time-bounded degradation episode.
###     Each Incident answers:
###        "Something was wrong during this period"
###        "Multiple symptoms appeared together"
###        "This was not just one-off noise"
###
###    That's why an Incident Window includes:
###        time range
###        severity rollup
###        event counts
###        storm detection
###        a narrative summary
###
###    What an Incident is not
####    ❌ Not a root cause
####    ❌ Not a single failure
####    ❌ Not guaranteed to be unique (you can have many incidents with similar patterns)
###    An Incident is observational, not explanatory. 
### 
### 
### This etcd_analysis makes use of a signature file to allow for expansion.
### The file is called "etcd-signatures.yaml" located in the tool-signatures directory by default.
####   By having a signature file we can add more content to the overall analysis rather than making code changes.
### 
## Generated Artifacts
###  1 - etcd_analysis_report.md
###  2 - etcd_analysis.json
###  3 - A csv file for each leader found, e.g.
####    3a - managerhost01_ucp-kv.log.events.csv
### 
###
### - What is PYTHONPATH doing?
####   - Telling Python to treat the tools/ directory as a top-level module search path.
####   - Without this Python would not know where to find the "tools/sos_triage"
####   - We are saying here: The package root lives inside /tools
### 
### - What does the -m mean?
####   - This is very important and tells python to run a module as a script, which effectively is this entire package sos_triage.
</detail>



## Quick Start

```bash
PYTHONPATH=tools python3 -m etcd_analysis analyze \
    --bundle-path tickets/12345678/docker-support-20260303-19_51_11 \
    --config tools/tool-signatures/etcd-signatures.yaml \
    --output-dir tickets/12345678
```

---

# SOS_TRIAGE

`sos_triage` evaluates sosreports for Mirantis-related product issues and produces a structured, deterministic RCA view into events.

It uses a signature file, `sos-signatures.yaml`, to make the analysis expandable without requiring code changes.

The signature file is located in `tools/tool-signatures` by default.

---

## Purpose

The goal of `sos_triage` is to provide:

* A single pane of glass report through `report.md`
* Structured intermediate artifacts for deeper reasoning
* Deterministic, configuration-driven analysis
* Reproducible execution metadata

`sos-signatures.yaml` is the primary configuration file for `sos_triage`.

It defines:
* Signatures (event detection)
* Clustering rules
* Heuristics
* Timeline inclusion

* What to scan inside an extracted sosreport
* What is considered interesting
* How matching events are interpreted
* How noisy bursts are compressed
* How the report timeline is built
* What we scan inside an extracted sosreport (include/exclude globs, limits, encoding)
* What we consider “interesting” (signatures: regex patterns + metadata)
* How we interpret patterns into higher-level conclusions (heuristics)
* How we compress noisy bursts (context_grouping / clustering policy)
* How we build the report timeline (timeline rules)


---

## Profiles

| Profile    | Name                | Intended Use                                                           |
| ---------- | ------------------- | ---------------------------------------------------------------------- |
| Profile A  | Quick Triage        | DEFAULT - Most common support-engineer workflow; likely 80–90% of runs |
| Profile B  | Deep Analysis       | JOURNAL - No guardrails or limits; used for deeper inspection          |
| Profile C  | One-shot Forensics  | FULL- Used for unusual, complex, or weird bundles                      |

---

## Mental Model

`sos_triage` transforms raw logs into layered analytical artifacts:

```text
Raw Logs
    ↓
events.jsonl   (atomic observations)
    ↓
clusters.json  (temporal compression)
    ↓
findings.json  (interpretive reasoning)
    ↓
report.md      (human-readable narrative)
```

`meta.json` records execution conditions and scan limits.

---

## Architecture Summary

Core principle:

* Scan everything
* Filter at event emission
* Cluster after filtering
* Derive findings from structured signal
* Render narrative from findings and timeline

The CLI controls scope and limits.

The YAML config defines analysis logic.

---

## What "Cluster" Means

In `sos_triage`, a cluster is a burst of semantically identical or near-identical events occurring close together in time.

It is **not**:

* A Kubernetes cluster
* A node group
* A distributed system concept

It is a temporal aggregation construct.

Think:

```text
This thing happened 137 times in 4 minutes.
```

Instead of emitting 137 lines into `report.md`, `sos_triage` collapses that repeated activity into one summarized object.

Example:

```text
CLUSTER: 137 x raft peer connection failures in 00:04:13
```

This is signal compression.

---

## Output Artifacts

All outputs are written to `--outdir`.

| File            | Purpose                              |
| --------------- | ------------------------------------ |
| `events.jsonl`  | Atomic normalized observations       |
| `clusters.json` | Burst compression of chatty patterns |
| `findings.json` | Heuristic conclusions with evidence  |
| `report.md`     | Human-readable RCA summary           |
| `meta.json`     | Execution ledger and scan conditions |

---

## Operational Guidance

When reviewing output:

1. Read `report.md`
2. Review `findings.json` for reasoning detail
3. Inspect `clusters.json` for burst patterns
4. Trace to `events.jsonl` if deeper context is required
5. Always check `meta.json` for limits and severity filtering

---

## Command Notes

### What `PYTHONPATH=tools` Does

`PYTHONPATH=tools` tells Python to treat the `tools/` directory as a top-level module search path.

Without this, Python may not know where to find the `tools/sos_triage` package.

### What `-m` Does

The `-m` flag tells Python to run a module as a script.

In this case, it runs the `sos_triage` package as the executable entry point.

---

## Quick Start

| Profile   | Name               | Intended Use                                                                 |
| --------- | ------------------ | ---------------------------------------------------------------------------- |
| Profile A | Quick Triage       | DEFAULT - Most common support-engineer workflow; likely 80–90% of runs       |
```bash
PYTHONPATH=tools python3 -m sos_triage analyze \
    tickets/12345678/sosreport-sl73fbrapq106-2026-03-05-uileqsh.tar.xz \
    --max-bytes 8000000 \
    --max-events 2000 \
    --verbose \
    --outdir tickets/12345678/sosanalysis \
    --configs-dir tools/tool-signatures \
    --cleanup-extracted
```

| Profile   | Name               | Intended Use                                                                 |
| --------- | ------------------ | ---------------------------------------------------------------------------- |
| Profile B | Deep Analysis      | --extract-mode JOURNAL - No guardrails or limits; used for deeper inspection |
```bash
PYTHONPATH=tools python3 -m sos_triage analyze \
    tickets/12345678/sosreport-sl73fbrapq106-2026-03-05-uileqsh.tar.xz \
    --extract-mode journal \
    --max-bytes 8000000 \
    --max-events 2000 \
    --verbose \
    --outdir tickets/12345678/sosanalysis \
    --configs-dir tools/tool-signatures \
    --cleanup-extracted
```

| Profile   | Name               | Intended Use                                                                 |
| --------- | ------------------ | ---------------------------------------------------------------------------- |
| Profile C | One-shot Forensics | --extract-mode FULL - Used for unusual, complex, or weird bundles            |
```bash
PYTHONPATH=tools python3 -m sos_triage analyze \
    tickets/12345678/sosreport-sl73fbrapq106-2026-03-05-uileqsh.tar.xz \
    --extract-mode full \
    --max-bytes 8000000 \
    --max-events 2000 \
    --verbose \
    --outdir tickets/12345678/sosanalysis \
    --configs-dir tools/tool-signatures \
    --cleanup-extracted
```

---

## Keeping the Extracted Sosreport

By default, the example above removes the extracted sosreport after analysis.

To keep the extracted sosreport, remove this argument:

```bash
--cleanup-extracted
```
