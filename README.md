<a id="top"></a>
# Support Tools

A collection of support-engineering utilities for analyzing support bundles, sosreports, ETCD behavior, and cluster-wide operational issues.

**Recommended Python Version:** 3.9+

---

## Available Tools

| Tool                 | Purpose                                                       |
| -------------------- | ------------------------------------------------------------- |
| [SDNODES.PY](#sdnodespy)         | StandAlone Tool: Cluster node inventory, validation, and hardware reporting |
| [PATTERNS_SEARCH.PY](#patterns_searchpy) | Multi-pattern scanning across support bundles |
| [BUNDLE_SANITIZE.PY](#bundle_sanitizepy) | Sanitizes customer-sensitive information from support bundles |
| [ETCD_ANALYSIS](#️etcd_analysis)      | Detects abnormal ETCD behavior and builds incident narratives |
| [SOS_TRIAGE](#sos_triage)         | Deterministic sosreport analysis with structured RCA outputs  |

## Standalone Tools:
> 1. sdnodes.py
> 2. bundle_sanitize.py
> 3. patterns_search.py
>> - Can use tool-signatures/patterns.txt

## Package-based Tools:
> 4. etcd_analyze.py <-- Launcher
>> - etcd_analysis/ <-- Package Implementation
>> - tools-signatures/etcd-signatures.yaml <-- etcd analysis patterns/signatures
> 5. sos_triage.py <-- Launcher
>> - sos_triage/ <-- Package Implementation
>> - tools-signatures/sos-signatures.yaml <-- sos analysis patterns/signatures


---
## 🖥️
## SDNODES.PY
---

Displays cluster information from an MKE3 cluster-wide support bundle with additional validation, guardrails, and reporting enhancements.
Purpose:
  Display node inventory and platform details from Docker / Mirantis support bundles, supporting:
>    - Cluster-wide support bundles (ucp-nodes.txt)
>    - Single-node support bundles (root-level dsinfo evidence)
>    - Compressed support bundle archives (.zip/.tgz/.tar.gz/.tar.xz)

  The tool is designed to operate as a standalone engineering utility with no external package dependencies, while also supporting structured output suitable for future Salesforce ingestion.

##  Primary audiences:
>    1. Engineers
>      - Human-readable terminal table
>      - Optional debug output
>      - Summary statistics
>
>    2. Ticket / Salesforce ingestion
>      - Clean semicolon-delimited output
>      - Optional JSON output
>      - No visual summary or console noise
## Major enhancements:

  Bundle support
  --------------
    1. Added support for both cluster-wide and single-node support bundles.
    2. Bundle detection now identifies:
>      - cluster bundles
>      - single-node bundles
>      - unsupported layouts
      with debug evidence describing the decision.
    3. Added support for compressed support bundle archives:
>        .zip
>        .tgz
>        .tar.gz
>        .tar.xz
>      including automatic secure extraction to a temporary directory.
    4. Archive extraction is hardened against path traversal (Zip Slip / Tar Slip) attacks.
    5. Output modes added:
>          engineer
>              Human-oriented table with summary information.
>          ticket
>              Clean ingestion output only.
    6. Output formats added:
>          table
>              Existing aligned / semicolon renderer.
>          json
>              Structured machine-readable output.

> Typical output includes cluster identifiers, node roles, engine versions, Kubernetes status, operating system details, hardware inventory, node health, and collection metadata.

<details>
<summary>Example Output</summary>

```text
CLUSTER-ID  HOSTNAME    NODE-ID     ROLE       TYPE    MCRv    MKEv    MSRv    SWARM?  KUBE?   OS      OSver                           ARCH    HYPERV  CPUs    RAM     GPU UPTIME  AVAIL   STATE   IP/MASK             COLLECT CREATED/UPDATED                             STATUS_MESSAGE      BUNDLEDATE
qzitmwnrwc  host5530U6  14qe3da13q  leader     MKE     23.0.9  3.8.7   -.-.--  swarm   kube    linux   Ubuntu-20.04.6/ Ubuntu 20.04.6  x86_64  VMware  16      31.31   ... 16:09   active  ready   10.151.194.85 / 28  /System 2024-04-26_02:27:13 / 2025-12-10_15:07:34   Healthy MKE manager 03/06/2026
qzitmwnrwc  host5531Q3  mu05shcfa9  manager    MKE     23.0.9  3.8.7   -.-.--  swarm   kube    linux   Ubuntu-20.04.6/ Ubuntu 20.04.6  x86_64  VMware  16      31.31   ... 1 day   active  ready   10.151.194.83 / 28  /System 2024-04-27_05:36:40 / 2025-12-10_15:07:24   Healthy MKE manager 03/06/2026
qzitmwnrwc  host553YAC  xermmuhoip  manager    MKE     23.0.9;3.8.7    -.-.--  swarm   kube    linux   Ubuntu-20.04.6/ Ubuntu 20.04.6  x86_64  VMware  12      31.31   ... 6:02    active  ready   10.151.194.84 / 28  /System 2024-04-26_02:39:47 / 2025-12-10_15:07:28   Healthy MKE manager 03/06/2026
qzitmwnrwc  host5533CO  t1j7ucm1id  worker     MCR     23.0.9;3.8.7    -.-.--  ------  kube    linux   Ubuntu-20.04.6/ Ubuntu 20.04.6  x86_64  VMware  16      31.31   ... 1 day   active  ready   10.151.204.134 / 27 /Shared 2024-04-26_06:05:13 / 2025-12-09_22:59:07   Healthy MKE worker  03/06/2026
qzitmwnrwc  host5539IU  in4v9k71lr  worker     MCR     23.0.9;3.8.7    -.-.--  ------  kube    linux   Ubuntu-20.04.6/ Ubuntu 20.04.6  x86_64  VMware  16      31.31   ... 1 day   active  ready   10.151.204.132 / 27 /Shared 2024-04-27_05:41:28 / 2025-12-09_22:59:02   Healthy MKE worker  03/06/2026
qzitmwnrwc  host553L9R  4q9v06f7yd  worker     MCR     23.0.9;3.8.7    -.-.--  ------  kube    linux   Ubuntu-20.04.6/ Ubuntu 20.04.6  x86_64  VMware  16      31.31   ... 6:54    active  ready   10.151.204.133 / 27 /Shared 2025-07-22_05:54:02 / 2025-12-10_08:14:10   Healthy MKE worker  03/06/2026
--------------------------------------------------------------------------
🔶🔶 SUMMARY INFORMATION 🔶🔶
Node Counts:  MKE:[3]   MCR:[3]   MSR:[0]   vCPU:[92]

Unique OS kernels discovered [2]
{'5.15.0-84-generic', '5.15.0-139-generic'}
---------------------------------------------------

```

</details>



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

python3 sdnodes.py --help
usage: sdnodes.py [-h] [--pretty {0,1}] [--outputfile OUTPUTFILE] [--filesave {0,1}] [--accountname ACCOUNTNAME] [--ticketnumber TICKETNUMBER] [--bundlepath BUNDLEPATH] [--bundlefile BUNDLEFILE] [--bundledate BUNDLEDATE]
                  [--bundlecreatedate BUNDLECREATEDATE] [--debug {0,1,2,3,4}] [--extended-output {0,1,2,3,4}] [--output-mode {engineer,ticket}] [--output-format {table,json}]

{TOOL_NAME} Version: {VERSION} Command line input enabled with:

options:
  -h, --help            show this help message and exit
  --pretty {0,1}        Set pretty level: 1=On (Default: no delimiters) 0=Off(Use a semicolon (;) as delimiter to enable import to spreadsheet)
  --outputfile OUTPUTFILE
                        Output file name/path. Default: nodes_output.csv for table output, nodes_output.json for JSON output. Can include a full path for placement; directory must already exist.
  --filesave {0,1}      Turn on saving to output file. Default=0 disabled. If enabled see --outputfile
  --accountname ACCOUNTNAME
                        Used to supply an Account Name if desired. Default = <undefined account name>. If using spaces in the Account Name be sure to enclose them in double quotes
  --ticketnumber TICKETNUMBER
                        Used if you want to show output associated specifically with a ticket number. Default = 00000000
  --bundlepath BUNDLEPATH
                        Path to where support bundle resides. Default = .
  --bundlefile BUNDLEFILE
                        Path to where compressed (e.g. zip..) support bundle resides. Default = .
  --bundledate BUNDLEDATE
                        Simple date of support bundle. Format: dd/mm/YYYY Default=today
  --bundlecreatedate BUNDLECREATEDATE
                        Extended date of support bundle. Any string, preferred style: 2025-07-21T06:51:40.000Z Default = ''
  --debug {0,1,2,3,4}   Debug level: 0=off (default) up to 4=very verbose
  --extended-output {0,1,2,3,4}
                        Extended output level: 0=baseline (default) up to 4=most detailed, for now if >= 1 then displays hardware info
  --output-mode {engineer,ticket}
                        Output mode: engineer=human terminal output with summary; ticket=clean semicolon-delimited ingestion output, useful for ingestion to such as Salesforce
  --output-format {table,json}
                        Output format: table=existing aligned/semicolon output; json=structured machine-readable JSON

```
</details>
---

[⬆ Back to Top](#top)

---
## 🔍
## PATTERNS_SEARCH.PY
---


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
```
</details>
---

[⬆ Back to Top](#top)

---
## ♻️
## BUNDLE_SANITIZE.PY 
---


Sanitizes extracted MKE3 support bundles and replaces customer-sensitive data with generated values.

## Data Sanitized
It will remove sensitive customer information such as but not limited to:

* IP Addresses
* Hostnames (unique short hostnames, complex hostnames)
* SHA Values
* Cluster IDs
* Node IDs
* Email Addresses
* Container IDs
* MAC Addresses
* Node Names

<details>
<summary>Generated Artifacts</summary>

```text
By default this will create:
1 - Sanitized bundle directory

2 - What was changed:
    2a - sanitize_changed_details.json
    2a - sanitize_changed_details.txt

3 - What files were changed:
    3a - sanitize_changed_files.json
    3a - sanitize_changed_files.txt
 
4 - Report outputs:
    4a - sanitize_report.html
    4a - sanitize_report.json
    4c - sanitize_report.md

5 - Json Mapping file of what maps to what from original to sanitized: Created with "--mapping" argv
    5a - sanitize_mapping.json

6 - SDNODE Before Sanitize and After Sanitize:
    6a - nodes_output.csv
    6a - sanitized_node_info.csv
```
</details>

<details>
<summary>BUNDLE_SANITIZE Examples</summary>

### Example-1: Sanitize the bundle "tickets/12345678/docker-support-20260303-19_51_11"
> Create additional json mapping file
> Place sanitized bundle into "tickets/12345678" which will be called "docker-support-20260303-19_51_11-sanitized"
```bash
python3 tools/bundle_sanitize.py \
    --bundle tickets/12345678/docker-support-20260303-19_51_11 \
    --mapping \
    --outdir tickets/12345678
```
</details>

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
</details>
---

[⬆ Back to Top](#top)

---
## ⚙️
## ETCD_ANALYSIS
---


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

<details>
<summary>Conceptual Model</summary>

```text
A) Detect bursts/storms (many events of same kind in a small window) and surface them as explicit "storm" events.

B) Collapse correlated events into a concise incident narrative per window.

C) This groups into an >>Incident<< a contiguous period of abnormal etcd behaviour -
    A time window where the system is >>meaningfully degraded<< not just noisy.

D) An Incident Window is a group of detected etcd events that occur close enough in
    time to be considered part of the same underlying degradation episode.
    Meaning, it is essentially a gap-based clustering of events.
    If the time gap between consecutive events exceeds a threshold then start a new incident otherwise its the same incident.
    So, essentially, an incident is fundamentally a time-bounded degradation episode.
    Each Incident answers:
        "Something was wrong during this period"
        "Multiple symptoms appeared together"
        "This was not just one-off noise"

    That's why an Incident Window includes:
        time range
        severity rollup
        event counts
        storm detection
        a narrative summary

    What an Incident is not
        ❌ Not a root cause
        ❌ Not a single failure
        ❌ Not guaranteed to be unique (you can have many incidents with similar patterns)
    An Incident is observational, not explanatory. 

This etcd_analysis makes use of a signature file to allow for expansion.
The file is called "etcd-signatures.yaml" located in the tool-signatures directory by default.
    By having a signature file we can add more content to the overall analysis rather than making code changes.

## Generated Artifacts
    1 - etcd_analysis_report.md
    2 - etcd_analysis.json
    3 - A csv file for each leader found, e.g.
        3a - managerhost01_ucp-kv.log.events.csv


- What is PYTHONPATH doing?
    - Telling Python to treat the tools/ directory as a top-level module search path.
    - Without this Python would not know where to find the "tools/sos_triage"
    - We are saying here: The package root lives inside /tools

    - What does the -m mean?
        - This is very important and tells python to run a module as a script, which effectively is this entire package sos_triage.
```
</details>

<details>
<summary>ETCD_ANALYZE Examples</summary>

### Example-1: Analyze bundle using typical etcd-signatures.yaml file with outputs going to tickets/12345678, which happens to be where the support bundle is located
```bash
PYTHONPATH=tools python3 -m etcd_analysis analyze \
    --bundle-path tickets/12345678/docker-support-20260303-19_51_11 \
    --config tools/tool-signatures/etcd-signatures.yaml \
    --output-dir tickets/123456787
```

### Example-2: Same as Example 1 but with a specific date (YYYY-MM-DD) and a +/- of two (2) days to analyze
```bash
PYTHONPATH=tools python3 -m etcd_analysis analyze \
    --bundle-path tickets/12345678/docker-support-20260303-19_51_11 \
    --config tools/tool-signatures/etcd-signatures.yaml \
    --output-dir tickets/123456787 \
    --date 2026-06-01 \
    --days 2
```

### Example-3: Interactive mode to query individual leader nodes for individual analysis (Useful to query individual leaders and their data)
```bash
PYTHONPATH=tools python3 -m etcd_analysis analyze \
    --bundle-path tickets/12345678/docker-support-20260303-19_51_11 \
    --config tools/tool-signatures/etcd-signatures.yaml \
    --output-dir tickets/123456787 \
    --interactive
```

### Example-4: Same as Example 1 but with a specific date (YYYY-MM-DD) and a +/- of two (2) days to analyze looking for a specific time and a timeframe around that time.
> **--time**
> Filter events to a point-in-time window centered on the given minute (format: YYYY-MM-DDThh:mm).
> Example: `--time=2026-01-28T06:20`
> **--time-window**
> Time window half-width in hours when used with `--time`.
> The effective range is ±hours around `--time`.
> `0` means only that minute.
```bash
PYTHONPATH=tools python3 -m etcd_analysis analyze \
    --bundle-path tickets/12345678/docker-support-20260303-19_51_11 \
    --config tools/tool-signatures/etcd-signatures.yaml \
    --output-dir tickets/123456787 \
    --date 2026-06-01 \
    --days 2 \
    --time=2026-01-28T06:20 \
    --time-window 10
```
</details>


### ETCD Signature File Content & Example

`etcd_analysis` uses a YAML signature file `etcd-signatures.yaml` to define detectable ETCD patterns and interpretation rules.

The default signature file is found:

[`tool-signatures/etcd-signatures.yaml`](tool-signatures/etcd-signatures.yaml)

<details>
<summary>Example signature structure</summary>

```yaml
################################################################################
# Formal mapping table: current etcd_analysis.py → YAML contract
# 
# ------------------------------+---------------------------------------------------------------------------------+---------------------------------------------------------------+----------------------
# Current Python area           |   Current symbol / logic                                                        |   YAML v2 destination                                         | Notes
# ------------------------------+---------------------------------------------------------------------------------+---------------------------------------------------------------+----------------------
# Raw etcd log signatures       | EVENT_PATTERNS                                                                  | signatures.events[].patterns	                                | direct migration
# Event kind name               | tuple first element in EVENT_PATTERNS                                           | signatures.events[].event_type                                | direct migration
# Base severity                 | BASE_SEVERITY                                                                   | signatures.events[].default_severity                          | direct migration
# Journal signal regexes        | _JOURNAL_SIGNAL_PATTERNS                                                        | journal_signatures.events[]                                   | direct migration
# Storm thresholds              | rules map inside detect_storms()                                                | storm_rules.rules[]                                           | direct migration
# Family classification         | _classify_incident_families() sets                                              | families.event_type_to_family                                 | direct migration
# Duration threshold buckets    | duration_aware_severity() numeric literals                                      | duration_policies.policies[].thresholds_ms                    | migrate values, keep math in Python
# Ratio boost thresholds        | duration_aware_severity() ratio literals                                        | duration_policies.ratio_boost                                 | move constants only
# Keyspace-sensitive thresholds | special /registry/health branch                                                 | duration_policies.keyspace_overrides[]                        | keep branch logic in Python
# Journal family bump map       | JOURNAL_TO_FAMILY inside _classify_incident_families()                          | families.event_type_to_family                                 | cleaner unified mapping
# Bundle source discovery       | scan_bundle(), find_ucp_kv_log(), find_journalctl_daemon_log() path assumptions | sources.bundle.roles.*                                        | Python still performs file lookup
# Node eligibility              | scan_bundle() (has_status or has_log)                                           | sources.bundle.analyzable_node_policy                         | move policy, keep enforcement in Python
# Narrative category hints      | ad hoc in window_narrative()                                                    | narrative.categories + signatures.events[].narrative_tags     | Python still assembles prose
# Higher-order interpretation   | currently mostly implicit in prose                                              | heuristics.rules[]                                            | new capability, additive
# Output schema stamps          | hard-coded JSON schema strings                                                  | outputs.schemas.*                                             | optional but useful
# Context defaults              | ad hoc / limited                                                                defaults.context                                                | mostly future-facing unless you add richer evidence excerpts
#
################################################################################




schema_version: etcd-signatures-v2
version: 1
name: etcd-signatures
description: >
  Detection contract for hybrid etcd incident analysis.

  YAML defines:
    - source discovery policy
    - raw event signatures
    - supplemental journal signatures
    - duration threshold policies
    - storm/burst rules
    - family classification rules
    - higher-order heuristic findings
    - narrative metadata

  Python remains responsible for:
    - timestamp parsing and normalization
    - duration extraction and unit conversion
    - etcd-status structured parsing
    - incident window clustering
    - cluster synthesis and topology reasoning
    - severity rollup math
    - report / CSV / JSON rendering

contract_notes:
  design_intent:
    - "YAML defines what to look for."
    - "Python decides what it means."
    - "Structured parsers remain code, not config."
  compatibility_goal:
    - "Initial bundled config should preserve current etcd_analysis.py behavior as closely as practical."

###############################################################################
# Validation / lint expectations
###############################################################################
validation:
  severity_enum: [critical, high, medium, low, info]
  source_role_enum:
    - ucp_kv_log
    - journalctl_daemon
    - etcd_status
    - dsinfo_txt

  required_top_level_sections:
    - defaults
    - sources
    - outputs
    - duration_policies
    - signatures
    - journal_signatures
    - storm_rules
    - families
    - heuristics
    - narrative

  uniqueness:
    signature_ids_must_be_unique: true
    journal_signature_ids_must_be_unique: true
    event_types_should_be_unique_within_section: true
    storm_rule_ids_must_be_unique: true
    heuristic_ids_must_be_unique: true

  references:
    duration_policy_must_exist_if_referenced: true
    heuristic_event_types_must_exist: true
    family_event_types_must_exist: true
    source_roles_must_be_valid: true

  regex:
    compile_patterns_at_load: true
    invalid_pattern_is_error: true

###############################################################################
# Defaults
###############################################################################
defaults:
  severities: [critical, high, medium, low, info]

  context:
    pre: 1
    post: 2
    max_line_length: 600
    trim_whitespace: true
    store_context_in_events_json: true
    store_context_in_findings: false

  excerpt:
    max_chars: 260

  ids:
    event:
      sequential_prefix: "evt_"
      sequential_width: 6
    incident:
      sequential_prefix: "inc_"
      sequential_width: 4

###############################################################################
# Source discovery
###############################################################################
sources:
  description: >
    Discovery policy for bundle-mode evidence collection.

  bundle:
    host_layout:
      dsinfo_dir_name: "dsinfo"

    roles:
      etcd_status:
        preferred_paths:
          - "dsinfo/etcd-status.txt"

      dsinfo_txt:
        preferred_paths:
          - "dsinfo/dsinfo.txt"

      ucp_kv_log:
        preferred_globs:
          - "dsinfo/logs/**/ucp-kv.log"
        selection_policy: newest_by_mtime

      journalctl_daemon:
        preferred_paths:
          - "dsinfo/journalctl_daemon.log"
        fallback_globs:
          - "dsinfo/logs/**/journalctl_daemon.log"
        selection_policy: newest_by_mtime

    analyzable_node_policy:
      require_one_of:
        - etcd_status
        - ucp_kv_log
      optional:
        - journalctl_daemon
        - dsinfo_txt
      notes:
        - "journalctl_daemon alone is supplemental and does not make a node analyzable."

###############################################################################
# Output schema stamps
###############################################################################
outputs:
  schemas:
    events_csv: "etcd-events-csv-v1"
    incidents_json: "etcd-incidents-json-v1"
    bundle_json: "etcd-bundle-json-v1"
    cluster_synthesis: "etcd-cluster-synthesis-v1"

###############################################################################
# Duration-aware severity policies
###############################################################################
duration_policies:
  description: >
    Numeric thresholds consumed by Python severity logic after duration extraction.

  ratio_boost:
    medium_gte: 3
    high_gte: 10
    critical_gte: 50

  keyspace_overrides:
    - key_prefix: "/registry/health"
      thresholds_ms:
        low: 100
        medium: 150
        high: 250
        critical: 500

  policies:
    slow_fdatasync:
      thresholds_ms:
        low: 200
        medium: 500
        high: 2000
        critical: 5000

    raft_heartbeat_miss:
      thresholds_ms:
        low: 50
        medium: 100
        high: 250
        critical: 1000

    apply_took_too_long:
      thresholds_ms:
        low: 100
        medium: 300
        high: 750
        critical: 1500

    linearizable_read_slow:
      thresholds_ms:
        low: 100
        medium: 300
        high: 750
        critical: 1500

    raft_read_agreement_slow:
      thresholds_ms:
        low: 100
        medium: 300
        high: 750
        critical: 1500

    rpc_request_stats:
      thresholds_ms:
        low: 100
        medium: 300
        high: 750
        critical: 1500

###############################################################################
# Primary etcd/server signatures (ucp-kv.log)
###############################################################################
signatures:
  description: >
    Raw event signatures matched against ucp-kv.log.

  events:
    - id: slow_fdatasync
      event_type: slow_fdatasync
      group: storage_timing
      default_severity: high
      confidence_weight: 0.95
      source_roles: [ucp_kv_log]
      patterns:
        - '"msg"\s*:\s*"slow fdatasync"'
        - 'slow fdatasync'
      narrative_tags: [storage_timing, possible_disk_stall]
      duration_policy: slow_fdatasync
      storm_eligible: true

    - id: readindex_retry
      event_type: readindex_retry
      group: read_path
      default_severity: medium
      confidence_weight: 0.90
      source_roles: [ucp_kv_log]
      patterns:
        - 'waiting for ReadIndex response took too long'
      narrative_tags: [read_path_pressure, quorum_read_delay]
      storm_eligible: true

    - id: linearizable_read_slow
      event_type: linearizable_read_slow
      group: read_path
      default_severity: medium
      confidence_weight: 0.90
      source_roles: [ucp_kv_log]
      patterns:
        - '"msg"\s*:\s*"trace\[.*\]\s+linearizableReadLoop"'
        - '\blinearizableReadLoop\b'
      narrative_tags: [read_path_pressure]
      duration_policy: linearizable_read_slow
      storm_eligible: true

    - id: raft_read_agreement_slow
      event_type: raft_read_agreement_slow
      group: read_path
      default_severity: medium
      confidence_weight: 0.90
      source_roles: [ucp_kv_log]
      patterns:
        - 'agreement among raft nodes before linearized reading'
      narrative_tags: [quorum_read_delay]
      duration_policy: raft_read_agreement_slow

    - id: raft_heartbeat_miss
      event_type: raft_heartbeat_miss
      group: raft_timing
      default_severity: high
      confidence_weight: 0.95
      source_roles: [ucp_kv_log]
      patterns:
        - 'leader failed to send out heartbeat on time'
      narrative_tags: [raft_timing, leader_delay]
      duration_policy: raft_heartbeat_miss
      storm_eligible: true

    - id: apply_took_too_long
      event_type: apply_took_too_long
      group: apply_path
      default_severity: medium
      confidence_weight: 0.95
      source_roles: [ucp_kv_log]
      patterns:
        - 'apply request took too long'
      narrative_tags: [apply_path_pressure]
      duration_policy: apply_took_too_long
      storm_eligible: true

    - id: raft_process_slow
      event_type: raft_process_slow
      group: apply_path_detail
      default_severity: low
      confidence_weight: 0.80
      source_roles: [ucp_kv_log]
      patterns:
        - "'process raft request'\\s*\\(duration:"
      narrative_tags: [apply_path_detail]

    - id: raft_compare_slow
      event_type: raft_compare_slow
      group: apply_path_detail
      default_severity: low
      confidence_weight: 0.75
      source_roles: [ucp_kv_log]
      patterns:
        - "'compare'\\s*\\(duration:"
      narrative_tags: [apply_path_detail]

    - id: inmemory_index_scan_slow
      event_type: inmemory_index_scan_slow
      group: apply_path_detail
      default_severity: low
      confidence_weight: 0.75
      source_roles: [ucp_kv_log]
      patterns:
        - 'range keys from in-memory index tree'
      narrative_tags: [index_scan_pressure]

    - id: applied_index_lag
      event_type: applied_index_lag
      group: correctness_risk
      default_severity: high
      confidence_weight: 0.95
      source_roles: [ucp_kv_log]
      patterns:
        - 'appliedIndex\s+is\s+now\s+lower\s+than\s+readState\.Index'
      narrative_tags: [correctness_risk, follower_or_apply_lag]
      storm_eligible: true

    - id: context_deadline
      event_type: context_deadline
      group: client_symptom
      default_severity: medium
      confidence_weight: 0.90
      source_roles: [ucp_kv_log]
      patterns:
        - 'context deadline exceeded'
      narrative_tags: [client_visible_timeout]
      storm_eligible: true

    - id: context_canceled
      event_type: context_canceled
      group: client_symptom
      default_severity: medium
      confidence_weight: 0.70
      source_roles: [ucp_kv_log]
      patterns:
        - 'context canceled'
      narrative_tags: [client_abort_or_timeout_followup]

    - id: grpc_transport_closing
      event_type: grpc_transport_closing
      group: transport
      default_severity: high
      confidence_weight: 0.80
      source_roles: [ucp_kv_log]
      patterns:
        - 'transport is closing'
      narrative_tags: [transport_churn]

    - id: peer_probe_unhealthy
      event_type: peer_probe_unhealthy
      group: peer_connectivity
      default_severity: critical
      confidence_weight: 0.95
      source_roles: [ucp_kv_log]
      patterns:
        - 'prober detected unhealthy status'
      narrative_tags: [peer_unhealthy, quorum_risk]

    - id: peer_connect_refused
      event_type: peer_connect_refused
      group: peer_connectivity
      default_severity: critical
      confidence_weight: 0.95
      source_roles: [ucp_kv_log]
      patterns:
        - 'connect:\s*connection refused'
      narrative_tags: [peer_unreachable, quorum_risk]

    - id: health_no_leader
      event_type: health_no_leader
      group: leadership
      default_severity: critical
      confidence_weight: 0.98
      source_roles: [ucp_kv_log]
      patterns:
        - 'serving\s+/health\s+false;\s+no leader'
        - 'RAFT NO LEADER'
        - '/health error'
      narrative_tags: [no_leader, availability_impact]

    - id: health_registry_read
      event_type: health_registry_read
      group: control_plane
      default_severity: low
      confidence_weight: 0.85
      source_roles: [ucp_kv_log]
      patterns:
        - 'key:"/registry/health"'
      narrative_tags: [control_plane_path, keyspace_sensitive]
      keyspace_sensitive: true

    - id: raft_election
      event_type: raft_election
      group: leadership
      default_severity: critical
      confidence_weight: 0.95
      source_roles: [ucp_kv_log]
      patterns:
        - 'starting a new election'
        - 'became pre-candidate'
        - 'elected leader'
        - 'became follower'
        - 'higher term'
      narrative_tags: [election_activity, leadership_instability]

    - id: client_conn_rejected
      event_type: client_conn_rejected
      group: client_symptom
      default_severity: high
      confidence_weight: 0.85
      source_roles: [ucp_kv_log]
      patterns:
        - 'rejected connection on client endpoint'
      narrative_tags: [client_visible_connectivity]

    - id: client_conn_reset
      event_type: client_conn_reset
      group: client_symptom
      default_severity: low
      confidence_weight: 0.65
      source_roles: [ucp_kv_log]
      patterns:
        - 'connection reset by peer'
        - '\bEOF\b'
      narrative_tags: [client_connection_churn]

    - id: rpc_request_stats
      event_type: rpc_request_stats
      group: general_latency
      default_severity: medium
      confidence_weight: 0.80
      source_roles: [ucp_kv_log]
      patterns:
        - '"msg"\s*:\s*"request stats"'
        - '\brequest stats\b'
      narrative_tags: [generic_request_latency]
      duration_policy: rpc_request_stats

###############################################################################
# Supplemental journal signatures
###############################################################################
journal_signatures:
  description: >
    Supplemental evidence matched against journalctl_daemon.log.

  events:
    - id: swarm_no_leader
      event_type: swarm_no_leader
      group: journal_leadership
      default_severity: critical
      confidence_weight: 0.85
      source_roles: [journalctl_daemon]
      patterns:
        - 'swarm does not have a leader'

    - id: journal_deadline_exceeded
      event_type: deadline_exceeded
      group: journal_network
      default_severity: high
      confidence_weight: 0.80
      source_roles: [journalctl_daemon]
      patterns:
        - 'DeadlineExceeded'
        - 'context deadline exceeded'

    - id: no_route_to_host
      event_type: no_route_to_host
      group: journal_network
      default_severity: high
      confidence_weight: 0.90
      source_roles: [journalctl_daemon]
      patterns:
        - 'no route to host'

    - id: connection_refused
      event_type: connection_refused
      group: journal_network
      default_severity: high
      confidence_weight: 0.90
      source_roles: [journalctl_daemon]
      patterns:
        - 'connection refused'

    - id: dns_no_such_host
      event_type: dns_no_such_host
      group: journal_network
      default_severity: medium
      confidence_weight: 0.75
      source_roles: [journalctl_daemon]
      patterns:
        - 'lookup .* no such host'

    - id: memberlist_refuting
      event_type: memberlist_refuting
      group: journal_membership
      default_severity: medium
      confidence_weight: 0.75
      source_roles: [journalctl_daemon]
      patterns:
        - 'memberlist:.*Refuting'

    - id: networkdb_connectivity_issues
      event_type: networkdb_connectivity_issues
      group: journal_network
      default_severity: medium
      confidence_weight: 0.75
      source_roles: [journalctl_daemon]
      patterns:
        - 'NetworkDB stats.*healthscore'

    - id: agent_session_failed
      event_type: agent_session_failed
      group: journal_leadership
      default_severity: high
      confidence_weight: 0.80
      source_roles: [journalctl_daemon]
      patterns:
        - 'agent: session failed'

    - id: etcd_rpc_unavailable
      event_type: etcd_rpc_unavailable
      group: journal_etcd_client
      default_severity: high
      confidence_weight: 0.85
      source_roles: [journalctl_daemon]
      patterns:
        - 'logger":"etcd-client"'
        - '"logger"\s*:\s*"etcd-client"'

    - id: journal_grpc_transport_closing
      event_type: grpc_transport_closing
      group: journal_transport
      default_severity: medium
      confidence_weight: 0.75
      source_roles: [journalctl_daemon]
      patterns:
        - 'transport is closing'

###############################################################################
# Storm / burst rules
###############################################################################
storm_rules:
  rules:
    - id: storm_readindex_retry
      event_type: readindex_retry
      window_seconds: 30
      count_gte: 5
      synthetic_event_type: storm_readindex_retry
      severity: high

    - id: storm_apply_took_too_long
      event_type: apply_took_too_long
      window_seconds: 60
      count_gte: 20
      synthetic_event_type: storm_apply_took_too_long
      severity: high

    - id: storm_linearizable_read_slow
      event_type: linearizable_read_slow
      window_seconds: 60
      count_gte: 20
      synthetic_event_type: storm_linearizable_read_slow
      severity: high

    - id: storm_raft_heartbeat_miss
      event_type: raft_heartbeat_miss
      window_seconds: 30
      count_gte: 3
      synthetic_event_type: storm_raft_heartbeat_miss
      severity: critical

    - id: storm_slow_fdatasync
      event_type: slow_fdatasync
      window_seconds: 60
      count_gte: 3
      synthetic_event_type: storm_slow_fdatasync
      severity: critical

    - id: storm_context_deadline
      event_type: context_deadline
      window_seconds: 60
      count_gte: 10
      synthetic_event_type: storm_context_deadline
      severity: high

    - id: storm_applied_index_lag
      event_type: applied_index_lag
      window_seconds: 60
      count_gte: 5
      synthetic_event_type: storm_applied_index_lag
      severity: critical

###############################################################################
# Family classification
###############################################################################
families:
  event_type_to_family:
    readindex_retry: read_path
    linearizable_read_slow: read_path
    raft_read_agreement_slow: read_path
    health_registry_read: read_path

    apply_took_too_long: apply_path
    raft_process_slow: apply_path
    raft_compare_slow: apply_path
    inmemory_index_scan_slow: apply_path
    applied_index_lag: apply_path

    slow_fdatasync: storage_timing
    raft_heartbeat_miss: storage_timing

    context_deadline: client_network
    context_canceled: client_network
    client_conn_rejected: client_network
    client_conn_reset: client_network
    grpc_transport_closing: client_network
    no_route_to_host: client_network
    connection_refused: client_network
    dns_no_such_host: client_network
    networkdb_connectivity_issues: client_network
    etcd_rpc_unavailable: client_network

    raft_election: raft_election
    health_no_leader: raft_election
    peer_probe_unhealthy: raft_election
    peer_connect_refused: raft_election
    swarm_no_leader: raft_election
    agent_session_failed: raft_election

###############################################################################
# Higher-order heuristic findings
###############################################################################
heuristics:
  rules:
    - id: likely_storage_stall_cascade
      title: "Likely storage timing cascade"
      enabled: true
      severity: high
      confidence_weight: 0.90
      window_seconds: 300
      requires:
        all_of:
          - slow_fdatasync
          - raft_heartbeat_miss
        any_of:
          - apply_took_too_long
          - readindex_retry
          - linearizable_read_slow
      outputs:
        tags: [storage_timing, cascade]
        likely_causes:
          - "WAL/fsync latency or storage stall"
          - "node-level pause affecting raft timing and apply latency"

    - id: likely_leader_overload
      title: "Likely leader overload / read-path pressure"
      enabled: true
      severity: high
      confidence_weight: 0.80
      window_seconds: 300
      requires:
        all_of:
          - readindex_retry
          - linearizable_read_slow
        none_of:
          - slow_fdatasync
      supports:
        - raft_read_agreement_slow
        - rpc_request_stats
      outputs:
        tags: [leader_overload, read_path_pressure]
        likely_causes:
          - "leader responsiveness degraded under load"
          - "hot read path or quorum read coordination pressure"

    - id: likely_peer_connectivity_failure
      title: "Likely peer connectivity failure"
      enabled: true
      severity: critical
      confidence_weight: 0.92
      window_seconds: 600
      requires:
        any_of:
          - peer_connect_refused
          - peer_probe_unhealthy
      supports:
        - raft_election
        - health_no_leader
        - connection_refused
        - no_route_to_host
      outputs:
        tags: [peer_connectivity, quorum_risk]
        likely_causes:
          - "member-to-member connectivity failure"
          - "peer listener unavailable or node down"
          - "network path/filtering issue"

    - id: likely_client_visible_outage
      title: "Client-visible etcd degradation"
      enabled: true
      severity: high
      confidence_weight: 0.85
      window_seconds: 300
      thresholds:
        - event_type: context_deadline
          count_gte: 5
      supports:
        - client_conn_rejected
        - grpc_transport_closing
        - health_no_leader
      outputs:
        tags: [client_visible, blast_radius]
        likely_causes:
          - "etcd degradation is surfacing to callers"
          - "timeouts or connection failures are affecting clients"

###############################################################################
# Narrative metadata
###############################################################################
narrative:
  categories:
    read_path:
      label: "read-path pressure"
    apply_path:
      label: "apply-path pressure"
    storage_timing:
      label: "storage timing degradation"
    raft_election:
      label: "leadership instability"
    client_network:
      label: "client/network symptom"
    control_plane:
      label: "control-plane path impact"
    correctness_risk:
      label: "correctness risk"

###############################################################################
# Reserved future expansion
###############################################################################
reserved:
  future_families:
    - watch_path
    - storage_quota_pressure
    - data_integrity
    - maintenance_side_effect
    - host_overload
```

</details>

---

[⬆ Back to Top](#top)

---
## 📊
## SOS_TRIAGE
---

Analyzes sosreports with a strong emphasis on Mirantis products to produce a structured and deterministic RCA view into events.
For example, analytics regarding one such item:
* Signatures + heuristics configuration for analyzing Docker Swarm manager
* Instability (raft/quorum/leadership), gossip/memberlist degradation, and
* Docker daemon restarts from sosreport artifacts.

## Key Capabilities
* A single pane of glass report through `report.md`
* Structured intermediate artifacts for deeper reasoning
* Deterministic, configuration-driven analysis
* Reproducible execution metadata
## Key Principles
* Scan everything
* Filter at event emission
* Cluster after filtering
* Derive findings from structured signal
* Render narrative from findings and timeline



## Operating Profiles
| Profile | Name | Purpose |
|----------|----------|----------|
| A | Quick Triage | Default |
| B | Deep Analysis | Journal |
| C | Forensics | Full |

### Profile A — Quick Triage

Most common support-engineer workflow; likely 80–90% of runs.

### Profile B — Deep Analysis

No guardrails or limits; used for deeper inspection.

### Profile C — One-shot Forensics

Used for unusual, complex, or weird bundles.


---

<details>
<summary>Conceptual Model</summary>
sos_triage transforms raw logs into layered analytical artifacts:

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
    ↓
meta.json records execution conditions and scan limits.
```

## What "Cluster" Means

In `sos_triage`, a cluster is a burst of semantically identical or near-identical events occurring close together in time.

It is **not**:

* A Kubernetes cluster
* A node group
* A distributed system concept

It is a temporal aggregation construct.

```text
Think:
    This thing happened 137 times in 4 minutes.

Instead of emitting 137 lines into `report.md`, `sos_triage` collapses that repeated activity into one summarized object.
Example:
    CLUSTER: 137 x raft peer connection failures in 00:04:13

This is signal compression.
```

</details>

<details>
<summary>Output Artifacts</summary>

All outputs are written to `--outdir`.

| File            | Purpose                              |
| --------------- | ------------------------------------ |
| `events.jsonl`  | Atomic normalized observations       |
| `clusters.json` | Burst compression of chatty patterns |
| `findings.json` | Heuristic conclusions with evidence  |
| `report.md`     | Human-readable RCA summary           |
| `meta.json`     | Execution ledger and scan conditions |


## Operational Guidance

When reviewing output:

1. Read `report.md`
2. Review `findings.json` for reasoning detail
3. Inspect `clusters.json` for burst patterns
4. Trace to `events.jsonl` if deeper context is required
5. Always check `meta.json` for limits and severity filtering

```text
- What is PYTHONPATH doing?
    - Telling Python to treat the tools/ directory as a top-level module search path.
    - Without this Python would not know where to find the "tools/sos_triage"
    - We are saying here: The package root lives inside /tools

    - What does the -m mean?
        - This is very important and tells python to run a module as a script, which effectively is this entire package sos_triage.
```
</details>

<details>
<summary>SOS_TRIAGE Examples</summary>

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


## Keeping the Extracted Sosreport

By default, the example above removes the extracted sosreport after analysis.

To keep the extracted sosreport, remove this argument:

```bash
--cleanup-extracted
```
</details>


## SOS_TRIAGE Signature File Content & Example

`sos_triage` uses a YAML signature file `sos-signatures.yaml` to define detectable patterns and interpretation rules.

The default signature file is found:

[`tool-signatures/sos-signatures.yaml`](tool-signatures/sos-signatures.yaml)

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

<details>
<summary>Example signature structure</summary>

```yaml
version: 5
name: sos-signatures
description: >
  Signatures + heuristics configuration for analyzing Docker Swarm manager
  instability (raft/quorum/leadership), gossip/memberlist degradation, and
  Docker daemon restarts from sosreport artifacts.

###############################################################################
# Global defaults (apply unless overridden)
###############################################################################
defaults:
  severities: [critical, high, medium, info]

  # Default context capture (Approach A: streaming with small buffer)
  context:
    pre: 1
    post: 2
    max_line_length: 500          # truncate long lines in stored context/excerpt
    trim_whitespace: true         # trim leading/trailing whitespace for stored strings
    store_context_in_events_jsonl: true
    store_context_in_findings: false

  # Excerpt defaults used in findings.json and report.md
  excerpt:
    max_chars: 240                # short excerpt for evidence samples

  # Event ID strategy: two IDs
  event_id:
    sequential_prefix: "evt_"
    sequential_width: 6           # evt_000001
    stable_hash:
      algorithm: "sha1"
      hex_chars: 12              # event_hash like e1c2a9f9b2c6
      canonical_fields:
        - source_relpath
        - line_number
        - signature_id
        - ts_normalized_or_raw
        - event_type
        - peer
        - port
        - message_normalized

  # Cluster ID strategy: two IDs (stable hash prefers membership)
  cluster_id:
    sequential_prefix: "clu_"
    sequential_width: 6           # clu_000001
    stable_hash:
      algorithm: "sha1"
      hex_chars: 12
      canonical_fields:
        - event_type
        - peer
        - port
        - start_ts_normalized_or_raw
        - end_ts_normalized_or_raw
        - count
        - member_event_hashes_sorted   # preferred stability anchor

###############################################################################
# sosreport source discovery (config-driven)
###############################################################################
sources:
  description: >
    Controls which files inside the extracted sosreport are scanned for
    signatures. Uses glob patterns relative to the sosreport root.

  # Include globs: scanned in the order listed (useful for determinism)
  include_globs:
    # Docker / container runtime logs
    - "var/log/docker*"
    - "var/log/containerd*"

    # Common syslog locations across distros
    - "var/log/messages*"
    - "var/log/syslog*"
    - "var/log/daemon.log*"
    - "var/log/kern.log*"

    # sos captured commands (journald + systemd + kernel)
    - "sos_commands/logs/journalctl*"
    - "sos_commands/systemd/systemctl*"
    - "sos_commands/kernel/dmesg*"

    # Some sosreports capture docker info / swarm state here
    - "sos_commands/docker/*"
    - "sos_strings/logs/journalctl*.tailed"
    - "var/log/installer/syslog*"

  # Exclude globs: remove noisy/binary/huge content
  exclude_globs:
    # Compressed files usually require extra handling; skip initially
    - "**/*.gz"
    - "**/*.xz"
    - "**/*.bz2"
    - "**/*.zip"

    # Binary journal files (not text); skip unless you later add a binary reader
    - "**/var/log/journal/**"
    - "**/*.journal"

    # Very large core dumps, etc.
    - "**/core*"
    - "**/*.core"

  # Guardrails
  file_limits:
    max_file_size_bytes: 104857600     # 100 MiB per file
    max_total_size_bytes: 536870912    # 512 MiB total scanned
    max_files: 5000

  # File handling behavior
  read:
    encoding: "utf-8"
    errors: "ignore"
    line_ending: "auto"

###############################################################################
# Output contracts and schema versions
###############################################################################
outputs:
  description: >
    Declares the schema versions for each output artifact. The tool will
    stamp these into the generated files and may validate compatibility.

  schemas:
    meta: "meta-v1"
    events: "events-v1"
    findings: "findings-v1"
    report: "report-md-v1"

  files:
    meta: "meta.json"
    events: "events.jsonl"
    findings: "findings.json"
    report: "report.md"

###############################################################################
# Signature definitions
###############################################################################
signatures:

  ###########################################################################
  # Docker daemon lifecycle (manager-impacting)
  ###########################################################################
  - id: docker_systemd_stop
    group: docker_daemon
    event_type: docker_restart
    severity: high
    confidence_weight: 0.90
    manager_only: true
    ports: []
    rationale: >
      Stopping Docker on a Swarm manager removes it from raft participation
      and can trigger leader elections.
    patterns:
      - "systemd\\[1\\]: Stopping Docker"
    relationships:
      follows:
        - event_type: docker_sigterm
          within_seconds: 120
    context:
      pre: 2
      post: 3

  - id: docker_systemd_start
    group: docker_daemon
    event_type: docker_restart
    severity: medium
    confidence_weight: 0.85
    manager_only: true
    ports: []
    rationale: >
      Docker start following a stop; used for restart storm correlation.
    patterns:
      - "systemd\\[1\\]: Started Docker"
    relationships:
      follows:
        - event_type: docker_restart
          within_seconds: 600
    context:
      pre: 1
      post: 2

  - id: dockerd_sigterm
    group: docker_daemon
    event_type: docker_sigterm
    severity: high
    confidence_weight: 0.95
    manager_only: true
    ports: []
    rationale: >
      Dockerd received SIGTERM (intentional shutdown via systemd/automation),
      not a crash.
    patterns:
      - "dockerd.*received signal.*terminated"
    context:
      pre: 1
      post: 2

  - id: docker_leftover_iptables
    group: docker_daemon
    event_type: docker_cleanup_warning
    severity: medium
    confidence_weight: 0.70
    manager_only: false
    ports: []
    rationale: >
      Leftover iptables processes can indicate rapid/repeated restarts and
      incomplete cleanup.
    patterns:
      - "docker\\.service: Found left-over process.*iptables"
    context:
      pre: 1
      post: 1

  ###########################################################################
  # Swarm leadership and raft consensus
  ###########################################################################
  - id: raft_leadership_lost
    group: raft
    event_type: raft_leadership_loss
    severity: critical
    confidence_weight: 0.95
    manager_only: true
    ports: [2377]
    rationale: >
      Loss of raft leader indicates control-plane instability and can disrupt
      cluster management operations.
    patterns:
      - "(?i)(lost leader|no leader)"
    relationships:
      follows:
        - event_type: raft_peer_connect_error
          within_seconds: 600
        - event_type: memberlist_timeout
          within_seconds: 900
    context:
      pre: 2
      post: 5

  - id: raft_leadership_lost_generic
    group: raft
    event_type: raft_leadership_loss
    severity: critical
    confidence_weight: 0.85
    manager_only: true
    ports: [2377]
    rationale: >
      Broad matching for leadership loss / leader unavailability messages that
      vary by Docker/Swarm versions and underlying raft implementations.
      Used when exact wording is unknown.
    patterns:
      - "(?i)leadership (lost|was lost|has been lost)"
      - "(?i)lost (the )?leader"
      - "(?i)no (current )?leader"
      - "(?i)leader (went away|has changed|changed)"
      - "(?i)became (candidate|follower)"
      - "(?i)starting a new election"
      - "(?i)election tick"
    relationships:
      follows:
        - event_type: raft_peer_connect_error
          within_seconds: 900
        - event_type: memberlist_timeout
          within_seconds: 1200
    context:
      pre: 2
      post: 6

  - id: swarm_controlplane_leader_generic
    group: swarm
    event_type: swarm_leader_change
    severity: high
    confidence_weight: 0.80
    manager_only: true
    ports: [2377]
    rationale: >
      Broad matching for Swarm control-plane components (manager/dispatcher/raft)
      reporting leader changes or leader unavailability where exact wording differs.
    patterns:
      - "(?i)manager.*(leader|leadership)"
      - "(?i)dispatcher.*(leader|leadership)"
      - "(?i)raft.*(leader|leadership)"
      - "(?i)swarm.*(leader|leadership)"
    relationships:
      follows:
        - event_type: raft_peer_connect_error
          within_seconds: 900
        - event_type: memberlist_timeout
          within_seconds: 1200
    context:
      pre: 2
      post: 6

  - id: raft_new_election
    group: raft
    event_type: raft_election
    severity: high
    confidence_weight: 0.90
    manager_only: true
    ports: [2377]
    rationale: >
      Elections are expected after manager failure/restart; repeated elections
      indicate instability.
    patterns:
      - "starting a new election"
    relationships:
      follows:
        - event_type: raft_leadership_loss
          within_seconds: 120
    context:
      pre: 2
      post: 5

  - id: raft_became_leader
    group: raft
    event_type: raft_leadership_gained
    severity: info
    confidence_weight: 0.85
    manager_only: true
    ports: [2377]
    rationale: >
      Used to correlate recovery and leadership churn.
    patterns:
      - "became leader"
    relationships:
      follows:
        - event_type: raft_election
          within_seconds: 600
    context:
      pre: 1
      post: 3

  - id: raft_peer_connect_error
    group: raft
    event_type: raft_peer_connect_error
    severity: high
    confidence_weight: 0.90
    manager_only: true
    ports: [2377]
    rationale: >
      Failure to connect to a peer on TCP/2377 indicates a manager is
      unavailable (daemon down/restarting) or connectivity is disrupted.
    patterns:
      - "dial tcp .*:2377.*(i/o timeout|connection refused|context deadline exceeded)"
    capture:
      peer: "(\\d+\\.\\d+\\.\\d+\\.\\d+)"
      port: "(2377)"
      reason: "(i/o timeout|connection refused|context deadline exceeded)"
    relationships:
      precedes:
        - event_type: raft_leadership_loss
          within_seconds: 900
    context:
      pre: 1
      post: 3

  ###########################################################################
  # Swarm membership / gossip (early instability indicators)
  ###########################################################################
  - id: memberlist_timeout
    group: memberlist
    event_type: memberlist_timeout
    severity: high
    confidence_weight: 0.85
    manager_only: true
    ports: [7946]
    rationale: >
      Timeouts on gossip port 7946 suggest network instability, packet loss,
      or intermittent filtering and often precede raft elections.
    patterns:
      - "memberlist:.*:7946.*i/o timeout"
      - "memberlist:.*no acks received"
    capture:
      peer: "(\\d+\\.\\d+\\.\\d+\\.\\d+)"
      port: "(7946)"
    relationships:
      precedes:
        - event_type: raft_election
          within_seconds: 1200
        - event_type: raft_leadership_loss
          within_seconds: 1800
    context:
      pre: 1
      post: 2

  - id: memberlist_suspect
    group: memberlist
    event_type: memberlist_suspect
    severity: medium
    confidence_weight: 0.80
    manager_only: true
    ports: [7946]
    rationale: >
      Nodes marked suspect indicate degraded membership health. Useful as
      supporting evidence for instability.
    patterns:
      - "memberlist: Suspect"
    relationships:
      follows:
        - event_type: memberlist_timeout
          within_seconds: 600
    context:
      pre: 1
      post: 2

  ###########################################################################
  # System / resource destabilizers (supporting evidence)
  ###########################################################################
  - id: oom_killer
    group: system_health
    event_type: oom_event
    severity: critical
    confidence_weight: 0.90
    manager_only: false
    ports: []
    rationale: >
      OOM can kill dockerd/containerd and trigger restarts; can also delay raft
      responsiveness.
    patterns:
      - "Out of memory"
      - "Killed process"
      - "oom-killer"
    relationships:
      precedes:
        - event_type: docker_restart
          within_seconds: 1800
    context:
      pre: 1
      post: 3

  - id: disk_full
    group: system_health
    event_type: disk_full
    severity: high
    confidence_weight: 0.85
    manager_only: false
    ports: []
    rationale: >
      Disk exhaustion can prevent raft log writes and disrupt Docker operations.
    patterns:
      - "No space left on device"
      - "ENOSPC"
    context:
      pre: 1
      post: 2

  - id: time_step
    group: system_health
    event_type: time_step
    severity: medium
    confidence_weight: 0.70
    manager_only: false
    ports: []
    rationale: >
      Significant clock adjustments can destabilize distributed consensus and
      produce leader churn.
    patterns:
      - "Time has been changed"
      - "System clock.*changed"
      - "stepped time"
    relationships:
      precedes:
        - event_type: raft_election
          within_seconds: 3600
    context:
      pre: 1
      post: 2

###############################################################################
# Temporal heuristics (hybrid approach: thresholds fire; relationships support)
###############################################################################
heuristics:
  - id: swarm_leader_churn
    title: "Swarm leader churn / control-plane instability"
    enabled: true
    severity: high
    confidence_weight: 0.85
    window_seconds: 900
    thresholds:
      - event_type: swarm_leader_change
        count_gte: 3
    supports:
      - event_type: raft_peer_connect_error
      - event_type: memberlist_timeout
      - event_type: raft_election
      - event_type: raft_leadership_loss
    outputs:
      tags: ["swarm_instability", "leader_churn"]
      likely_causes:
        - "raft elections due to manager connectivity loss or latency"
        - "packet loss/congestion or ACL/firewall impacting manager-to-manager traffic"
        - "manager restarts or daemon unavailability causing leadership turnover"
      ports_implicated: [2377, 7946]

  - id: swarm_gossip_instability
    title: "Swarm gossip instability detected"
    enabled: true
    severity: high
    confidence_weight: 0.80
    window_seconds: 600
    thresholds:
      - event_type: memberlist_timeout
        count_gte: 5
    supports:
      - event_type: memberlist_suspect
      - event_type: raft_election
      - event_type: raft_leadership_loss
    outputs:
      tags: ["network_suspected", "memberlist"]
      likely_causes:
        - "packet loss or congestion between managers"
        - "intermittent firewall/ACL behavior affecting TCP/7946"
        - "MTU mismatch impacting overlay/gossip traffic"
      ports_implicated: [7946]

  - id: repeated_elections
    title: "Repeated raft elections detected"
    enabled: true
    severity: high
    confidence_weight: 0.85
    window_seconds: 900
    thresholds:
      - event_type: raft_election
        count_gte: 2
    supports:
      - event_type: raft_peer_connect_error
      - event_type: raft_leadership_loss
    outputs:
      tags: ["raft_instability"]
      likely_causes:
        - "manager connectivity loss or latency on TCP/2377"
        - "manager restarts causing raft churn"
      ports_implicated: [2377]

  - id: docker_restart_storm
    title: "Docker restart storm detected"
    enabled: true
    severity: high
    confidence_weight: 0.90
    window_seconds: 600
    thresholds:
      - event_type: docker_restart
        count_gte: 3
    supports:
      - event_type: docker_sigterm
      - event_type: docker_cleanup_warning
      - event_type: raft_election
      - event_type: raft_leadership_loss
    outputs:
      tags: ["operator_action_suspected", "restart_storm"]
      likely_causes:
        - "manual restarts"
        - "automation restarting docker due to health checks"
      ports_implicated: [2377, 7946]

  - id: leadership_loss_present
    title: "Raft leadership loss observed"
    enabled: true
    severity: critical
    confidence_weight: 0.95
    window_seconds: 1800
    thresholds:
      - event_type: raft_leadership_loss
        count_gte: 1
    supports:
      - event_type: raft_election
      - event_type: raft_peer_connect_error
      - event_type: memberlist_timeout
    outputs:
      tags: ["leadership_loss"]
      likely_causes:
        - "loss of manager connectivity on 2377/7946"
        - "manager restart or daemon unavailability"
      ports_implicated: [2377, 7946]

###############################################################################
# Context grouping (event clustering for chatty patterns)
###############################################################################
context_grouping:
  enabled: true
  description: >
    Groups related events into clusters to summarize bursts (e.g., many
    memberlist timeouts or raft peer connection failures) and reduce noise
    in timelines while preserving diagnostic value.

  chatty_event_types:
    - memberlist_timeout
    - raft_peer_connect_error

  cluster_window_seconds: 60
  max_gap_seconds: 30
  group_by_keys: [event_type, peer, port]
  min_events: 3

  outputs:
    include_in_findings: true
    include_in_timeline: true
    include_in_report: true

    timeline_cluster_row_format: >
      CLUSTER: {event_type} to {peer}:{port} — {count} events from {start} to {end}

    sample_strategy:
      include_first: true
      include_last: true
      include_max_samples: 3

    cluster_fields:
      - count
      - start
      - end
      - top_reasons
      - sources

###############################################################################
# Timeline construction (Option 2: from events.jsonl with clustering + downsample)
###############################################################################
timeline:
  enabled: true
  description: >
    Builds the report timeline from events.jsonl using clustering for chatty
    event types, always-keep rules for critical events, and time bucketing to
    reduce noise while preserving causal story.

  max_rows: 40
  bucket_seconds: 120
  quiet_gap_seconds: 1200

  include_event_types:
    - raft_leadership_loss
    - raft_election
    - raft_leadership_gained
    - raft_peer_connect_error
    - docker_restart
    - docker_sigterm
    - docker_cleanup_warning
    - memberlist_timeout
    - memberlist_suspect
    - oom_event
    - disk_full
    - time_step

  always_keep:
    severity_at_least: critical
    first_event_type_occurrence: true
    referenced_by_findings: true
    cluster_rows: true
    gap_boundary_markers: true

  downsample:
    per_bucket:
      max_per_event_type: 1
      pick: earliest

    overflow_policy:
      drop_order:
        - info
        - medium
        - high
      prefer_keep:
        - raft_leadership_loss
        - raft_election
        - docker_restart
        - memberlist_timeout
        - raft_peer_connect_error

  chatty_handling:
    memberlist_timeout:
      prefer_clusters: true
      max_peers_per_10min: 2
      peer_diversity_note: true
    raft_peer_connect_error:
      prefer_clusters: true
      max_peers_per_10min: 2
      peer_diversity_note: true

```
</details>
---

[⬆ Back to Top](#top)

---