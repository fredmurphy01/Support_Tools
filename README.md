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

Displays node information from an MKE3 cluster support bundle with additional validation, guardrails, and reporting enhancements.

> Note: This tool currently operates on MKE3 cluster-wide support bundles.

## Quick Start

```bash
python3 tools/sdnodes.py \
    --bundlepath tickets/12345678/docker-support-20260303-19_51_11
```


<details>
<summary>SDNODES Examples</summary>

### Example-1: Basic output (default is pretty)
```bash
python3 tools/sdnodes.py --bundlepath tickets/12345678/docker-support-20260303-19_51_11
```

### Example-2: Extended output showing hardware (default is pretty)
```bash
python3 tools/sdnodes.py --bundlepath tickets/12345678/docker-support-20260303-19_51_11 --extended-output 1
```
### Example-3: Output to console in csv style
```bash
python3 tools/sdnodes.py --bundlepath tickets/12345678/docker-support-20260303-19_51_11 --pretty 0
```

### Example-4: Output to a file (Typically used for output in csv format so the file can be imported to spreadsheet. Default file = nodes_output.csv)
```bash
python3 tools/sdnodes.py --bundlepath tickets/12345678/docker-support-20260303-19_51_11 --pretty 0 --filesave 1 --outputfile outputdir/nodes_output_file.csv
```

### Example-5: Add columns Accountname & Ticket number to console output first two columns. Particularly useful if saving output file for later use.
```bash
python3 tools/sdnodes.py --bundlepath tickets/12345678/docker-support-20260303-19_51_11 --accountname CORP-ABC --ticketnumber 12345678
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

## Output Artifacts

By default the tool creates:

* report-patsrc.md
* support_bundle_ddmmmyyyy-hh-mm.json
* support_bundle_ddmmmyyyy-hh-mm.txt

## Quick Start

```bash
python3 tools/patterns_search.py \
    --directory tickets/12345678/docker-support-20260303-19_51_11
```

## Common Examples

### Standard Pattern Scan

```bash
python3 tools/patterns_search.py \
    --directory tickets/12345678/docker-support-20260303-19_51_11
```

### Verbose Mode

```bash
python3 tools/patterns_search.py \
    --directory tickets/12345678/docker-support-20260303-19_51_11 \
    --verbose
```

### External Pattern File

```bash
python3 tools/patterns_search.py \
    --directory tickets/12345678/docker-support-20260303-19_51_11 \
    --patterns tools/tool-signatures/patterns.txt
```

---

# BUNDLE_SANITIZE.PY

Sanitizes extracted MKE3 support bundles and replaces customer-sensitive data with generated values.

## Data Sanitized

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

### Sanitized Content

* Sanitized bundle directory

### Change Tracking

* sanitize_changed_details.json
* sanitize_changed_details.txt
* sanitize_changed_files.json
* sanitize_changed_files.txt

### Reports

* sanitize_report.html
* sanitize_report.json
* sanitize_report.md

### Optional Mapping

* sanitize_mapping.json

## Quick Start

```bash
python3 tools/bundle_sanitize.py \
    --bundle tickets/12345678/docker-support-20260303-19_51_11 \
    --mapping \
    --outdir tickets/12345678
```

---

# ETCD_ANALYSIS

Analyzes ETCD logs and related artifacts to identify abnormal behavior and construct incident narratives.

## Key Capabilities

* Detect event storms
* Correlate related events
* Build incident windows
* Generate severity-aware summaries
* Produce structured output artifacts

## Generated Artifacts

* etcd_analysis_report.md
* etcd_analysis.json
* *.events.csv

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

| Profile   | Name               | Intended Use                                                           |
| --------- | ------------------ | ---------------------------------------------------------------------- |
| Profile A | Quick Triage       | DEFAULT - Most common support-engineer workflow; likely 80–90% of runs |
| Profile B | Deep Analysis      | JOURNAL - No guardrails or limits; used for deeper inspection          |
| Profile C | One-shot Forensics | FULL- Used for unusual, complex, or weird bundles                      |

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
