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

## Common Examples

### Basic Output

```bash
python3 tools/sdnodes.py \
    --bundlepath tickets/12345678/docker-support-20260303-19_51_11
```

### Extended Hardware Information

```bash
python3 tools/sdnodes.py \
    --bundlepath tickets/12345678/docker-support-20260303-19_51_11 \
    --extended-output 1
```

### CSV Style Output

```bash
python3 tools/sdnodes.py \
    --bundlepath tickets/12345678/docker-support-20260303-19_51_11 \
    --pretty 0
```

### Save Output To File

```bash
python3 tools/sdnodes.py \
    --bundlepath tickets/12345678/docker-support-20260303-19_51_11 \
    --pretty 0 \
    --filesave 1 \
    --outputfile outputdir/nodes_output_file.csv
```

## Full Command Help

```text
python3 tools/sdnodes.py -h

usage: sdnodes.py [-h] [--pretty {0,1}] [--outputfile OUTPUTFILE]
                  [--filesave {0,1}]
                  ...
```

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

Evaluates sosreports and produces structured deterministic analysis using configurable signatures and heuristics.

## Purpose

Transforms raw logs into layered analytical artifacts:

```text
Raw Logs
    ↓
events.jsonl
    ↓
clusters.json
    ↓
findings.json
    ↓
report.md
```

## Generated Artifacts

* events.jsonl
* clusters.json
* findings.json
* report.md
* meta.json

## Quick Start

```bash
PYTHONPATH=tools python3 -m sos_triage analyze \
    tickets/12345678/sosreport.tar.xz \
    --outdir tickets/12345678/sosanalysis
```
