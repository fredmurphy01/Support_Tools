#!/usr/bin/env python3
"""
bundle_sanitize_v9_6.py

Unified flow:
- Phase A: read seeded CSV, generate deterministic mappings, emit:
    - sanitized_node_info.csv
    - sanitize_mapping.json
    - sanitize_report.json
    - sanitize_report.md
    - sanitize_report.html
- Phase B: rebuild bundle tree into sanitized root, sanitize path names,
  sanitize text-like file contents, and apply a first high-value
  intelligence pass for:
    1) derived short hostnames
    2) host:port / ip:port endpoints
    3) URLs
    4) MAC addresses -> mac-001
    5) email-like strings -> user001@example.invalid
    6) first certificate-aware token handling
- Additional artifacts:
    - sanitize_changed_files.txt
    - sanitize_changed_files.json
    - sanitize_changed_details.txt
    - sanitize_changed_details.json
"""

from __future__ import annotations

import argparse
import csv
import json
import mimetypes
import re
import os
import shutil
import sys
import signal
import time
from dataclasses import dataclass, field
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit
import subprocess

TEXT_EXTENSIONS = {
    ".txt", ".log", ".json", ".yaml", ".yml", ".csv", ".tsv", ".md",
    ".xml", ".conf", ".cfg", ".ini", ".cnf", ".service", ".sh", ".py",
    ".out", ".err", ".crt", ".pem", ".cer", ".html", ".js", ".properties",
    ".toml",
}

IPV4_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
)
MAC_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b|\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
CERT_DNS_RE = re.compile(r"(?P<prefix>\bDNS:)\s*(?P<value>[^,\s]+)")
CERT_IP_RE = re.compile(r"(?P<prefix>\bIP Address:)\s*(?P<value>[^,\s]+)")
CERT_CN_EQ_RE = re.compile(r"(?P<prefix>\bCN=)(?P<value>[^,/\n]+)")
CERT_CN_NODE_RE = re.compile(r"(?P<prefix>\bCN:system:node:)(?P<value>[^\s,]+)")
CERT_CN_NODE_EQ_RE = re.compile(r"(?P<prefix>\bCN=system:node:)(?P<value>[^,/\n]+)")
URL_CANDIDATE_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>]+")
HOSTPORT_RE = re.compile(
    r"\b(?P<host>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,63})+)|(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}|[A-Za-z0-9][A-Za-z0-9-]{1,62})\:(?P<port>\d{1,5})\b"
)
SHA256_RE = re.compile(r"\bsha256:(?P<value>[0-9a-fA-F]{64})\b")
CONTAINER_FULL_CONTEXT_RE = re.compile(
    r'(?P<prefix>(?:"Id"\s*:\s*"|\bcontainer(?:_id| id)?\b\s*[:=]\s*|\bcontainerd://|\bdocker://|/containers/))(?P<value>[0-9a-fA-F]{64})(?P<suffix>"?)'
)
CONTAINER_SHORT_CONTEXT_RE = re.compile(
    r'(?P<prefix>(?:"Hostname"\s*:\s*"|"Aliases"\s*:\s*\[\s*"|\bhostname\b\s*[:=]\s*|/containers/))(?P<value>[0-9a-fA-F]{12})(?P<suffix>"?)'
)
PURE_CONTAINER_FULL_RE = re.compile(r'\b(?P<value>[0-9a-fA-F]{64})\b')
PURE_CONTAINER_SHORT_RE = re.compile(r'\b(?P<value>[0-9a-fA-F]{12})\b')
WHITESPACE_RE = re.compile(r"\s+")

_WORKER_MAPPING: dict = {}
_WORKER_REPLACEMENTS: List[Tuple[str, str]] = []


@dataclass
class Stats:
    dry_run: bool = False
    rows_read: int = 0
    rows_written: int = 0
    rows_changed: int = 0
    files_total: int = 0
    files_changed: int = 0
    files_unchanged: int = 0
    files_copied_binary: int = 0
    files_errors: int = 0
    dirs_created: int = 0
    renamed_paths: int = 0
    hostname_values_seeded: int = 0
    short_hostname_values_seeded: int = 0
    ip_values_seeded: int = 0
    cluster_ids_seeded: int = 0
    node_ids_seeded: int = 0
    hostname_whitespace_normalized: int = 0
    columns_sanitized: Set[str] = field(default_factory=set)
    replacements_by_class: Dict[str, int] = field(default_factory=dict)
    collisions: List[Dict[str, str]] = field(default_factory=list)
    changed_files: List[str] = field(default_factory=list)
    changed_details: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def bump(self, key: str, amount: int = 1) -> None:
        self.replacements_by_class[key] = self.replacements_by_class.get(key, 0) + amount


@dataclass
class SeedInventory:
    unique_hostnames: Set[str] = field(default_factory=set)
    unique_short_hostnames: Set[str] = field(default_factory=set)
    unique_ips: Set[str] = field(default_factory=set)
    unique_cluster_ids: Set[str] = field(default_factory=set)
    unique_node_ids: Set[str] = field(default_factory=set)


class DeterministicMapper:
    def __init__(self) -> None:
        self.hostname_map: Dict[str, str] = {}
        self.short_hostname_map: Dict[str, str] = {}
        self.ip_map: Dict[str, str] = {}
        self.cluster_map: Dict[str, str] = {}
        self.node_map: Dict[str, str] = {}
        self.mac_map: Dict[str, str] = {}
        self.email_map: Dict[str, str] = {}
        self.sha256_map: Dict[str, str] = {}
        self.container_id_map: Dict[str, str] = {}
        self.container_short_id_map: Dict[str, str] = {}

    @staticmethod
    def normalize_hostname(value: str) -> Tuple[str, bool]:
        original = value or ""
        normalized = WHITESPACE_RE.sub("", original.strip()).lower()
        return normalized, normalized != original.strip().lower()

    def map_hostname(self, value: str) -> str:
        key, _ = self.normalize_hostname(value)
        if not key:
            return value
        if key not in self.hostname_map:
            idx = len(self.hostname_map) + 1
            self.hostname_map[key] = f"host-{idx:03d}.example.invalid"
        return self.hostname_map[key]

    def seed_short_hostname(self, hostname_value: str) -> None:
        key, _ = self.normalize_hostname(hostname_value)
        if not key:
            return

        mapped_hostname = self.map_hostname(key)
        mapped_short = mapped_hostname.split(".", 1)[0]

        # Always seed the normalized source itself as a short-host key.
        # This covers common real-world inputs like "BY73UIX01" where
        # the CSV hostname is already the short hostname and not an FQDN.
        if key not in self.short_hostname_map:
            self.short_hostname_map[key] = mapped_short

        # If the source is an FQDN, also seed the first label explicitly.
        if "." in key:
            short = key.split(".", 1)[0]
            if short not in self.short_hostname_map:
                self.short_hostname_map[short] = mapped_short

    def map_short_hostname(self, value: str) -> str:
        return self.short_hostname_map.get(value.strip().lower(), value)

    def map_ip(self, value: str) -> str:
        key = value.strip()
        if not key:
            return value
        if key not in self.ip_map:
            idx = len(self.ip_map) + 1
            octet3 = ((idx - 1) // 254) % 254 + 1
            octet4 = ((idx - 1) % 254) + 1
            self.ip_map[key] = f"10.0.{octet3}.{octet4}"
        return self.ip_map[key]

    def map_cluster(self, value: str) -> str:
        key = value.strip()
        if not key:
            return value
        if key not in self.cluster_map:
            idx = len(self.cluster_map) + 1
            self.cluster_map[key] = f"cluster-{idx:03d}"
        return self.cluster_map[key]

    def map_node(self, value: str) -> str:
        key = value.strip()
        if not key:
            return value
        if key not in self.node_map:
            idx = len(self.node_map) + 1
            self.node_map[key] = f"node-{idx:03d}"
        return self.node_map[key]

    def map_mac(self, value: str) -> str:
        key = value.strip().lower()
        if not key:
            return value
        if key not in self.mac_map:
            idx = len(self.mac_map) + 1
            self.mac_map[key] = f"mac-{idx:03d}"
        return self.mac_map[key]

    def map_email(self, value: str) -> str:
        key = value.strip().lower()
        if not key:
            return value
        if key not in self.email_map:
            idx = len(self.email_map) + 1
            self.email_map[key] = f"user{idx:03d}@example.invalid"
        return self.email_map[key]

    def map_sha256_digest(self, value: str) -> str:
        key = value.strip().lower()
        if not key:
            return value
        if key not in self.sha256_map:
            idx = len(self.sha256_map) + 1
            self.sha256_map[key] = f"digest-{idx:03d}"
        return self.sha256_map[key]

    def map_container_id(self, value: str) -> str:
        key = value.strip().lower()
        if not key:
            return value
        if key not in self.container_id_map:
            idx = len(self.container_id_map) + 1
            mapped = f"container-{idx:03d}"
            self.container_id_map[key] = mapped
            self.container_short_id_map.setdefault(key[:12], f"ctr-{idx:03d}")
        return self.container_id_map[key]

    def map_container_short_id(self, value: str) -> str:
        key = value.strip().lower()
        if not key:
            return value
        if key not in self.container_short_id_map:
            idx = len(self.container_short_id_map) + 1
            self.container_short_id_map[key] = f"ctr-{idx:03d}"
        return self.container_short_id_map[key]


def normalize_header_name(name: str) -> str:
    return (name or "").strip()


def normalize_row_keys(row: dict) -> dict:
    return {normalize_header_name(k): v for k, v in row.items()}


def get_field(row: dict, field: str) -> str:
    return row.get(field, "") or row.get(f"{field} ", "") or ""


def looks_textual(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    mime, _ = mimetypes.guess_type(path.name)
    return bool(mime and (mime.startswith("text/") or mime in {"application/json", "application/xml"}))


def seed_mappings_from_csv(csv_path: Path, mapper: DeterministicMapper, stats: Stats) -> Tuple[List[dict], SeedInventory]:
    rows: List[dict] = []
    inventory = SeedInventory()
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=";")
        if reader.fieldnames:
            reader.fieldnames = [normalize_header_name(name) for name in reader.fieldnames]
        for raw_row in reader:
            row = normalize_row_keys(raw_row)
            rows.append(row)
            stats.rows_read += 1

            hostname = get_field(row, "HOSTNAME")
            if hostname:
                normalized, changed = mapper.normalize_hostname(hostname)
                if changed:
                    stats.hostname_whitespace_normalized += 1
                if normalized:
                    inventory.unique_hostnames.add(normalized)
                    inventory.unique_short_hostnames.add(normalized.split(".", 1)[0])
                mapper.map_hostname(hostname)
                mapper.seed_short_hostname(hostname)

            ip_mask = get_field(row, "IP/MASK")
            m = IPV4_RE.search(ip_mask)
            if m:
                ip = m.group(0)
                inventory.unique_ips.add(ip)
                mapper.map_ip(ip)

            cluster_id = get_field(row, "CLUSTER-ID")
            if cluster_id and cluster_id.strip():
                inventory.unique_cluster_ids.add(cluster_id.strip())
                mapper.map_cluster(cluster_id)

            node_id = get_field(row, "NODE-ID")
            if node_id and node_id.strip():
                inventory.unique_node_ids.add(node_id.strip())
                mapper.map_node(node_id)

    stats.hostname_values_seeded = len(mapper.hostname_map)
    stats.short_hostname_values_seeded = len(mapper.short_hostname_map)
    stats.ip_values_seeded = len(mapper.ip_map)
    stats.cluster_ids_seeded = len(mapper.cluster_map)
    stats.node_ids_seeded = len(mapper.node_map)
    return rows, inventory


def build_known_replacements(mapper: DeterministicMapper) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for d in (mapper.hostname_map, mapper.ip_map, mapper.cluster_map, mapper.node_map, mapper.short_hostname_map):
        for src, dst in d.items():
            pairs.append((src, dst))
    pairs.sort(key=lambda item: len(item[0]), reverse=True)
    return pairs


def preseed_digest_and_container_mappings(bundle_dir: Path, mapper: DeterministicMapper) -> None:
    """
    Cheap preseed pass.

    We only preseed sha256 digests, because they are narrow/high-confidence
    and can appear in paths. Full/short container IDs are discovered during
    the normal sanitize pipeline instead of via a whole-bundle regex sweep,
    which proved too expensive on large bundles.
    """
    sha_values: Set[str] = set()
    scanned_files = 0
    last_progress = time.time()
    max_preseed_bytes = 8 * 1024 * 1024

    print("[info] preseed: scanning bundle for sha256 digests only ...", file=sys.stderr)

    for path in bundle_dir.rglob("*"):
        if not path.is_file() or not looks_textual(path):
            continue

        # Keep the preseed pass cheap. Very large logs are sanitized in the
        # normal pipeline later and do not need an up-front digest sweep.
        try:
            if path.stat().st_size > max_preseed_bytes:
                continue
        except Exception:
            continue

        scanned_files += 1
        if scanned_files == 1 or scanned_files % 200 == 0 or (time.time() - last_progress) >= 10:
            print(f"[progress] preseed: scanned {scanned_files} text files for sha256 digests ...", file=sys.stderr)
            last_progress = time.time()

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        sha_values.update(m.group("value").lower() for m in SHA256_RE.finditer(content))

    for value in sorted(sha_values):
        mapper.map_sha256_digest(value)

    print(f"[info] preseed: seeded {len(sha_values)} sha256 digests", file=sys.stderr)


def sanitize_digest_and_container_tokens(text: str, mapper: DeterministicMapper, stats: Optional[Stats], per_file: Optional[Dict[str, int]], path_mode: bool = False) -> str:
    def sha_repl(match: re.Match[str]) -> str:
        value = match.group("value").lower()
        mapped = mapper.map_sha256_digest(value)
        if stats:
            stats.bump("sha256_digest")
        if per_file is not None:
            per_file["sha256_digest"] = per_file.get("sha256_digest", 0) + 1
        return f"sha256:{mapped}"

    def full_ctx_repl(match: re.Match[str]) -> str:
        value = match.group("value").lower()
        mapped = mapper.map_container_id(value)
        if stats:
            stats.bump("container_id")
        if per_file is not None:
            per_file["container_id"] = per_file.get("container_id", 0) + 1
        return f"{match.group('prefix')}{mapped}{match.group('suffix')}"

    def short_ctx_repl(match: re.Match[str]) -> str:
        value = match.group("value").lower()
        mapped = mapper.map_container_short_id(value)
        if stats:
            stats.bump("container_short_id")
        if per_file is not None:
            per_file["container_short_id"] = per_file.get("container_short_id", 0) + 1
        return f"{match.group('prefix')}{mapped}{match.group('suffix')}"

    text = SHA256_RE.sub(sha_repl, text)
    text = CONTAINER_FULL_CONTEXT_RE.sub(full_ctx_repl, text)
    text = CONTAINER_SHORT_CONTEXT_RE.sub(short_ctx_repl, text)

    if path_mode:
        m = PURE_CONTAINER_FULL_RE.fullmatch(text)
        if m:
            value = m.group("value").lower()
            mapped = mapper.map_container_id(value)
            if stats:
                stats.bump("container_id")
            if per_file is not None:
                per_file["container_id"] = per_file.get("container_id", 0) + 1
            return mapped
        m = PURE_CONTAINER_SHORT_RE.fullmatch(text)
        if m:
            value = m.group("value").lower()
            mapped = mapper.map_container_short_id(value)
            if stats:
                stats.bump("container_short_id")
            if per_file is not None:
                per_file["container_short_id"] = per_file.get("container_short_id", 0) + 1
            return mapped

    return text


def sanitize_component(name: str, mapper: DeterministicMapper) -> str:
    normalized_name = name.strip().lower()

    # First, handle whole-component hostname matches using normalized lookup.
    # This is the safest fix for bundle path parts like "BYOTL5530U6".
    if normalized_name in mapper.short_hostname_map:
        return mapper.short_hostname_map[normalized_name].strip()

    if normalized_name in mapper.hostname_map:
        return mapper.hostname_map[normalized_name].strip()

    # Fall back to the existing replacement pass for other seeded values.
    for src, dst in build_known_replacements(mapper):
        if src in name:
            name = name.replace(src, dst)

    name = sanitize_digest_and_container_tokens(name, mapper, None, None, path_mode=True)
    return name.strip()


def sanitize_urls(text: str, mapper: DeterministicMapper, stats: Optional[Stats], per_file: Optional[Dict[str, int]]) -> str:
    def repl(match: re.Match[str]) -> str:
        original = match.group(0)
        try:
            parts = urlsplit(original)
        except Exception:
            return original
        host = parts.hostname
        if not host:
            return original
        new_host = host
        key = None
        if host in mapper.ip_map:
            new_host = mapper.map_ip(host)
            key = "url_ip"
        elif host.lower() in mapper.hostname_map:
            new_host = mapper.map_hostname(host)
            key = "url_hostname"
        elif host.lower() in mapper.short_hostname_map:
            new_host = mapper.map_short_hostname(host)
            key = "url_short_hostname"
        if new_host == host:
            return original
        if stats: stats.bump(key)
        if per_file is not None: per_file[key] = per_file.get(key, 0) + 1
        netloc = parts.netloc
        userinfo = ""
        if "@" in netloc:
            userinfo = netloc.split("@", 1)[0] + "@"
        port = f":{parts.port}" if parts.port else ""
        new_netloc = f"{userinfo}{new_host}{port}"
        return urlunsplit((parts.scheme, new_netloc, parts.path, parts.query, parts.fragment))
    return URL_CANDIDATE_RE.sub(repl, text)


def sanitize_hostport(text: str, mapper: DeterministicMapper, stats: Optional[Stats], per_file: Optional[Dict[str, int]]) -> str:
    def repl(match: re.Match[str]) -> str:
        host = match.group("host")
        port = match.group("port")
        new_host = host
        key = None
        if host in mapper.ip_map:
            new_host = mapper.map_ip(host)
            key = "hostport_ip"
        elif host.lower() in mapper.hostname_map:
            new_host = mapper.map_hostname(host)
            key = "hostport_hostname"
        elif host.lower() in mapper.short_hostname_map:
            new_host = mapper.map_short_hostname(host)
            key = "hostport_short_hostname"
        if new_host == host:
            return match.group(0)
        if stats: stats.bump(key)
        if per_file is not None: per_file[key] = per_file.get(key, 0) + 1
        return f"{new_host}:{port}"
    return HOSTPORT_RE.sub(repl, text)


def sanitize_cert_tokens(text: str, mapper: DeterministicMapper, stats: Optional[Stats], per_file: Optional[Dict[str, int]]) -> str:
    def dns_repl(match: re.Match[str]) -> str:
        value = match.group("value")
        key = None
        repl_value = None
        if value.lower() in mapper.hostname_map:
            key = "cert_dns_hostname"
            repl_value = mapper.map_hostname(value)
        elif value.lower() in mapper.short_hostname_map:
            key = "cert_dns_short_hostname"
            repl_value = mapper.map_short_hostname(value)
        if repl_value is None:
            return match.group(0)
        if stats: stats.bump(key)
        if per_file is not None: per_file[key] = per_file.get(key, 0) + 1
        return f"{match.group('prefix')}{repl_value}"

    def ip_repl(match: re.Match[str]) -> str:
        value = match.group("value")
        if value not in mapper.ip_map:
            return match.group(0)
        if stats: stats.bump("cert_ip")
        if per_file is not None: per_file["cert_ip"] = per_file.get("cert_ip", 0) + 1
        return f"{match.group('prefix')}{mapper.map_ip(value)}"

    def cn_repl(match: re.Match[str]) -> str:
        value = match.group("value").strip()
        key = None
        repl_value = None
        if value.lower() in mapper.hostname_map:
            key = "cert_cn_hostname"
            repl_value = mapper.map_hostname(value)
        elif value.lower() in mapper.short_hostname_map:
            key = "cert_cn_short_hostname"
            repl_value = mapper.map_short_hostname(value)
        if repl_value is None:
            return match.group(0)
        if stats: stats.bump(key)
        if per_file is not None: per_file[key] = per_file.get(key, 0) + 1
        return f"{match.group('prefix')}{repl_value}"

    text = CERT_DNS_RE.sub(dns_repl, text)
    text = CERT_IP_RE.sub(ip_repl, text)
    text = CERT_CN_EQ_RE.sub(cn_repl, text)
    text = CERT_CN_NODE_RE.sub(cn_repl, text)
    text = CERT_CN_NODE_EQ_RE.sub(cn_repl, text)
    return text


def sanitize_general_tokens(text: str, mapper: DeterministicMapper, replacements: List[Tuple[str, str]], stats: Optional[Stats], per_file: Optional[Dict[str, int]]) -> str:
    def email_repl(match: re.Match[str]) -> str:
        if stats: stats.bump("email")
        if per_file is not None: per_file["email"] = per_file.get("email", 0) + 1
        return mapper.map_email(match.group(0))

    def mac_repl(match: re.Match[str]) -> str:
        if stats: stats.bump("mac")
        if per_file is not None: per_file["mac"] = per_file.get("mac", 0) + 1
        return mapper.map_mac(match.group(0))

    text = EMAIL_RE.sub(email_repl, text)
    text = MAC_RE.sub(mac_repl, text)

    for src, dst in replacements:
        count = text.count(src)
        if count:
            text = text.replace(src, dst)
            # classify broad replacements
            key = "generic"
            if src in mapper.hostname_map:
                key = "hostname"
            elif src in mapper.short_hostname_map:
                key = "short_hostname"
            elif src in mapper.ip_map:
                key = "ip"
            elif src in mapper.cluster_map:
                key = "cluster_id"
            elif src in mapper.node_map:
                key = "node_id"
            if stats: stats.bump(key, count)
            if per_file is not None: per_file[key] = per_file.get(key, 0) + count
    return text


def sanitize_text(text: str, mapper: DeterministicMapper, replacements: List[Tuple[str, str]], stats: Optional[Stats], per_file: Optional[Dict[str, int]]) -> str:
    text = sanitize_digest_and_container_tokens(text, mapper, stats, per_file)
    text = sanitize_urls(text, mapper, stats, per_file)
    text = sanitize_hostport(text, mapper, stats, per_file)
    text = sanitize_cert_tokens(text, mapper, stats, per_file)
    text = sanitize_general_tokens(text, mapper, replacements, stats, per_file)
    return text


def sanitize_csv_rows(rows: List[dict], mapper: DeterministicMapper, replacements: List[Tuple[str, str]], stats: Stats) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        new_row = dict(normalize_row_keys(dict(row)))
        row_changed = False

        hostname = get_field(new_row, "HOSTNAME")
        if hostname:
            normalized, _ = mapper.normalize_hostname(hostname)

            # Prefer short-host mapping for CSV output
            sanitized = mapper.short_hostname_map.get(
                normalized,
                mapper.map_hostname(hostname).split(".", 1)[0]
            )

            if sanitized != hostname:
                new_row["HOSTNAME"] = sanitized
                row_changed = True
                stats.columns_sanitized.add("HOSTNAME")
                stats.bump("hostname")

        ip_mask = get_field(new_row, "IP/MASK")
        if ip_mask:
            m = IPV4_RE.search(ip_mask)
            if m:
                start, end = m.span()
                sanitized = f"{ip_mask[:start]}{mapper.map_ip(m.group(0))}{ip_mask[end:]}"
                if sanitized != ip_mask:
                    new_row["IP/MASK"] = sanitized
                    row_changed = True
                    stats.columns_sanitized.add("IP/MASK")
                    stats.bump("ip_mask")

        cluster_id = get_field(new_row, "CLUSTER-ID")
        if cluster_id:
            sanitized = mapper.map_cluster(cluster_id)
            if sanitized != cluster_id:
                new_row["CLUSTER-ID"] = sanitized
                row_changed = True
                stats.columns_sanitized.add("CLUSTER-ID")
                stats.bump("cluster_id")

        node_id = get_field(new_row, "NODE-ID")
        if node_id:
            sanitized = mapper.map_node(node_id)
            if sanitized != node_id:
                new_row["NODE-ID"] = sanitized
                row_changed = True
                stats.columns_sanitized.add("NODE-ID")
                stats.bump("node_id")

        status_message = get_field(new_row, "STATUS_MESSAGE")
        if status_message:
            sanitized = sanitize_text(status_message, mapper, replacements, stats, None)
            if sanitized != status_message:
                new_row["STATUS_MESSAGE"] = sanitized
                row_changed = True
                stats.columns_sanitized.add("STATUS_MESSAGE")

        out.append(new_row)
        stats.rows_written += 1
        if row_changed:
            stats.rows_changed += 1
    return out


def write_csv(rows: List[dict], out_path: Path) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)


def html_escape(value: object) -> str:
    text = str(value)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def status_badge(label: str, kind: str) -> str:
    return f'<span class="badge badge-{kind}">{html_escape(label)}</span>'


def build_report(stats: Stats, inventory: SeedInventory, mapper: DeterministicMapper, include_mapping: bool, bundle_processed: bool, sanitized_root: Optional[Path]) -> dict:
    return {
        "summary": {
            "dry_run": stats.dry_run,
            "rows_read": stats.rows_read,
            "rows_written": stats.rows_written,
            "rows_changed": stats.rows_changed,
            "changed_files_count": stats.files_changed,
            "unchanged_files_count": stats.files_unchanged,
            "binary_copied_files_count": stats.files_copied_binary,
            "error_files_count": stats.files_errors,
            "files_total": stats.files_total,
            "dirs_created": stats.dirs_created,
            "renamed_paths": stats.renamed_paths,
            "hostname_values_seeded": stats.hostname_values_seeded,
            "short_hostname_values_seeded": stats.short_hostname_values_seeded,
            "ip_values_seeded": stats.ip_values_seeded,
            "cluster_ids_seeded": stats.cluster_ids_seeded,
            "node_ids_seeded": stats.node_ids_seeded,
            "hostname_whitespace_normalized": stats.hostname_whitespace_normalized,
            "columns_sanitized": sorted(stats.columns_sanitized),
            "replacements_by_class": dict(sorted(stats.replacements_by_class.items())),
            "collision_count": len(stats.collisions),
        },
        "uniques": {
            "unique_hostnames": len(inventory.unique_hostnames),
            "unique_short_hostnames": len(inventory.unique_short_hostnames),
            "unique_ips": len(inventory.unique_ips),
            "unique_cluster_ids": len(inventory.unique_cluster_ids),
            "unique_node_ids": len(inventory.unique_node_ids),
        },
        "bundle": {"processed": bundle_processed, "sanitized_root": str(sanitized_root) if sanitized_root else None},
        "output": {
            "mapping_included": include_mapping,
            "changed_files_txt": "sanitize_changed_files.txt",
            "changed_files_json": "sanitize_changed_files.json",
            "changed_details_txt": "sanitize_changed_details.txt",
            "changed_details_json": "sanitize_changed_details.json",
        },
        "examples": {
            "hostnames": list(mapper.hostname_map.items()),
            "short_hostnames": list(mapper.short_hostname_map.items()),
            "ips": list(mapper.ip_map.items()),
            "cluster_ids": list(mapper.cluster_map.items()),
            "node_ids": list(mapper.node_map.items()),
            "macs": list(mapper.mac_map.items()),
            "emails": list(mapper.email_map.items()),
            "sha256_digests": list(mapper.sha256_map.items()),
            "container_ids": list(mapper.container_id_map.items()),
            "container_short_ids": list(mapper.container_short_id_map.items()),
        },
        "collisions": stats.collisions,
    }


def write_markdown_report(out_dir: Path, report: dict) -> None:
    s = report["summary"]
    u = report["uniques"]
    b = report["bundle"]
    output = report["output"]
    replacement_lines = "\n".join(f"- `{k}`: **{v}**" for k, v in s["replacements_by_class"].items()) or "- _No replacements recorded._"
    columns = ", ".join(f"`{c}`" for c in s["columns_sanitized"]) or "_None_"
    md = f"""# Bundle Sanitize v9.6 Report

## Run Summary

| Item | Value |
|---|---:|
| Rows read | {s['rows_read']} |
| Rows written | {s['rows_written']} |
| Rows changed | {s['rows_changed']} |
| Files total | {s['files_total']} |
| Changed files count | {s['changed_files_count']} |
| Unchanged files count | {s['unchanged_files_count']} |
| Binary copied files count | {s['binary_copied_files_count']} |
| Error files count | {s['error_files_count']} |
| Directories created | {s['dirs_created']} |
| Renamed paths | {s['renamed_paths']} |
| Collision count | {s['collision_count']} |

## Seed Inventory

| Identifier class | Unique count |
|---|---:|
| Hostnames | {u['unique_hostnames']} |
| Short hostnames | {u['unique_short_hostnames']} |
| IP addresses | {u['unique_ips']} |
| Cluster IDs | {u['unique_cluster_ids']} |
| Node IDs | {u['unique_node_ids']} |

## CSV Sanitization Coverage

- Columns sanitized: {columns}
- Hostname whitespace normalized: **{s['hostname_whitespace_normalized']}**

## Seeded Mapping Counts

| Mapping class | Count |
|---|---:|
| Hostnames | {s['hostname_values_seeded']} |
| Short hostnames | {s['short_hostname_values_seeded']} |
| IPs | {s['ip_values_seeded']} |
| Cluster IDs | {s['cluster_ids_seeded']} |
| Node IDs | {s['node_ids_seeded']} |

## Replacements By Class

{replacement_lines}

## Output Notes

- Mapping file included: **{'Yes' if report['output']['mapping_included'] else 'No'}**
- Sanitized bundle root: **{b['sanitized_root'] or 'N/A'}**
- Changed files manifest (txt): **{output['changed_files_txt']}**
- Changed files manifest (json): **{output['changed_files_json']}**
- Changed file details (txt): **{output['changed_details_txt']}**
- Changed file details (json): **{output['changed_details_json']}**
"""
    (out_dir / "sanitize_report.md").write_text(md, encoding="utf-8")


def write_html_report(out_dir: Path, report: dict) -> None:
    s = report["summary"]
    u = report["uniques"]
    b = report["bundle"]
    output = report["output"]
    columns = s["columns_sanitized"]
    replacements = s["replacements_by_class"]

    card_rows = [
        ("Rows read", s["rows_read"]),
        ("Rows changed", s["rows_changed"]),
        ("Files total", s["files_total"]),
        ("Files changed", s["changed_files_count"]),
        ("Files unchanged", s["unchanged_files_count"]),
        ("Binary copied", s["binary_copied_files_count"]),
        ("Hostnames seeded", s["hostname_values_seeded"]),
        ("Short hosts seeded", s["short_hostname_values_seeded"]),
        ("IPs seeded", s["ip_values_seeded"]),
        ("Renamed paths", s["renamed_paths"]),
    ]

    replacement_rows = "".join(
        f"<tr><td><code>{html_escape(k)}</code></td><td>{html_escape(v)}</td></tr>"
        for k, v in replacements.items()
    ) or '<tr><td colspan="2"><em>No replacements recorded.</em></td></tr>'

    column_chips = " ".join(f'<span class="chip"><code>{html_escape(c)}</code></span>' for c in columns) or '<span class="muted">None</span>'

    examples_order = [
        ("Hostnames", report["examples"]["hostnames"]),
        ("Short Hostnames", report["examples"]["short_hostnames"]),
        ("IPs", report["examples"]["ips"]),
        ("Cluster IDs", report["examples"]["cluster_ids"]),
        ("Node IDs", report["examples"]["node_ids"]),
        ("MACs", report["examples"]["macs"]),
        ("Emails", report["examples"]["emails"]),
        ("SHA256 Digests", report["examples"]["sha256_digests"]),
        ("Container IDs", report["examples"]["container_ids"]),
        ("Container Short IDs", report["examples"]["container_short_ids"]),
    ]
    panels = []
    for label, items in examples_order:
        if not items:
            continue
        lis = "".join(f"<li><code>{html_escape(src)}</code> → <code>{html_escape(dst)}</code></li>" for src, dst in items)
        hint = '<span class="scroll-hint">Scroll</span>' if len(items) > 6 else ""
        panels.append(f'<section class="panel mapping-panel"><div class="section-head"><h3>{html_escape(label)} <span class="muted">({len(items)})</span></h3>{hint}</div><div class="examples-wrap"><ul class="examples">{lis}</ul></div></section>')
    examples_html = "".join(panels)

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bundle Sanitize v9.6 Report</title>
<style>
:root {{ color-scheme: light dark; --bg:#0b1020; --panel:#111831; --panel-2:#17203f; --text:#e7ecff; --muted:#9fb0df; --line:#2b3a68; --good:#1f9d55; --warn:#d9822b; --info:#2d7ff9; --chip:#22305d; }}
@media (prefers-color-scheme: light) {{ :root {{ --bg:#f5f7fb; --panel:#fff; --panel-2:#eef3ff; --text:#19233d; --muted:#58698f; --line:#d4def5; --good:#157347; --warn:#b26a16; --info:#0d6efd; --chip:#e6edff; }} }}
* {{ box-sizing:border-box; }} body {{ margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:var(--bg); color:var(--text); }}
.wrap {{ max-width:1240px; margin:0 auto; padding:24px; }} h1,h2,h3 {{ margin:0 0 12px; }} p {{ margin:0 0 12px; }}
.hero {{ display:flex; gap:12px; align-items:center; justify-content:space-between; padding:18px 20px; border:1px solid var(--line); background:linear-gradient(135deg,var(--panel),var(--panel-2)); border-radius:16px; margin-bottom:18px; }}
.hero-meta {{ display:flex; gap:8px; flex-wrap:wrap; }}
.badge {{ display:inline-flex; align-items:center; border-radius:999px; padding:5px 10px; font-size:12px; font-weight:700; }}
.badge-good {{ background:color-mix(in srgb, var(--good) 18%, transparent); color:var(--good); border:1px solid color-mix(in srgb, var(--good) 45%, transparent); }}
.badge-warn {{ background:color-mix(in srgb, var(--warn) 18%, transparent); color:var(--warn); border:1px solid color-mix(in srgb, var(--warn) 45%, transparent); }}
.badge-info {{ background:color-mix(in srgb, var(--info) 18%, transparent); color:var(--info); border:1px solid color-mix(in srgb, var(--info) 45%, transparent); }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-bottom:18px; }}
.card,.panel {{ border:1px solid var(--line); background:var(--panel); border-radius:16px; padding:16px; }}
.card .label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
.card .value {{ font-size:28px; font-weight:800; margin-top:8px; }}
.section-grid {{ display:grid; grid-template-columns:1.2fr .8fr; gap:16px; margin-bottom:18px; }}
.examples-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:16px; margin-bottom:18px; }}
.mapping-panel {{ min-height:200px; }} .section-head {{ display:flex; justify-content:space-between; gap:8px; align-items:center; }}
.scroll-hint {{ color:var(--muted); font-size:12px; }} table {{ width:100%; border-collapse:collapse; }}
th,td {{ text-align:left; padding:10px 8px; border-bottom:1px solid var(--line); vertical-align:top; }} th {{ color:var(--muted); font-size:13px; }}
.chips {{ display:flex; gap:8px; flex-wrap:wrap; }} .chip {{ background:var(--chip); border:1px solid var(--line); border-radius:999px; padding:6px 10px; font-size:12px; }}
.muted {{ color:var(--muted); }} .examples-wrap {{ max-height:220px; overflow-y:auto; padding-right:6px; }} .examples {{ margin:0; padding-left:18px; }} .examples li {{ margin:0 0 8px; }}
code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
@media (max-width:860px) {{ .section-grid {{ grid-template-columns:1fr; }} .hero {{ flex-direction:column; align-items:flex-start; }} }}
</style></head>
<body><div class="wrap">
<header class="hero"><div><h1>Bundle Sanitize v9.6 Report</h1><p class="muted">Unified CSV + bundle sanitization report.</p></div>
<div class="hero-meta">{status_badge('Write mode','good')}{status_badge('Bundle processed' if b['processed'] else 'CSV only','info')}{status_badge('Mapping included' if report['output']['mapping_included'] else 'No mapping file','good' if report['output']['mapping_included'] else 'warn')}</div></header>
<section class="grid">{''.join(f'<div class="card"><div class="label">{html_escape(label)}</div><div class="value">{html_escape(value)}</div></div>' for label, value in card_rows)}</section>
<section class="section-grid">
<div class="panel"><h2>Run Summary</h2><table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>Hostname whitespace normalized</td><td>{html_escape(s['hostname_whitespace_normalized'])}</td></tr>
<tr><td>Columns sanitized</td><td><div class="chips">{column_chips}</div></td></tr>
<tr><td>Collision count</td><td>{html_escape(s['collision_count'])}</td></tr>
<tr><td>Sanitized bundle root</td><td><code>{html_escape(b['sanitized_root'] or 'N/A')}</code></td></tr>
<tr><td>Changed files manifest (txt)</td><td><code>{html_escape(output['changed_files_txt'])}</code></td></tr>
<tr><td>Changed files manifest (json)</td><td><code>{html_escape(output['changed_files_json'])}</code></td></tr>
<tr><td>Changed file details (txt)</td><td><code>{html_escape(output['changed_details_txt'])}</code></td></tr>
<tr><td>Changed file details (json)</td><td><code>{html_escape(output['changed_details_json'])}</code></td></tr>
</table></div>
<div class="panel"><h2>Unique Seed Inventory</h2><table>
<tr><th>Identifier class</th><th>Unique count</th></tr>
<tr><td>Hostnames</td><td>{html_escape(u['unique_hostnames'])}</td></tr>
<tr><td>Short hostnames</td><td>{html_escape(u['unique_short_hostnames'])}</td></tr>
<tr><td>IP addresses</td><td>{html_escape(u['unique_ips'])}</td></tr>
<tr><td>Cluster IDs</td><td>{html_escape(u['unique_cluster_ids'])}</td></tr>
<tr><td>Node IDs</td><td>{html_escape(u['unique_node_ids'])}</td></tr>
</table></div></section>
<section class="section-grid">
<div class="panel"><h2>Seeded Mapping Counts</h2><table>
<tr><th>Mapping class</th><th>Count</th></tr>
<tr><td>Hostnames</td><td>{html_escape(s['hostname_values_seeded'])}</td></tr>
<tr><td>Short hostnames</td><td>{html_escape(s['short_hostname_values_seeded'])}</td></tr>
<tr><td>IPs</td><td>{html_escape(s['ip_values_seeded'])}</td></tr>
<tr><td>Cluster IDs</td><td>{html_escape(s['cluster_ids_seeded'])}</td></tr>
<tr><td>Node IDs</td><td>{html_escape(s['node_ids_seeded'])}</td></tr>
</table></div>
<div class="panel"><h2>Replacements by Class</h2><table><tr><th>Class</th><th>Count</th></tr>{replacement_rows}</table></div></section>
<section class="examples-grid">{examples_html}</section></div></body></html>"""
    (out_dir / "sanitize_report.html").write_text(html, encoding="utf-8")


def write_changed_files_artifacts(out_dir: Path, stats: Stats) -> None:
    rel_paths = sorted(stats.changed_files)
    txt_path = out_dir / "sanitize_changed_files.txt"
    json_path = out_dir / "sanitize_changed_files.json"

    txt_lines = [f"Changed files ({len(rel_paths)})", ""]
    txt_lines.extend(rel_paths)
    txt_path.write_text("\n".join(txt_lines) + "\n", encoding="utf-8")

    payload = {
        "changed_files_count": len(rel_paths),
        "changed_files": rel_paths,
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_changed_details_artifacts(out_dir: Path, stats: Stats) -> None:
    txt_path = out_dir / "sanitize_changed_details.txt"
    json_path = out_dir / "sanitize_changed_details.json"

    details_entries = []
    lines = []
    for rel_path in sorted(stats.changed_details.keys()):
        counts = dict(sorted(stats.changed_details[rel_path].items()))
        total = sum(counts.values())
        details_entries.append({
            "path": rel_path,
            "total_replacements": total,
            "replacement_counts": counts,
        })
        lines.append(rel_path)
        lines.append(f"  total_replacements: {total}")
        for key, value in counts.items():
            lines.append(f"  {key}: {value}")
        lines.append("")

    txt_path.write_text("\n".join(lines).rstrip() + ("\n" if lines else ""), encoding="utf-8")
    json_payload = {
        "changed_files_count": len(details_entries),
        "changed_files": details_entries,
    }
    json_path.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")


def write_report_files(out_dir: Path, stats: Stats, inventory: SeedInventory, mapper: DeterministicMapper, include_mapping: bool, bundle_processed: bool, sanitized_root: Optional[Path]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(stats, inventory, mapper, include_mapping, bundle_processed, sanitized_root)
    (out_dir / "sanitize_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown_report(out_dir, report)
    write_html_report(out_dir, report)
    write_changed_files_artifacts(out_dir, stats)
    write_changed_details_artifacts(out_dir, stats)
    if include_mapping:
        mapping = {
            "hostnames": mapper.hostname_map,
            "short_hostnames": mapper.short_hostname_map,
            "ips": mapper.ip_map,
            "cluster_ids": mapper.cluster_map,
            "node_ids": mapper.node_map,
            "macs": mapper.mac_map,
            "emails": mapper.email_map,
            "sha256_digests": mapper.sha256_map,
            "container_ids": mapper.container_id_map,
            "container_short_ids": mapper.container_short_id_map,
        }
        (out_dir / "sanitize_mapping.json").write_text(json.dumps(mapping, indent=2), encoding="utf-8")


def init_worker(mapping: dict) -> None:
    global _WORKER_MAPPING, _WORKER_REPLACEMENTS
    _WORKER_MAPPING = mapping
    _WORKER_REPLACEMENTS = list(mapping["known_replacements"])


def determine_workers(requested: int) -> int:
    if requested <= 0:
        cpu = cpu_count() or 2
        workers = max(1, cpu - 2)
        print(f"[info] using {workers} workers (auto: cpu-2)", file=sys.stderr)
        return workers
    return min(requested, cpu_count() or 1)


def validate_bundle_path(bundle_root: Path) -> None:
    if not bundle_root.exists():
        raise RuntimeError(f"Bundle path does not exist: {bundle_root}")
    if not bundle_root.is_dir():
        raise RuntimeError(f"Bundle path is not a directory: {bundle_root}")

def resolve_sdnodes_path() -> Path:
    return (Path(__file__).resolve().parent / "sdnodes.py").resolve()


def generate_seed_csv_from_bundle(bundle_dir: Path, out_dir: Path) -> Path:
    sdnodes_path = resolve_sdnodes_path()
    if not sdnodes_path.exists() or not sdnodes_path.is_file():
        raise RuntimeError(f"sdnodes.py not found: {sdnodes_path}")

    generated_csv_path = (out_dir / "nodes_output.csv").resolve()

    cmd = [
        str(sys.executable),
        "-u",
        str(sdnodes_path),
        "--bundlepath",
        str(bundle_dir),
        "--filesave",
        "1",
        "--pretty",
        "0",
        "--outputfile",
        str(generated_csv_path),
    ]

    print(f"[info] generating node inventory csv via sdnodes -> {generated_csv_path}", file=sys.stderr)

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
    except KeyboardInterrupt:
        raise
    except Exception as e:
        raise RuntimeError(f"failed to launch sdnodes.py: {e}")

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="", file=sys.stderr, flush=True)
    finally:
        if proc.stdout is not None:
            proc.stdout.close()

    returncode = proc.wait()

    if not generated_csv_path.exists() or not generated_csv_path.is_file():
        raise RuntimeError(
            f"seed csv was not produced by sdnodes.py: {generated_csv_path}"
        )

    if returncode != 0:
        raise RuntimeError(
            f"sdnodes.py exited with status {returncode} and seed csv cannot be trusted: {generated_csv_path}"
        )
    return generated_csv_path

def build_worker_mapping(mapper: DeterministicMapper) -> dict:
    return {
        "hostnames": dict(mapper.hostname_map),
        "short_hostnames": dict(mapper.short_hostname_map),
        "ips": dict(mapper.ip_map),
        "cluster_ids": dict(mapper.cluster_map),
        "node_ids": dict(mapper.node_map),
        "macs": dict(mapper.mac_map),
        "emails": dict(mapper.email_map),
        "sha256_digests": dict(mapper.sha256_map),
        "container_ids": dict(mapper.container_id_map),
        "container_short_ids": dict(mapper.container_short_id_map),
        "known_replacements": build_known_replacements(mapper),
    }


def sanitize_text_worker(content: str) -> Tuple[str, Dict[str, int]]:
    mapper = DeterministicMapper()
    mapper.hostname_map = dict(_WORKER_MAPPING["hostnames"])
    mapper.short_hostname_map = dict(_WORKER_MAPPING["short_hostnames"])
    mapper.ip_map = dict(_WORKER_MAPPING["ips"])
    mapper.cluster_map = dict(_WORKER_MAPPING["cluster_ids"])
    mapper.node_map = dict(_WORKER_MAPPING["node_ids"])
    mapper.mac_map = dict(_WORKER_MAPPING["macs"])
    mapper.email_map = dict(_WORKER_MAPPING["emails"])
    mapper.sha256_map = dict(_WORKER_MAPPING["sha256_digests"])
    mapper.container_id_map = dict(_WORKER_MAPPING["container_ids"])
    mapper.container_short_id_map = dict(_WORKER_MAPPING["container_short_ids"])
    per_file: Dict[str, int] = {}
    content = sanitize_digest_and_container_tokens(content, mapper, None, per_file)
    content = sanitize_urls(content, mapper, None, per_file)
    content = sanitize_hostport(content, mapper, None, per_file)
    content = sanitize_cert_tokens(content, mapper, None, per_file)
    content = sanitize_general_tokens(content, mapper, _WORKER_REPLACEMENTS, None, per_file)
    return content, per_file


def process_file(job: Tuple[str, str, str]) -> Tuple[str, str, str, Dict[str, int]]:
    src_str, dst_str, rel_str = job
    src_path = Path(src_str)
    dst_path = Path(dst_str)
    try:
        if looks_textual(src_path):
            text = src_path.read_text(encoding="utf-8", errors="ignore")
            new_text, per_file = sanitize_text_worker(text)
            dst_path.write_text(new_text, encoding="utf-8")
            return ("changed" if text != new_text else "unchanged", src_str, rel_str, per_file)
        shutil.copy2(src_path, dst_path)
        return ("copied", src_str, rel_str, {})
    except Exception as e:
        return (f"error:{e}", src_str, rel_str, {})


def sanitize_bundle(bundle_dir: Path, out_dir: Path, mapper: DeterministicMapper, stats: Stats, workers: int) -> Path:
    bundle_dir = bundle_dir.resolve()
    out_dir = out_dir.resolve()
    sanitized_root = out_dir / f"{bundle_dir.name}-sanitized"
    sanitized_root.mkdir(parents=True, exist_ok=True)

    seen_paths = set()
    file_jobs: List[Tuple[str, str, str]] = []
    worker_mapping = build_worker_mapping(mapper)

    for path in bundle_dir.rglob("*"):
        try:
            if path.resolve().is_relative_to(sanitized_root.resolve()):
                continue
        except Exception:
            pass

        rel = path.relative_to(bundle_dir)
        parts = []
        for part in rel.parts:
            new_part = sanitize_component(part, mapper)
            if new_part != part:
                stats.renamed_paths += 1
            parts.append(new_part)

        target = sanitized_root.joinpath(*parts)
        key = str(target).lower()
        if key in seen_paths:
            stats.collisions.append({"source": str(path), "target": str(target)})
            raise RuntimeError(f"Collision detected:\n{path}\n→ {target}")
        seen_paths.add(key)

        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            stats.dirs_created += 1
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            file_jobs.append((str(path), str(target), str(Path(*parts))))

    total_jobs = len(file_jobs)
    if total_jobs == 0:
        return sanitized_root

    start = time.time()
    done = 0
    next_progress = 1
    last_progress = start

    def note_progress(done_count: int) -> None:
        nonlocal next_progress, last_progress
        now = time.time()
        if done_count == 1 or done_count >= next_progress or (now - last_progress) >= 10:
            elapsed = now - start
            print(f"[progress] processed {done_count}/{total_jobs} files in {elapsed:.1f}s ...", file=sys.stderr)
            last_progress = now
            if done_count >= next_progress:
                next_progress = ((done_count // 200) + 1) * 200

    iterator = None
    pool = None
    if workers > 1:
        pool = Pool(processes=workers, initializer=init_worker, initargs=(worker_mapping,))
        iterator = pool.imap_unordered(process_file, file_jobs, chunksize=25)
    else:
        init_worker(worker_mapping)
        iterator = map(process_file, file_jobs)

    try:
        for result, _src, rel_str, per_file in iterator:
            done += 1
            note_progress(done)
            stats.files_total += 1
            if result == "changed":
                stats.files_changed += 1
                stats.changed_files.append(rel_str)
                if per_file:
                    stats.changed_details[rel_str] = dict(sorted(per_file.items()))
            elif result == "unchanged":
                stats.files_unchanged += 1
            elif result == "copied":
                stats.files_copied_binary += 1
            elif result.startswith("error:"):
                stats.files_errors += 1
    finally:
        if pool is not None:
            pool.close()
            pool.join()

    return sanitized_root


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Unified bundle sanitizer v9.7")
    p.add_argument("--bundle", required=True, help="Extracted bundle directory to sanitize")
    p.add_argument("--outdir", required=True, help="Output directory for artifacts and sanitized bundle")
    p.add_argument("--mapping", action="store_true", help="Write sanitize_mapping.json")
    p.add_argument("--workers", type=int, default=0, help="Worker processes for bundle content rewrite (0=auto cpu-2)")
    return p

def _handle_sigterm(signum, frame):
    raise KeyboardInterrupt


def _handle_top_level_interrupt() -> int:
    print("\n[bundle_sanitize] interrupted — exiting gracefully", file=sys.stderr)
    return 130

def main() -> int:
    args = build_parser().parse_args()
    out_dir = Path(args.outdir).expanduser().resolve()
    bundle_dir = Path(args.bundle).expanduser().resolve()

    validate_bundle_path(bundle_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    csv_path = generate_seed_csv_from_bundle(bundle_dir, out_dir)

    if not csv_path.exists() or not csv_path.is_file():
        raise SystemExit(f"Generated seed CSV not found: {csv_path}")

    mapper = DeterministicMapper()
    stats = Stats()
    rows, inventory = seed_mappings_from_csv(csv_path, mapper, stats)

    preseed_digest_and_container_mappings(bundle_dir, mapper)

    replacements = build_known_replacements(mapper)
    sanitized_rows = sanitize_csv_rows(rows, mapper, replacements, stats)

    write_csv(sanitized_rows, out_dir / "sanitized_node_info.csv")

    workers = determine_workers(args.workers)
    sanitized_root = sanitize_bundle(bundle_dir, out_dir, mapper, stats, workers)

    write_report_files(out_dir, stats, inventory, mapper, bool(args.mapping), bool(bundle_dir), sanitized_root)

    print(json.dumps({
        "ok": True,
        "outdir": str(out_dir),
        "sanitized_csv": str(out_dir / "sanitized_node_info.csv"),
        "bundle_processed": bool(bundle_dir),
        "sanitized_root": str(sanitized_root) if sanitized_root else None,
        "report_json": str(out_dir / "sanitize_report.json"),
        "report_md": str(out_dir / "sanitize_report.md"),
        "report_html": str(out_dir / "sanitize_report.html"),
        "changed_files_txt": str(out_dir / "sanitize_changed_files.txt"),
        "changed_files_json": str(out_dir / "sanitize_changed_files.json"),
        "changed_details_txt": str(out_dir / "sanitize_changed_details.txt"),
        "changed_details_json": str(out_dir / "sanitize_changed_details.json"),
        "mapping": str(out_dir / "sanitize_mapping.json") if args.mapping else None,
    }, indent=2))
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(_handle_top_level_interrupt())