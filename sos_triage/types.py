""" types.py version 1.1.0 """
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

@dataclass(frozen=True)
class ResolvedPaths:
    sosreport_path: Path
    config_path: Path
    outdir: Path
    extract_dir: Path

@dataclass(frozen=True)
class FileTarget:
    relpath: str
    abspath: Path
    size_bytes: int

@dataclass
class ScanStats:
    files_considered: int = 0
    files_matched_includes: int = 0
    files_excluded: int = 0
    files_skipped_too_large: int = 0
    files_skipped_unreadable: int = 0
    files_scanned: int = 0
    bytes_scanned: int = 0
    bytes_skipped_too_large: int = 0
    skip_reasons: Dict[str, int] = field(default_factory=dict)

@dataclass
class EventsWriteResult:
    events_emitted: int
    events_with_parsed_timestamps: int
    events_without_timestamps: int
    signatures_matched: Dict[str, int]
    events_truncated: bool = False

@dataclass
class ExtractResult:
    extracted_root: Path
    status: str
    archive_format: str

@dataclass
class SignatureDef:
    id: str
    group: str
    event_type: str
    severity: str
    confidence_weight: float
    manager_only: bool
    ports: List[int]
    rationale: str
    patterns: List[str]
    capture: Dict[str, str] = field(default_factory=dict)
    context: Dict[str, int] = field(default_factory=dict)

@dataclass
class Config:
    raw: Dict[str, Any]
    defaults: Dict[str, Any]
    sources: Dict[str, Any]
    outputs: Dict[str, Any]
    signatures: List[SignatureDef]
    compiled: Dict[str, Any]  # signature_id -> compiled regex list + captures

@dataclass
class EventCandidate:
    signature_id: str
    event_type: str
    severity: str
    confidence: float
    ports: List[int]
    ts: Optional[str]
    ts_raw: Optional[str]
    source_relpath: str
    line_number: int
    message: str
    excerpt: str
    peer: Optional[str]=None
    port: Optional[int]=None
    reason: Optional[str]=None
    context_pre: List[str]=field(default_factory=list)
    context_post: List[str]=field(default_factory=list)

@dataclass
class AnalyzeResult:
    events_path: Path
    meta_path: Path
    extracted_root: Optional[Path]
    scan_stats: ScanStats
    events_result: Optional[EventsWriteResult]
