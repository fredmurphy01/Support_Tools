""" lint.py version 1.1.0 """
from __future__ import annotations

"""Config linter for configs/sos-signatures.yaml.

Purpose
-------
Keep signature authoring safe and predictable by validating:
  - required top-level keys
  - signature schema basics
  - duplicate IDs
  - regex compilation
  - severity values
  - cross-references to event_types in context_grouping / timeline / heuristics

This linter does *not* attempt to prove correctness of semantics; it is meant
to prevent obvious breakage and accidental noise regressions.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import yaml


ALLOWED_SEVERITIES = {"critical", "high", "medium", "info"}


@dataclass(frozen=True)
class LintMessage:
    level: str  # "ERROR" | "WARN"
    code: str
    message: str
    path: str = ""


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _collect_event_types_from_signatures(signatures: List[Dict[str, Any]]) -> Set[str]:
    evts: Set[str] = set()
    for s in signatures:
        et = s.get("event_type")
        if isinstance(et, str) and et:
            evts.add(et)
    return evts


def _iter_heuristic_event_types(raw: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    """Yield (event_type, yaml_path) for any heuristic references."""
    heur = raw.get("heuristics")
    if not isinstance(heur, list):
        return
    for i, h in enumerate(heur):
        if not isinstance(h, dict):
            continue
        for section in ("thresholds", "supports"):
            items = h.get(section)
            if not isinstance(items, list):
                continue
            for j, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                et = item.get("event_type")
                if isinstance(et, str) and et:
                    yield et, f"heuristics[{i}].{section}[{j}].event_type"


def lint_config(config_path: Path) -> List[LintMessage]:
    msgs: List[LintMessage] = []

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception as e:
        return [LintMessage("ERROR", "CONFIG_LOAD_FAILED", str(e), path=str(config_path))]

    if not isinstance(raw, dict):
        return [LintMessage("ERROR", "CONFIG_INVALID", "Config root must be a mapping", path=str(config_path))]

    # Required top-level keys (matches loader expectations)
    for k in ("defaults", "sources", "outputs", "signatures"):
        if k not in raw:
            msgs.append(LintMessage("ERROR", "MISSING_KEY", f"Missing required top-level key: {k}", path=k))

    sigs = raw.get("signatures")
    if not isinstance(sigs, list):
        msgs.append(LintMessage("ERROR", "SIGNATURES_NOT_LIST", "signatures must be a list", path="signatures"))
        return msgs

    # Defaults.severities sanity
    defaults = raw.get("defaults")
    if isinstance(defaults, dict):
        sev = defaults.get("severities")
        if sev is not None:
            bad = [s for s in _as_list(sev) if str(s).lower() not in ALLOWED_SEVERITIES]
            if bad:
                msgs.append(
                    LintMessage(
                        "WARN",
                        "DEFAULT_SEVERITIES_UNKNOWN",
                        f"defaults.severities contains unknown values: {bad} (allowed: {sorted(ALLOWED_SEVERITIES)})",
                        path="defaults.severities",
                    )
                )

    # Signature schema + regex compilation
    seen_ids: Set[str] = set()
    signature_event_types = _collect_event_types_from_signatures(sigs)
    for i, s in enumerate(sigs):
        pfx = f"signatures[{i}]"
        if not isinstance(s, dict):
            msgs.append(LintMessage("ERROR", "SIGNATURE_NOT_MAPPING", "Signature must be a mapping", path=pfx))
            continue

        sid = s.get("id")
        if not isinstance(sid, str) or not sid.strip():
            msgs.append(LintMessage("ERROR", "SIGNATURE_ID_MISSING", "Signature requires non-empty id", path=f"{pfx}.id"))
            continue

        if sid in seen_ids:
            msgs.append(LintMessage("ERROR", "DUPLICATE_SIGNATURE_ID", f"Duplicate signature id: {sid}", path=f"{pfx}.id"))
        seen_ids.add(sid)

        et = s.get("event_type")
        if not isinstance(et, str) or not et.strip():
            msgs.append(
                LintMessage(
                    "ERROR",
                    "SIGNATURE_EVENT_TYPE_MISSING",
                    f"Signature '{sid}' requires non-empty event_type",
                    path=f"{pfx}.event_type",
                )
            )

        sev = s.get("severity", "info")
        if isinstance(sev, str) and sev.lower() not in ALLOWED_SEVERITIES:
            msgs.append(
                LintMessage(
                    "ERROR",
                    "SIGNATURE_SEVERITY_UNKNOWN",
                    f"Signature '{sid}' has unknown severity '{sev}' (allowed: {sorted(ALLOWED_SEVERITIES)})",
                    path=f"{pfx}.severity",
                )
            )

        patterns = s.get("patterns")
        if not isinstance(patterns, list) or not patterns:
            msgs.append(
                LintMessage(
                    "ERROR",
                    "SIGNATURE_PATTERNS_MISSING",
                    f"Signature '{sid}' requires patterns: [ ... ]",
                    path=f"{pfx}.patterns",
                )
            )
            continue

        for j, pat in enumerate(patterns):
            if not isinstance(pat, str) or not pat:
                msgs.append(LintMessage("ERROR", "PATTERN_NOT_STRING", f"Pattern must be a non-empty string", path=f"{pfx}.patterns[{j}]"))
                continue
            try:
                re.compile(pat)
            except Exception as e:
                msgs.append(
                    LintMessage(
                        "ERROR",
                        "REGEX_COMPILE_FAILED",
                        f"Signature '{sid}' pattern[{j}] failed to compile: {e}",
                        path=f"{pfx}.patterns[{j}]",
                    )
                )

        capture = s.get("capture") or {}
        if capture is not None and not isinstance(capture, dict):
            msgs.append(LintMessage("ERROR", "CAPTURE_NOT_MAPPING", f"capture must be a mapping", path=f"{pfx}.capture"))
        elif isinstance(capture, dict):
            for k, v in capture.items():
                if not isinstance(v, str) or not v:
                    msgs.append(LintMessage("ERROR", "CAPTURE_REGEX_NOT_STRING", f"capture.{k} must be a non-empty string", path=f"{pfx}.capture.{k}"))
                    continue
                try:
                    re.compile(v)
                except Exception as e:
                    msgs.append(LintMessage("ERROR", "CAPTURE_REGEX_COMPILE_FAILED", f"Signature '{sid}' capture.{k} failed to compile: {e}", path=f"{pfx}.capture.{k}"))

        # Low-effort guardrail: warn on extremely generic patterns
        for j, pat in enumerate(patterns):
            if isinstance(pat, str) and pat.strip().lower() in {"error", "failed", "timeout"}:
                msgs.append(
                    LintMessage(
                        "WARN",
                        "PATTERN_TOO_GENERIC",
                        f"Signature '{sid}' pattern[{j}] looks overly generic ('{pat}'); consider anchoring to component/context",
                        path=f"{pfx}.patterns[{j}]",
                    )
                )

    # Cross references: context_grouping.chatty_event_types
    cg = raw.get("context_grouping")
    if isinstance(cg, dict):
        chatty = cg.get("chatty_event_types")
        if chatty is not None and not isinstance(chatty, list):
            msgs.append(LintMessage("ERROR", "CHATTY_NOT_LIST", "context_grouping.chatty_event_types must be a list", path="context_grouping.chatty_event_types"))
        elif isinstance(chatty, list):
            for i, et in enumerate(chatty):
                if not isinstance(et, str) or not et:
                    msgs.append(LintMessage("ERROR", "CHATTY_BAD_ITEM", "chatty_event_types entries must be strings", path=f"context_grouping.chatty_event_types[{i}]"))
                    continue
                if et not in signature_event_types:
                    msgs.append(LintMessage("WARN", "UNKNOWN_EVENT_TYPE", f"chatty_event_types references unknown event_type '{et}'", path=f"context_grouping.chatty_event_types[{i}]"))

    # Cross references: timeline.include_event_types
    tl = raw.get("timeline")
    if isinstance(tl, dict):
        inc = tl.get("include_event_types")
        if inc is not None and not isinstance(inc, list):
            msgs.append(LintMessage("ERROR", "TIMELINE_INCLUDE_NOT_LIST", "timeline.include_event_types must be a list", path="timeline.include_event_types"))
        elif isinstance(inc, list):
            for i, et in enumerate(inc):
                if not isinstance(et, str) or not et:
                    msgs.append(LintMessage("ERROR", "TIMELINE_INCLUDE_BAD_ITEM", "include_event_types entries must be strings", path=f"timeline.include_event_types[{i}]"))
                    continue
                if et not in signature_event_types:
                    msgs.append(LintMessage("WARN", "UNKNOWN_EVENT_TYPE", f"timeline.include_event_types references unknown event_type '{et}'", path=f"timeline.include_event_types[{i}]"))

    # Cross references: heuristics thresholds/supports
    for et, pth in _iter_heuristic_event_types(raw):
        if et not in signature_event_types:
            msgs.append(LintMessage("WARN", "UNKNOWN_EVENT_TYPE", f"{pth} references unknown event_type '{et}'", path=pth))

    # Suggestion: signatures not referenced anywhere
    referenced: Set[str] = set()
    if isinstance(cg, dict) and isinstance(cg.get("chatty_event_types"), list):
        referenced |= {x for x in cg.get("chatty_event_types") if isinstance(x, str)}
    if isinstance(tl, dict) and isinstance(tl.get("include_event_types"), list):
        referenced |= {x for x in tl.get("include_event_types") if isinstance(x, str)}
    referenced |= {et for et, _ in _iter_heuristic_event_types(raw)}

    # Only warn if the event_type never appears in any of those lists.
    # This can be intentional (supporting evidence only), so it's a WARN.
    for et in sorted(signature_event_types):
        if et not in referenced:
            msgs.append(
                LintMessage(
                    "WARN",
                    "EVENT_TYPE_UNREFERENCED",
                    f"event_type '{et}' is not referenced by clustering, heuristics, or timeline include list (may be intentional)",
                    path="signatures[*].event_type",
                )
            )

    return msgs


def format_lint_messages(msgs: List[LintMessage]) -> str:
    lines: List[str] = []
    for m in msgs:
        loc = f" ({m.path})" if m.path else ""
        lines.append(f"[{m.level}] {m.code}: {m.message}{loc}")
    return "\n".join(lines)


def has_errors(msgs: List[LintMessage]) -> bool:
    return any(m.level == "ERROR" for m in msgs)
