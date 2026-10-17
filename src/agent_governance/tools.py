"""Tool admission checks for MCP-style tool definitions.

Screens a tool before it is added to a charter: hidden instructions in the
description, and schema or server-identity drift against a previously admitted
manifest. This is a deterministic scan, not a model classifier.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


class ToolAdmissionError(ValueError):
    """The tool was not admitted. `findings` lists every reason."""

    def __init__(self, findings: list[str]):
        self.findings = findings
        super().__init__("; ".join(findings))


@dataclass(frozen=True)
class ToolManifest:
    """The definition a tool server presented, separate from the action policy."""

    name: str
    description: str
    input_schema: dict[str, Any]
    server_id: str | None = None


# Phrases that show up in tool-poisoning descriptions. Each pair is a stable
# finding label plus a case-insensitive pattern.
_INSTRUCTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore previous instructions",
     re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions", re.I)),
    ("disregard policy",
     re.compile(r"disregard\s+(your|the|all)\s+(rules|policy|charter|instructions)", re.I)),
    ("conceal from operator",
     re.compile(r"do\s+not\s+(tell|inform|alert|notify)\s+the\s+(user|human|operator)", re.I)),
    ("hidden markup",
     re.compile(r"<\s*(important|system|hidden)\b", re.I)),
    ("html comment",
     re.compile(r"<!--.*?-->", re.I | re.S)),
    ("role override",
     re.compile(r"you\s+are\s+now\s+", re.I)),
    ("override policy",
     re.compile(r"override\s+(the\s+)?(system|safety|policy)", re.I)),
)

# Characters used to hide text from a reviewer while a model still reads them.
_STEALTH_CODEPOINTS = {
    0x200B, 0x200C, 0x200D, 0xFEFF,  # zero-width / BOM
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi embedding and override
    0x2066, 0x2067, 0x2068, 0x2069,
}


def scan_tool_description(text: str) -> list[str]:
    """Return findings for hidden instructions or stealth characters."""
    if not isinstance(text, str):
        return ["tool description is not text"]
    findings: list[str] = []
    for label, pattern in _INSTRUCTION_PATTERNS:
        if pattern.search(text):
            findings.append(label)
    stealth = sorted({
        f"U+{ord(ch):04X}"
        for ch in text
        if ord(ch) in _STEALTH_CODEPOINTS or 0xE0000 <= ord(ch) <= 0xE007F
    })
    if stealth:
        findings.append("hidden unicode in description: " + ", ".join(stealth))
    return findings


def scan_schema_drift(baseline: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Return findings when `current` changes the contract `baseline` pinned."""
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        return ["schema is not an object"]
    findings: list[str] = []
    if baseline.get("type") != current.get("type"):
        findings.append(f"schema type changed: {baseline.get('type')} -> {current.get('type')}")

    b_props = baseline.get("properties") or {}
    c_props = current.get("properties") or {}
    if not isinstance(b_props, dict) or not isinstance(c_props, dict):
        findings.append("schema properties are not an object")
        return findings

    for name in sorted(set(b_props) - set(c_props)):
        findings.append(f"property removed: {name}")
    for name in sorted(set(b_props) & set(c_props)):
        b_type = b_props[name].get("type") if isinstance(b_props[name], dict) else None
        c_type = c_props[name].get("type") if isinstance(c_props[name], dict) else None
        if b_type != c_type:
            findings.append(f"property type changed: {name} {b_type} -> {c_type}")

    b_required = set(baseline.get("required") or [])
    c_required = set(current.get("required") or [])
    for name in sorted(b_required - c_required):
        findings.append(f"required field dropped: {name}")
    for name in sorted(c_required - b_required):
        findings.append(f"required field added: {name}")

    if baseline.get("additionalProperties") is False and current.get("additionalProperties") is not False:
        findings.append("additionalProperties widened")
    return findings


def screen_tool(manifest: ToolManifest, baseline: ToolManifest | None = None) -> list[str]:
    """Screen one manifest. With a baseline, also check identity and schema drift."""
    findings = scan_tool_description(manifest.description)
    if baseline is None:
        return findings
    if baseline.name != manifest.name:
        findings.append(f"tool name changed: {baseline.name} -> {manifest.name}")
    if baseline.server_id and manifest.server_id != baseline.server_id:
        findings.append(
            f"server identity changed: {baseline.server_id} -> {manifest.server_id}"
        )
    findings.extend(scan_schema_drift(baseline.input_schema, manifest.input_schema))
    return findings


def schema_digest(schema: dict[str, Any]) -> str:
    encoded = json.dumps(schema, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()
