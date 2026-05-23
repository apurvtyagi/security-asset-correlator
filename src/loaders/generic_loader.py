"""
src/loaders/generic_loader.py

Config-driven loader for any security tool source.

Adding a new source requires:
  1. Add a block under ``sources:`` in config/source_mappings.yaml
  2. If the tool uses an unusual field shape, add a @transform function here
  3. No new Python files or classes needed

Architecture:
  GenericLoader reads source_mappings.yaml at instantiation time and maps
  source-specific JSON fields → RawAssetRecord using field rules and named
  transform functions. The LoaderRegistry auto-discovers any source defined
  in the YAML, so callers use LoaderRegistry.get("mytool") for both Python-
  registered and YAML-configured sources.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from ..correlator.models import RawAssetRecord, VulnerabilityFinding
from .base_loader import BaseLoader

logger = logging.getLogger(__name__)

_DEFAULT_MAPPINGS = Path(__file__).parent.parent / "config" / "source_mappings.yaml"

# ---------------------------------------------------------------------------
# Transform registry
# ---------------------------------------------------------------------------

_TRANSFORMS: dict[str, Callable[..., Any]] = {}


def transform(name: str) -> Callable:
    """Decorator that registers a function as a named transform."""
    def decorator(fn: Callable) -> Callable:
        _TRANSFORMS[name] = fn
        return fn
    return decorator


def _apply(name: str, value: Any, source: str = "") -> Any:
    fn = _TRANSFORMS.get(name)
    if fn is None:
        raise KeyError(
            f"Unknown transform '{name}'. "
            f"Available: {sorted(_TRANSFORMS.keys())}"
        )
    import inspect
    sig = inspect.signature(fn)
    if len(sig.parameters) > 1:
        return fn(value, source)
    return fn(value)


# ---------------------------------------------------------------------------
# General-purpose transforms
# ---------------------------------------------------------------------------

@transform("iso_datetime")
def _iso_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).rstrip("Z")).replace(tzinfo=UTC)
    except (ValueError, AttributeError):
        return None


@transform("ensure_list")
def _ensure_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if v]
    return [value] if value else []


@transform("first_of_list")
def _first_of_list(value: Any) -> str | None:
    if isinstance(value, list):
        return next((s for s in value if s), None)
    return value if value else None


@transform("dedup_list")
def _dedup_list(value: Any) -> list:
    """Deduplicate a list while preserving order and filtering empty values."""
    if not isinstance(value, list):
        return []
    seen: set = set()
    result = []
    for v in value:
        if v and v not in seen:
            seen.add(v)
            result.append(v)
    return result


# ---------------------------------------------------------------------------
# Source-specific asset field transforms
# ---------------------------------------------------------------------------

@transform("aws_platform_to_os")
def _aws_platform(value: Any) -> str:
    return "Windows" if str(value or "").lower() == "windows" else "Linux"


@transform("az_to_region")
def _az_to_region(value: Any) -> str | None:
    """Strip trailing AZ letter: 'us-east-1a' → 'us-east-1'."""
    if not value:
        return None
    s = str(value)
    return s[:-1] if s and s[-1].isalpha() else s


@transform("aws_tags_list")
def _aws_tags_list(value: Any) -> dict:
    """[{Key, Value}] → {key: value}"""
    if not isinstance(value, list):
        return {}
    return {
        tag["Key"]: tag.get("Value", "")
        for tag in value
        if isinstance(tag, dict) and "Key" in tag
    }


@transform("edr_tags")
def _edr_tags(value: Any) -> dict:
    """CrowdStrike tag list ['SensorGroupingTags/prod'] OR dict → canonical tags dict."""
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {str(v): True for v in value if v}
    return {}


@transform("mac_to_list")
def _mac_to_list(value: Any) -> list[str]:
    """Single MAC string → [normalized lowercase colon-separated MAC]."""
    if not value:
        return []
    return [str(value).replace("-", ":").lower()]


@transform("tenable_tags")
def _tenable_tags(value: Any) -> dict:
    """[{category, value}] → {category: value}"""
    if not isinstance(value, list):
        return {}
    return {
        entry.get("category", "tag"): entry.get("value", "")
        for entry in value
        if isinstance(entry, dict)
    }


@transform("qualys_tags")
def _qualys_tags(value: Any) -> dict:
    """{TAG: [{NAME, ID}]} → {name: id}. Handles single-dict XML-to-JSON quirk."""
    if not isinstance(value, dict):
        return {}
    tag_root = value.get("TAG", [])
    if isinstance(tag_root, dict):
        tag_root = [tag_root]
    return {
        tag.get("NAME", ""): tag.get("ID", "")
        for tag in tag_root
        if isinstance(tag, dict) and tag.get("NAME")
    }


# ---------------------------------------------------------------------------
# Vulnerability extraction transforms
# These accept (value, source) so the finding carries the correct source name.
# ---------------------------------------------------------------------------

@transform("tenable_vulns")
def _tenable_vulns(value: Any, source: str = "tenable") -> list[VulnerabilityFinding]:
    if not isinstance(value, list):
        return []
    findings = []
    for v in value:
        cves = v.get("cve", [])
        if isinstance(cves, str):
            cves = [cves]
        findings.append(VulnerabilityFinding(
            source=source,
            source_finding_id=str(v.get("plugin_id", "")),
            cve_ids=cves,
            severity=v.get("severity"),
            cvss3_base=v.get("cvss3_base_score"),
            title=v.get("plugin_name"),
            first_found=_iso_datetime(v.get("first_found")),
            last_found=_iso_datetime(v.get("last_found")),
            status=v.get("state", "open"),
        ))
    return findings


_QUALYS_SEVERITY: dict[int, str] = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}


@transform("qualys_vulns")
def _qualys_vulns(value: Any, source: str = "qualys") -> list[VulnerabilityFinding]:
    """Handles the Qualys XML-to-JSON quirk where DETECTION can be dict or list."""
    if not isinstance(value, dict):
        return []
    raw_list = value.get("DETECTION", [])
    if isinstance(raw_list, dict):
        raw_list = [raw_list]
    findings = []
    for d in raw_list:
        cves = _qualys_cve_list(d.get("CVE_LIST", {}))
        severity_int = d.get("SEVERITY", 0)
        raw_status = (d.get("STATUS") or "").lower()
        findings.append(VulnerabilityFinding(
            source=source,
            source_finding_id=str(d.get("QID", "")),
            cve_ids=cves,
            severity=_QUALYS_SEVERITY.get(severity_int, "info"),
            cvss3_base=d.get("CVSS3_BASE"),
            title=d.get("TITLE"),
            first_found=_iso_datetime(d.get("FIRST_FOUND_DATETIME")),
            last_found=_iso_datetime(d.get("LAST_FOUND_DATETIME")),
            status="open" if raw_status in ("active", "open") else "potential",
        ))
    return findings


def _qualys_cve_list(cve_list: Any) -> list[str]:
    """CVE_LIST.CVE can be a string, list, or nested dict in Qualys output."""
    if isinstance(cve_list, str):
        return [cve_list]
    if isinstance(cve_list, list):
        return cve_list
    if isinstance(cve_list, dict):
        raw = cve_list.get("CVE", [])
        if isinstance(raw, str):
            return [raw]
        if isinstance(raw, list):
            return raw
    return []


# ---------------------------------------------------------------------------
# Field resolution helpers
# ---------------------------------------------------------------------------

def _resolve(record: dict, path: str) -> Any:
    """Resolve a dot-separated field path: 'Placement.AvailabilityZone'."""
    value: Any = record
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
        if value is None:
            return None
    return value


def _apply_rule(record: dict, rule: Any, source: str = "") -> Any:
    """
    Apply a single field mapping rule to a raw source record.

    Supported rule shapes (from source_mappings.yaml):
      "SourceField"                              — direct lookup, returns scalar
      ["Field1", "Field2"]                       — pick non-empty into list
      {field: "F", transform: "fn"}             — extract then transform
      {pick: ["F1", "F2"], transform: "fn"}     — pick list then transform
      {value: "literal"}                         — hardcoded static value
    """
    if isinstance(rule, str):
        return _resolve(record, rule)

    if isinstance(rule, list):
        return [v for f in rule if (v := _resolve(record, f)) is not None and str(v).strip()]

    if isinstance(rule, dict):
        if "value" in rule:
            return rule["value"]

        tfn = rule.get("transform")

        if "pick" in rule:
            values = [v for f in rule["pick"] if (v := _resolve(record, f)) is not None and str(v).strip()]
            return _apply(tfn, values, source) if tfn else (values or None)

        if "field" in rule:
            val = _resolve(record, rule["field"])
            return _apply(tfn, val, source) if tfn is not None else val

    return None


# ---------------------------------------------------------------------------
# GenericLoader
# ---------------------------------------------------------------------------

class GenericLoader(BaseLoader):
    """
    YAML-config-driven loader.

    Reads a source's field mapping from config/source_mappings.yaml and maps
    source-specific JSON to RawAssetRecord without any source-specific Python code.

    To add a new security tool:
      1. Add a block under ``sources:`` in config/source_mappings.yaml
      2. Add a @transform function here only if the tool has an unusual field shape
      3. No new Python files required — LoaderRegistry.get("mytool") just works
    """

    def __init__(self, source: str, mapping: dict) -> None:
        self.SOURCE = source
        self._mapping = mapping

    @classmethod
    def from_config(
        cls,
        source: str,
        mappings_file: Path = _DEFAULT_MAPPINGS,
    ) -> GenericLoader:
        """Load the mapping for ``source`` from the YAML config file."""
        with open(mappings_file) as fh:
            config = yaml.safe_load(fh)
        sources = config.get("sources", {})
        key = source.lower()
        if key not in sources:
            available = ", ".join(sorted(sources.keys()))
            raise KeyError(
                f"Source '{source}' not found in {mappings_file}. "
                f"Configured: {available or '(none)'}"
            )
        return cls(key, sources[key])

    def load(self, raw_records: list[dict] | dict) -> list[RawAssetRecord]:
        if isinstance(raw_records, dict):
            raw_records = [raw_records]
        result = []
        for rec in raw_records:
            try:
                result.append(self._normalize(rec))
            except Exception:
                logger.exception("GenericLoader[%s] failed on record", self.SOURCE)
        return result

    def _normalize(self, record: dict) -> RawAssetRecord:
        m = self._mapping
        source_id_field = m.get("source_id_field", "id")
        default_asset_type = m.get("asset_type", "unknown")

        kwargs: dict[str, Any] = {
            "source": self.SOURCE,
            "source_id": str(
                _resolve(record, source_id_field)
                or f"{self.SOURCE}-{hash(str(record))}"
            ),
            "asset_type": default_asset_type,
            "raw": record,
        }

        for canonical_field, rule in m.get("fields", {}).items():
            value = _apply_rule(record, rule, self.SOURCE)
            if value is not None:
                kwargs[canonical_field] = value

        vuln_cfg = m.get("vulnerabilities")
        if vuln_cfg:
            vuln_data = _resolve(record, vuln_cfg["field"])
            if vuln_data is not None:
                tfn = vuln_cfg.get("transform")
                if tfn:
                    vulns = _apply(tfn, vuln_data, self.SOURCE)
                    if vulns:
                        kwargs["vulnerabilities"] = vulns

        return RawAssetRecord(**kwargs)
