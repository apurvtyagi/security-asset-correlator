"""
src/correlator/models.py

Shared data models used across the entire correlator package.
All modules import from here to avoid circular dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class VulnerabilityFinding:
    """A single vulnerability finding from one source tool before deduplication."""
    source: str
    source_finding_id: str
    cve_ids: list[str] = field(default_factory=list)
    severity: str | None = None          # critical | high | medium | low | info
    cvss3_base: float | None = None
    title: str | None = None
    first_found: datetime | None = None
    last_found: datetime | None = None
    status: str = "open"                    # open | potential | fixed
    component: str | None = None        # Affected package/component for grouping


@dataclass
class CanonicalVulnerability:
    """
    Deduplicated vulnerability for a canonical asset.
    Combines findings for the same CVE across all sources.
    """
    cve_id: str
    severity: str | None = None
    cvss3_base: float | None = None
    title: str | None = None
    sources: list[str] = field(default_factory=list)
    first_found: datetime | None = None
    last_found: datetime | None = None
    status: str = "open"
    raw_finding_count: int = 0


@dataclass
class RawAssetRecord:
    """
    Normalized record produced by a source loader.
    Represents a single asset as seen by one security tool.
    """
    source: str                              # "aws" | "edr" | "tenable" | "qualys"
    source_id: str                           # Tool's internal identifier
    instance_id: str | None = None       # Cloud instance ID (hard identifier)
    agent_id: str | None = None          # EDR agent UUID (hard identifier)
    mac_addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)   # Normalized by loader
    ip_addresses: list[str] = field(default_factory=list)
    os_name: str | None = None
    os_version: str | None = None
    cloud_region: str | None = None
    cloud_account_id: str | None = None
    tags: dict = field(default_factory=dict)
    last_seen: datetime | None = None
    asset_type: str | None = None
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    raw: dict = field(default_factory=dict) # Original payload for lineage


@dataclass
class MatchResult:
    """Result of comparing a RawAssetRecord against one CanonicalAsset."""
    confidence: float
    match_layer: str    # "hard_id" | "hostname" | "ip" | "metadata" | "hostname+ip"
    matched_on: dict    # e.g. {"field": "instance_id", "value": "i-0a1b2c3d"}


@dataclass
class CanonicalAsset:
    """
    Authoritative asset record built by merging one or more RawAssetRecords.
    One CanonicalAsset per real-world entity regardless of how many tools observe it.
    """
    canonical_id: str                        # Stable internal UUID
    instance_id: str | None = None
    agent_id: str | None = None
    hostname: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    mac_addresses: list[str] = field(default_factory=list)
    os_name: str | None = None
    os_version: str | None = None
    cloud_region: str | None = None
    cloud_account_id: str | None = None
    tags: dict = field(default_factory=dict)
    last_seen: datetime | None = None
    asset_type: str = "unknown"

    # Lifecycle state
    status: str = "active"  # active | possibly_offline | offline | terminated | archived

    # Lineage and audit trail
    contributing_sources: list[str] = field(default_factory=list)
    source_records: list[RawAssetRecord] = field(default_factory=list)
    conflicts: list[dict] = field(default_factory=list)
    vulnerabilities: list[CanonicalVulnerability] = field(default_factory=list)
    match_confidence: float = 1.0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Risk scoring
    risk_score: float = 0.0          # 0.0–10.0 composite risk score
    risk_severity: str = "low"       # critical | high | medium | low
    risk_factors: dict = field(default_factory=dict)  # score breakdown

    # Drift tracking — field changes detected between ingestions
    drift_events: list[dict] = field(default_factory=list)
