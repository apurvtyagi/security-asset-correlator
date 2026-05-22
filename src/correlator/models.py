"""
src/correlator/models.py

Shared data models used across the entire correlator package.
All modules import from here to avoid circular dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class VulnerabilityFinding:
    """A single vulnerability finding from one source tool before deduplication."""
    source: str
    source_finding_id: str
    cve_ids: list[str] = field(default_factory=list)
    severity: Optional[str] = None          # critical | high | medium | low | info
    cvss3_base: Optional[float] = None
    title: Optional[str] = None
    first_found: Optional[datetime] = None
    last_found: Optional[datetime] = None
    status: str = "open"                    # open | potential | fixed
    component: Optional[str] = None        # Affected package/component for grouping


@dataclass
class CanonicalVulnerability:
    """
    Deduplicated vulnerability for a canonical asset.
    Combines findings for the same CVE across all sources.
    """
    cve_id: str
    severity: Optional[str] = None
    cvss3_base: Optional[float] = None
    title: Optional[str] = None
    sources: list[str] = field(default_factory=list)
    first_found: Optional[datetime] = None
    last_found: Optional[datetime] = None
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
    instance_id: Optional[str] = None       # Cloud instance ID (hard identifier)
    agent_id: Optional[str] = None          # EDR agent UUID (hard identifier)
    mac_addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)   # Normalized by loader
    ip_addresses: list[str] = field(default_factory=list)
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_account_id: Optional[str] = None
    tags: dict = field(default_factory=dict)
    last_seen: Optional[datetime] = None
    asset_type: Optional[str] = None
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
    instance_id: Optional[str] = None
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_addresses: list[str] = field(default_factory=list)
    mac_addresses: list[str] = field(default_factory=list)
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_account_id: Optional[str] = None
    tags: dict = field(default_factory=dict)
    last_seen: Optional[datetime] = None
    asset_type: str = "unknown"

    # Lifecycle state
    status: str = "active"  # active | possibly_offline | offline | terminated | archived

    # Lineage and audit trail
    contributing_sources: list[str] = field(default_factory=list)
    source_records: list[RawAssetRecord] = field(default_factory=list)
    conflicts: list[dict] = field(default_factory=list)     # Field-level disagreements
    vulnerabilities: list[CanonicalVulnerability] = field(default_factory=list)
    match_confidence: float = 1.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
