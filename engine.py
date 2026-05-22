"""
src/correlator/engine.py

Core correlation orchestration. Loads normalized asset records from all sources,
runs layered matching, and produces a canonical asset store.

This is pseudocode with real structure — not all external dependencies are wired.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import uuid
import logging

logger = logging.getLogger(__name__)

MERGE_THRESHOLD = 0.70      # Confidence >= this → merge records
FLAG_THRESHOLD = 0.50       # Confidence >= this → flag for review, don't merge


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class RawAssetRecord:
    """Normalized record from a single source tool."""
    source: str                              # "aws" | "edr" | "tenable" | "qualys"
    source_id: str                           # Tool's internal identifier
    instance_id: Optional[str] = None       # Cloud instance ID (hard identifier)
    agent_id: Optional[str] = None          # EDR agent UUID (hard identifier)
    mac_addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)   # Normalized
    ip_addresses: list[str] = field(default_factory=list)
    os_name: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_account_id: Optional[str] = None
    tags: dict = field(default_factory=dict)
    last_seen: Optional[datetime] = None
    raw: dict = field(default_factory=dict) # Original payload for lineage


@dataclass
class CanonicalAsset:
    """Authoritative asset record merging one or more RawAssetRecords."""
    canonical_id: str                        # Stable internal UUID
    instance_id: Optional[str] = None
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_addresses: list[str] = field(default_factory=list)
    mac_addresses: list[str] = field(default_factory=list)
    os_name: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_account_id: Optional[str] = None
    tags: dict = field(default_factory=dict)
    last_seen: Optional[datetime] = None
    asset_type: str = "unknown"

    # Lineage and audit
    contributing_sources: list[str] = field(default_factory=list)
    source_records: list[RawAssetRecord] = field(default_factory=list)
    conflicts: list[dict] = field(default_factory=list)  # Field disagreements
    match_confidence: float = 1.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class MatchResult:
    confidence: float
    match_layer: str    # "hard_id" | "hostname" | "ip" | "metadata"
    matched_on: dict    # {"field": "instance_id", "value": "i-0a1b2c3d"}


# ---------------------------------------------------------------------------
# Layered Matching Engine
# ---------------------------------------------------------------------------

class MatchEngine:
    """
    Matches incoming RawAssetRecord against existing canonical assets.
    Returns the best match and confidence score, or None if no match found.

    Match layers execute in order. First layer to exceed MERGE_THRESHOLD
    short-circuits — no need to continue.
    """

    def find_best_match(
        self,
        record: RawAssetRecord,
        canonical_store: list[CanonicalAsset],
    ) -> tuple[Optional[CanonicalAsset], Optional[MatchResult]]:

        best_asset = None
        best_result = None

        for canonical in canonical_store:
            result = self._score_match(record, canonical)
            if result and (best_result is None or result.confidence > best_result.confidence):
                best_result = result
                best_asset = canonical
                if best_result.confidence >= MERGE_THRESHOLD:
                    break  # Hard match found — stop searching

        return best_asset, best_result

    def _score_match(
        self,
        record: RawAssetRecord,
        canonical: CanonicalAsset,
    ) -> Optional[MatchResult]:

        # Layer 1: Hard identifiers (cloud instance ID, EDR agent UUID, MAC)
        hard_match = self._match_hard_ids(record, canonical)
        if hard_match:
            return hard_match

        # Layer 2: Hostname match (normalized)
        hostname_match = self._match_hostname(record, canonical)
        if hostname_match and hostname_match.confidence >= MERGE_THRESHOLD:
            return hostname_match

        # Layer 3: IP cross-reference (staleness-weighted)
        ip_match = self._match_ips(record, canonical)

        # Combine hostname and IP partial confidence scores
        combined_confidence = 0.0
        if hostname_match:
            combined_confidence += hostname_match.confidence * 0.6
        if ip_match:
            combined_confidence += ip_match.confidence * 0.4

        if combined_confidence >= FLAG_THRESHOLD:
            return MatchResult(
                confidence=combined_confidence,
                match_layer="hostname+ip",
                matched_on={
                    "hostname": hostname_match.matched_on if hostname_match else None,
                    "ip": ip_match.matched_on if ip_match else None,
                }
            )

        # Layer 4: Metadata correlation (OS + region + tags)
        return self._match_metadata(record, canonical)

    def _match_hard_ids(
        self, record: RawAssetRecord, canonical: CanonicalAsset
    ) -> Optional[MatchResult]:
        """Confidence 1.0 — unambiguous identity proof."""

        if record.instance_id and canonical.instance_id:
            if record.instance_id == canonical.instance_id:
                return MatchResult(
                    confidence=1.0,
                    match_layer="hard_id",
                    matched_on={"field": "instance_id", "value": record.instance_id}
                )

        if record.agent_id and canonical.agent_id:
            if record.agent_id == canonical.agent_id:
                return MatchResult(
                    confidence=1.0,
                    match_layer="hard_id",
                    matched_on={"field": "agent_id", "value": record.agent_id}
                )

        # MAC address match — careful with shared virtual MACs (VMware, cloud)
        if record.mac_addresses and canonical.mac_addresses:
            shared_macs = set(record.mac_addresses) & set(canonical.mac_addresses)
            if shared_macs and not self._is_virtual_mac(list(shared_macs)[0]):
                return MatchResult(
                    confidence=0.95,
                    match_layer="hard_id",
                    matched_on={"field": "mac_address", "value": list(shared_macs)[0]}
                )

        return None

    def _match_hostname(
        self, record: RawAssetRecord, canonical: CanonicalAsset
    ) -> Optional[MatchResult]:
        """
        Confidence 0.85 for exact normalized hostname match.
        Penalize for generic hostnames (ip-10-x-x-x, localhost, etc.).
        """
        if not record.hostnames or not canonical.hostname:
            return None

        canonical_norm = self._normalize_hostname(canonical.hostname)
        for raw_hostname in record.hostnames:
            norm = self._normalize_hostname(raw_hostname)
            if norm == canonical_norm:
                confidence = 0.85
                if self._is_generic_hostname(norm):
                    confidence = 0.45  # Don't auto-merge on "ip-10-0-1-5"
                return MatchResult(
                    confidence=confidence,
                    match_layer="hostname",
                    matched_on={"field": "hostname", "value": norm}
                )

        return None

    def _match_ips(
        self, record: RawAssetRecord, canonical: CanonicalAsset
    ) -> Optional[MatchResult]:
        """
        Confidence 0.60–0.75 based on IP overlap and staleness.
        Private IPs weighted lower than public IPs.
        """
        if not record.ip_addresses or not canonical.ip_addresses:
            return None

        shared_ips = set(record.ip_addresses) & set(canonical.ip_addresses)
        if not shared_ips:
            return None

        # Private IP ranges are less unique — penalize
        shared_private = [ip for ip in shared_ips if self._is_private_ip(ip)]
        shared_public = [ip for ip in shared_ips if not self._is_private_ip(ip)]

        if shared_public:
            confidence = 0.75
        elif shared_private:
            confidence = 0.60
        else:
            return None

        # Staleness decay: if canonical.last_seen > 48h ago, reduce confidence
        if canonical.last_seen:
            age_hours = (datetime.now(timezone.utc) - canonical.last_seen).seconds / 3600
            if age_hours > 48:
                confidence *= max(0.5, 1.0 - (age_hours / 720))  # Decay over 30 days

        return MatchResult(
            confidence=confidence,
            match_layer="ip",
            matched_on={"field": "ip_addresses", "value": list(shared_ips)}
        )

    def _match_metadata(
        self, record: RawAssetRecord, canonical: CanonicalAsset
    ) -> Optional[MatchResult]:
        """
        Confidence up to 0.55. Combination of OS + region + tags.
        Never sufficient alone to trigger merge — only to flag for review.
        """
        score = 0.0
        matched_on = {}

        if record.os_name and canonical.os_name:
            if self._normalize_os(record.os_name) == self._normalize_os(canonical.os_name):
                score += 0.20
                matched_on["os_name"] = record.os_name

        if record.cloud_region and canonical.cloud_region:
            if record.cloud_region == canonical.cloud_region:
                score += 0.15
                matched_on["cloud_region"] = record.cloud_region

        if record.cloud_account_id and canonical.cloud_account_id:
            if record.cloud_account_id == canonical.cloud_account_id:
                score += 0.15
                matched_on["cloud_account_id"] = record.cloud_account_id

        if score < 0.20:
            return None

        return MatchResult(
            confidence=score,
            match_layer="metadata",
            matched_on=matched_on
        )

    # Utility methods

    def _normalize_hostname(self, hostname: str) -> str:
        hostname = hostname.lower().strip()
        for suffix in [".local", ".internal", ".corp", ".lan", "-prod", "-dev", "-staging"]:
            if hostname.endswith(suffix):
                hostname = hostname[: -len(suffix)]
        return hostname

    def _is_generic_hostname(self, hostname: str) -> bool:
        generic_patterns = ["ip-", "ec2-", "localhost", "ubuntu", "centos", "windows"]
        return any(hostname.startswith(p) for p in generic_patterns)

    def _is_private_ip(self, ip: str) -> bool:
        # Simplified — use ipaddress module in production
        return ip.startswith(("10.", "172.16.", "192.168."))

    def _is_virtual_mac(self, mac: str) -> bool:
        # VMware OUI prefixes — these aren't unique per machine
        virtual_ouis = ["00:50:56", "00:0c:29", "00:05:69"]
        return any(mac.lower().startswith(oui) for oui in virtual_ouis)

    def _normalize_os(self, os_name: str) -> str:
        os_name = os_name.lower()
        if "windows" in os_name:
            return "windows"
        if "ubuntu" in os_name or "debian" in os_name:
            return "debian_family"
        if "rhel" in os_name or "centos" in os_name or "amazon linux" in os_name:
            return "rhel_family"
        return os_name


# ---------------------------------------------------------------------------
# Merger: builds canonical record from matched sources
# ---------------------------------------------------------------------------

class RecordMerger:
    """
    Given a canonical asset and a new raw record that matched it,
    updates the canonical record using source confidence rankings.
    Logs any field-level conflicts.
    """

    # Source authority rank per field (lower = more authoritative)
    SOURCE_AUTHORITY = {
        "instance_id":      {"aws": 1, "edr": 5, "tenable": 10, "qualys": 10},
        "hostname":         {"edr": 1, "aws": 2, "tenable": 4, "qualys": 4},
        "os_name":          {"edr": 1, "tenable": 2, "qualys": 2, "aws": 3},
        "cloud_region":     {"aws": 1, "azure": 1, "gcp": 1, "edr": 8},
        "cloud_account_id": {"aws": 1, "azure": 1, "gcp": 1},
    }

    def merge(self, canonical: CanonicalAsset, record: RawAssetRecord) -> CanonicalAsset:
        canonical.contributing_sources.append(record.source)
        canonical.source_records.append(record)

        # Scalar fields — authority-ranked conflict resolution
        for field_name in ["instance_id", "hostname", "os_name", "cloud_region", "cloud_account_id"]:
            new_value = getattr(record, field_name, None)
            if new_value is None:
                continue

            current_value = getattr(canonical, field_name, None)
            if current_value is None:
                setattr(canonical, field_name, new_value)
                continue

            if current_value != new_value:
                canonical.conflicts.append({
                    "field": field_name,
                    "existing_value": current_value,
                    "existing_source": self._find_source_for_field(canonical, field_name),
                    "incoming_value": new_value,
                    "incoming_source": record.source,
                    "resolution": "kept_existing",  # Updated below if we replace
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

                # Replace if incoming source is more authoritative
                authority = self.SOURCE_AUTHORITY.get(field_name, {})
                current_authority = authority.get(self._find_source_for_field(canonical, field_name), 99)
                incoming_authority = authority.get(record.source, 99)
                if incoming_authority < current_authority:
                    setattr(canonical, field_name, new_value)
                    canonical.conflicts[-1]["resolution"] = "replaced_with_higher_authority"

        # List fields — union merge
        for field_name in ["ip_addresses", "mac_addresses"]:
            existing = getattr(canonical, field_name, [])
            incoming = getattr(record, field_name, [])
            merged = list(set(existing + incoming))
            setattr(canonical, field_name, merged)

        # Tags — union with source namespace prefix
        for k, v in record.tags.items():
            namespaced_key = f"{record.source}:{k}"
            canonical.tags[namespaced_key] = v

        # last_seen — always take max
        if record.last_seen:
            if canonical.last_seen is None or record.last_seen > canonical.last_seen:
                canonical.last_seen = record.last_seen

        canonical.updated_at = datetime.now(timezone.utc)
        return canonical

    def _find_source_for_field(self, canonical: CanonicalAsset, field_name: str) -> str:
        """Walk source records in reverse to find which source set this field."""
        for rec in reversed(canonical.source_records):
            val = getattr(rec, field_name, None)
            if val is not None:
                return rec.source
        return "unknown"


# ---------------------------------------------------------------------------
# Correlation Engine (orchestration)
# ---------------------------------------------------------------------------

class CorrelationEngine:
    def __init__(self):
        self.match_engine = MatchEngine()
        self.merger = RecordMerger()
        self.canonical_store: list[CanonicalAsset] = []
        self.flagged_for_review: list[dict] = []

    def process(self, records: list[RawAssetRecord]) -> list[CanonicalAsset]:
        """
        Process a batch of normalized raw records.
        Returns the updated canonical store.
        """
        logger.info(f"Processing {len(records)} raw asset records")

        for record in records:
            canonical, match_result = self.match_engine.find_best_match(
                record, self.canonical_store
            )

            if match_result and match_result.confidence >= MERGE_THRESHOLD:
                # High-confidence match: merge into existing canonical
                logger.debug(
                    f"MERGE [{match_result.confidence:.2f}] {record.source}:{record.source_id} "
                    f"→ canonical:{canonical.canonical_id} via {match_result.match_layer}"
                )
                self.merger.merge(canonical, record)

            elif match_result and match_result.confidence >= FLAG_THRESHOLD:
                # Ambiguous match: create new canonical but flag for human review
                new_canonical = self._create_canonical(record, match_result.confidence)
                self.canonical_store.append(new_canonical)
                self.flagged_for_review.append({
                    "new_canonical_id": new_canonical.canonical_id,
                    "possible_duplicate_of": canonical.canonical_id,
                    "confidence": match_result.confidence,
                    "match_layer": match_result.match_layer,
                    "matched_on": match_result.matched_on,
                    "flagged_at": datetime.now(timezone.utc).isoformat(),
                })
                logger.warning(
                    f"FLAG [{match_result.confidence:.2f}] {record.source}:{record.source_id} "
                    f"may duplicate canonical:{canonical.canonical_id}"
                )

            else:
                # No match: create new canonical asset
                new_canonical = self._create_canonical(record, 1.0)
                self.canonical_store.append(new_canonical)
                logger.debug(
                    f"NEW canonical:{new_canonical.canonical_id} "
                    f"from {record.source}:{record.source_id}"
                )

        logger.info(
            f"Correlation complete. "
            f"Canonical assets: {len(self.canonical_store)}, "
            f"Flagged for review: {len(self.flagged_for_review)}"
        )
        return self.canonical_store

    def _create_canonical(self, record: RawAssetRecord, confidence: float) -> CanonicalAsset:
        return CanonicalAsset(
            canonical_id=str(uuid.uuid4()),
            instance_id=record.instance_id,
            agent_id=record.agent_id,
            hostname=record.hostnames[0] if record.hostnames else None,
            ip_addresses=record.ip_addresses[:],
            mac_addresses=record.mac_addresses[:],
            os_name=record.os_name,
            cloud_region=record.cloud_region,
            cloud_account_id=record.cloud_account_id,
            tags=dict(record.tags),
            last_seen=record.last_seen,
            contributing_sources=[record.source],
            source_records=[record],
            match_confidence=confidence,
        )
