"""
src/correlator/merger.py

Merges a matched RawAssetRecord into an existing CanonicalAsset.

Merge strategies by field type:
- Scalar fields (hostname, os_name, etc.): authority-ranked conflict resolution
- List fields (ip_addresses, mac_addresses): union, deduplicated, order-preserving
- Tags: union with source namespace prefix (e.g. "aws:env" = "prod")
- last_seen: always take the maximum (most recent) value
- Vulnerabilities: deduplicate by CVE ID, union sources, take earliest first_found
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from .conflict_resolver import ConflictResolver
from .models import (
    CanonicalAsset,
    CanonicalVulnerability,
    RawAssetRecord,
    VulnerabilityFinding,
)

logger = logging.getLogger(__name__)


class RecordMerger:
    """
    Merges RawAssetRecords into CanonicalAssets using field-level authority config.
    All operations mutate the canonical asset in place and return it.
    """

    # Scalar fields subject to authority-based conflict resolution.
    # Note: "hostname" is handled separately below because RawAssetRecord stores
    # hostnames as a list (hostnames) while CanonicalAsset has a single hostname.
    SCALAR_FIELDS = [
        "instance_id", "agent_id", "os_name", "os_version",
        "cloud_region", "cloud_account_id", "asset_type",
    ]
    # List fields that are always union-merged across sources
    LIST_FIELDS = ["ip_addresses", "mac_addresses"]

    def __init__(self, authority_config: dict[str, dict[str, int]]):
        self.conflict_resolver = ConflictResolver(authority_config)

    def merge(self, canonical: CanonicalAsset, record: RawAssetRecord) -> CanonicalAsset:
        """Merge record into canonical. Mutates canonical in place and returns it."""
        # Capture the dominant source BEFORE appending the new record so conflict
        # attribution correctly reflects who previously owned the field values.
        current_source = self._dominant_source(canonical)

        if record.source not in canonical.contributing_sources:
            canonical.contributing_sources.append(record.source)
        canonical.source_records.append(record)

        for field_name in self.SCALAR_FIELDS:
            incoming_value = getattr(record, field_name, None)
            if incoming_value is None:
                continue
            current_value = getattr(canonical, field_name, None)
            if current_value is None:
                setattr(canonical, field_name, incoming_value)
                continue
            if current_value != incoming_value:
                resolved, _ = self.conflict_resolver.resolve(
                    canonical, field_name,
                    current_value, current_source,
                    incoming_value, record.source,
                )
                setattr(canonical, field_name, resolved)

        # Hostname: RawAssetRecord.hostnames is a list; use the first non-empty entry.
        incoming_hostname = next((h for h in record.hostnames if h), None)
        if incoming_hostname is not None:
            if canonical.hostname is None:
                canonical.hostname = incoming_hostname
            elif canonical.hostname != incoming_hostname:
                resolved, _ = self.conflict_resolver.resolve(
                    canonical, "hostname",
                    canonical.hostname, current_source,
                    incoming_hostname, record.source,
                )
                canonical.hostname = resolved

        for field_name in self.LIST_FIELDS:
            existing: list = getattr(canonical, field_name, []) or []
            incoming: list = getattr(record, field_name, []) or []
            # dict.fromkeys preserves insertion order while deduplicating
            merged = list(dict.fromkeys(existing + incoming))
            setattr(canonical, field_name, merged)

        # Tags: namespace each key with its source to avoid cross-source collisions
        for k, v in record.tags.items():
            canonical.tags[f"{record.source}:{k}"] = v

        # last_seen: take the most recent observation across all sources
        if record.last_seen:
            if canonical.last_seen is None or record.last_seen > canonical.last_seen:
                canonical.last_seen = record.last_seen

        if record.vulnerabilities:
            self._merge_vulnerabilities(canonical, record.vulnerabilities)

        canonical.updated_at = datetime.now(timezone.utc)
        return canonical

    def _merge_vulnerabilities(
        self,
        canonical: CanonicalAsset,
        incoming: list[VulnerabilityFinding],
    ) -> None:
        """
        Deduplicate vulnerability findings by CVE ID.
        Multiple findings for the same CVE are collapsed into one CanonicalVulnerability
        with all source tools listed, the earliest first_found, and the highest CVSS score.
        """
        by_cve: dict[str, CanonicalVulnerability] = {
            v.cve_id: v for v in canonical.vulnerabilities
        }

        for finding in incoming:
            for cve_id in finding.cve_ids:
                if cve_id in by_cve:
                    existing = by_cve[cve_id]
                    if finding.source not in existing.sources:
                        existing.sources.append(finding.source)
                    existing.raw_finding_count += 1
                    # Earliest first_found wins
                    if finding.first_found and (
                        existing.first_found is None or finding.first_found < existing.first_found
                    ):
                        existing.first_found = finding.first_found
                    # Latest last_found wins
                    if finding.last_found and (
                        existing.last_found is None or finding.last_found > existing.last_found
                    ):
                        existing.last_found = finding.last_found
                    # "open" status takes precedence over "potential"
                    if finding.status == "open" and existing.status != "open":
                        existing.status = "open"
                    # Keep highest CVSS score
                    if finding.cvss3_base is not None and (
                        existing.cvss3_base is None or finding.cvss3_base > existing.cvss3_base
                    ):
                        existing.cvss3_base = finding.cvss3_base
                else:
                    by_cve[cve_id] = CanonicalVulnerability(
                        cve_id=cve_id,
                        severity=finding.severity,
                        cvss3_base=finding.cvss3_base,
                        title=finding.title,
                        sources=[finding.source],
                        first_found=finding.first_found,
                        last_found=finding.last_found,
                        status=finding.status,
                        raw_finding_count=1,
                    )

        canonical.vulnerabilities = list(by_cve.values())

    def _dominant_source(self, canonical: CanonicalAsset) -> str:
        """Return the source that most recently contributed to this canonical asset."""
        if canonical.source_records:
            return canonical.source_records[-1].source
        if canonical.contributing_sources:
            return canonical.contributing_sources[-1]
        return "unknown"
