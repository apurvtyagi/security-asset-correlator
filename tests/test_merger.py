"""
tests/test_merger.py

Tests for canonical record construction and vulnerability deduplication.
Covers scalar field merging, list union, tag namespacing, last_seen logic,
and cross-source CVE deduplication.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from src.correlator.models import (
    CanonicalAsset,
    CanonicalVulnerability,
    RawAssetRecord,
    VulnerabilityFinding,
)
from src.correlator.merger import RecordMerger


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_AUTHORITY = {
    "hostname":         {"edr": 1, "aws": 2, "tenable": 4, "qualys": 4},
    "instance_id":      {"aws": 1, "edr": 5, "tenable": 10, "qualys": 10},
    "os_name":          {"edr": 1, "tenable": 2, "qualys": 2, "aws": 3},
    "cloud_region":     {"aws": 1, "edr": 8},
    "cloud_account_id": {"aws": 1},
    "agent_id":         {"edr": 1},
    "asset_type":       {"aws": 1, "edr": 2},
}


@pytest.fixture
def merger() -> RecordMerger:
    return RecordMerger(_AUTHORITY)


def _aws_canonical(**overrides) -> CanonicalAsset:
    """Build a canonical asset as if it was created from an AWS record."""
    base = CanonicalAsset(
        canonical_id="canon-001",
        instance_id="i-abc123",
        hostname="prod-api-07",
        ip_addresses=["10.0.4.22"],
        os_name="Amazon Linux 2023",
        cloud_region="us-east-1",
        cloud_account_id="123456789012",
        asset_type="server",
        contributing_sources=["aws"],
        source_records=[
            RawAssetRecord(
                source="aws", source_id="aws-001",
                instance_id="i-abc123", hostnames=["prod-api-07"],
                ip_addresses=["10.0.4.22"], os_name="Amazon Linux 2023",
                cloud_region="us-east-1", cloud_account_id="123456789012",
                asset_type="server",
            )
        ],
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


# ---------------------------------------------------------------------------
# Scalar field merging
# ---------------------------------------------------------------------------

class TestScalarMerge:
    def test_higher_authority_source_replaces_hostname(self, merger):
        canonical = _aws_canonical()  # aws rank=2 for hostname
        edr_record = RawAssetRecord(
            source="edr", source_id="edr-001",
            hostnames=["prod-api-07-edr"],  # edr rank=1 — more authoritative
        )
        result = merger.merge(canonical, edr_record)
        assert result.hostname == "prod-api-07-edr"
        assert len(result.conflicts) == 1
        assert result.conflicts[0]["resolution"] == "replaced_with_higher_authority"

    def test_lower_authority_source_does_not_replace_hostname(self, merger):
        canonical = _aws_canonical()  # aws rank=2 for hostname
        tenable_record = RawAssetRecord(
            source="tenable", source_id="t-001",
            hostnames=["prod-api-07-tenable"],  # tenable rank=4 — less authoritative
        )
        result = merger.merge(canonical, tenable_record)
        assert result.hostname == "prod-api-07"
        assert result.conflicts[0]["resolution"] == "kept_existing"

    def test_equal_authority_keeps_existing(self, merger):
        # Switch canonical to have been set by tenable (rank=4)
        canonical = _aws_canonical()
        canonical.source_records = [
            RawAssetRecord(source="tenable", source_id="t-000", hostnames=["prod-api-07"])
        ]
        canonical.contributing_sources = ["tenable"]
        qualys_record = RawAssetRecord(
            source="qualys", source_id="q-001",
            hostnames=["prod-api-07-qualys"],  # qualys rank=4, same as tenable
        )
        result = merger.merge(canonical, qualys_record)
        assert result.hostname == "prod-api-07"

    def test_none_incoming_does_not_overwrite_existing(self, merger):
        canonical = _aws_canonical()
        record = RawAssetRecord(
            source="qualys", source_id="q-002",
            # hostnames is empty list by default — no incoming hostname
            os_name=None,
            cloud_region=None,
        )
        result = merger.merge(canonical, record)
        assert result.hostname == "prod-api-07"
        assert result.os_name == "Amazon Linux 2023"
        assert result.cloud_region == "us-east-1"

    def test_none_existing_filled_by_incoming(self, merger):
        canonical = _aws_canonical()
        canonical.agent_id = None
        record = RawAssetRecord(
            source="edr", source_id="edr-002",
            agent_id="new-agent-uuid",
        )
        result = merger.merge(canonical, record)
        assert result.agent_id == "new-agent-uuid"

    def test_conflict_logged_with_full_metadata(self, merger):
        canonical = _aws_canonical()
        record = RawAssetRecord(
            source="edr", source_id="edr-003",
            hostnames=["prod-api-07-edr"],
        )
        merger.merge(canonical, record)
        conflict = canonical.conflicts[0]
        assert conflict["field"] == "hostname"
        assert conflict["existing_source"] == "aws"
        assert conflict["incoming_source"] == "edr"
        assert "timestamp" in conflict
        assert "resolved_value" in conflict


# ---------------------------------------------------------------------------
# List field merging
# ---------------------------------------------------------------------------

class TestListMerge:
    def test_ip_addresses_union_merged(self, merger):
        canonical = _aws_canonical()
        record = RawAssetRecord(
            source="qualys", source_id="q-003",
            ip_addresses=["10.0.4.23", "52.14.100.200"],
        )
        result = merger.merge(canonical, record)
        assert "10.0.4.22" in result.ip_addresses
        assert "10.0.4.23" in result.ip_addresses
        assert "52.14.100.200" in result.ip_addresses

    def test_ip_deduplication_on_merge(self, merger):
        canonical = _aws_canonical()
        record = RawAssetRecord(
            source="edr", source_id="edr-004",
            ip_addresses=["10.0.4.22"],  # Already present
        )
        merger.merge(canonical, record)
        assert canonical.ip_addresses.count("10.0.4.22") == 1

    def test_mac_addresses_union_merged(self, merger):
        canonical = _aws_canonical()
        canonical.mac_addresses = ["aa:bb:cc:dd:ee:ff"]
        record = RawAssetRecord(
            source="edr", source_id="edr-005",
            mac_addresses=["11:22:33:44:55:66"],
        )
        result = merger.merge(canonical, record)
        assert "aa:bb:cc:dd:ee:ff" in result.mac_addresses
        assert "11:22:33:44:55:66" in result.mac_addresses


# ---------------------------------------------------------------------------
# Tag merging
# ---------------------------------------------------------------------------

class TestTagMerge:
    def test_tags_namespaced_by_source(self, merger):
        canonical = _aws_canonical()
        record = RawAssetRecord(
            source="edr", source_id="edr-006",
            tags={"group": "prod-servers", "status": "active"},
        )
        result = merger.merge(canonical, record)
        assert "edr:group" in result.tags
        assert result.tags["edr:group"] == "prod-servers"
        assert "edr:status" in result.tags

    def test_tags_from_multiple_sources_coexist(self, merger):
        canonical = _aws_canonical()
        merger.merge(canonical, RawAssetRecord(source="aws", source_id="aws-2", tags={"env": "prod"}))
        merger.merge(canonical, RawAssetRecord(source="edr", source_id="edr-7", tags={"env": "production"}))
        assert "aws:env" in canonical.tags
        assert "edr:env" in canonical.tags
        assert canonical.tags["aws:env"] == "prod"
        assert canonical.tags["edr:env"] == "production"


# ---------------------------------------------------------------------------
# last_seen merging
# ---------------------------------------------------------------------------

class TestLastSeenMerge:
    def test_newer_last_seen_replaces_older(self, merger):
        canonical = _aws_canonical()
        canonical.last_seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
        record = RawAssetRecord(
            source="edr", source_id="edr-008",
            last_seen=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )
        result = merger.merge(canonical, record)
        assert result.last_seen == datetime(2026, 6, 1, tzinfo=timezone.utc)

    def test_older_last_seen_does_not_replace_newer(self, merger):
        canonical = _aws_canonical()
        canonical.last_seen = datetime(2026, 6, 1, tzinfo=timezone.utc)
        record = RawAssetRecord(
            source="qualys", source_id="q-004",
            last_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        result = merger.merge(canonical, record)
        assert result.last_seen == datetime(2026, 6, 1, tzinfo=timezone.utc)

    def test_none_last_seen_filled_from_incoming(self, merger):
        canonical = _aws_canonical()
        canonical.last_seen = None
        ts = datetime(2026, 5, 22, tzinfo=timezone.utc)
        record = RawAssetRecord(source="edr", source_id="edr-009", last_seen=ts)
        merger.merge(canonical, record)
        assert canonical.last_seen == ts


# ---------------------------------------------------------------------------
# Contributing sources tracking
# ---------------------------------------------------------------------------

class TestContributingSourcesTracking:
    def test_source_added_on_first_merge(self, merger):
        canonical = _aws_canonical()
        assert "aws" in canonical.contributing_sources
        merger.merge(canonical, RawAssetRecord(source="edr", source_id="edr-010"))
        assert "edr" in canonical.contributing_sources

    def test_duplicate_source_not_added_twice(self, merger):
        canonical = _aws_canonical()
        merger.merge(canonical, RawAssetRecord(source="aws", source_id="aws-dup"))
        assert canonical.contributing_sources.count("aws") == 1


# ---------------------------------------------------------------------------
# Vulnerability deduplication
# ---------------------------------------------------------------------------

class TestVulnerabilityDeduplication:
    def test_same_cve_from_two_sources_deduplicated(self, merger):
        canonical = _aws_canonical()
        canonical.vulnerabilities = [
            CanonicalVulnerability(
                cve_id="CVE-2024-53907", severity="critical", cvss3_base=9.8,
                sources=["tenable"],
                first_found=datetime(2026, 4, 10, tzinfo=timezone.utc),
                last_found=datetime(2026, 5, 22, tzinfo=timezone.utc),
                raw_finding_count=1,
            )
        ]
        record = RawAssetRecord(
            source="qualys", source_id="q-vuln-001",
            vulnerabilities=[
                VulnerabilityFinding(
                    source="qualys", source_finding_id="qid-376211",
                    cve_ids=["CVE-2024-53907"],
                    severity="critical", cvss3_base=9.8,
                    first_found=datetime(2026, 4, 11, tzinfo=timezone.utc),
                    last_found=datetime(2026, 5, 19, tzinfo=timezone.utc),
                    status="open",
                )
            ],
        )
        merger.merge(canonical, record)

        matches = [v for v in canonical.vulnerabilities if v.cve_id == "CVE-2024-53907"]
        assert len(matches) == 1
        assert "tenable" in matches[0].sources
        assert "qualys" in matches[0].sources
        assert matches[0].raw_finding_count == 2

    def test_different_cves_not_merged(self, merger):
        canonical = _aws_canonical()
        canonical.vulnerabilities = [
            CanonicalVulnerability(cve_id="CVE-2024-53907", sources=["tenable"], raw_finding_count=1)
        ]
        record = RawAssetRecord(
            source="qualys", source_id="q-vuln-002",
            vulnerabilities=[
                VulnerabilityFinding(
                    source="qualys", source_finding_id="qid-380100",
                    cve_ids=["CVE-2025-10001"],
                    severity="medium",
                )
            ],
        )
        merger.merge(canonical, record)
        assert len(canonical.vulnerabilities) == 2

    def test_first_found_takes_earliest_across_sources(self, merger):
        canonical = _aws_canonical()
        canonical.vulnerabilities = [
            CanonicalVulnerability(
                cve_id="CVE-2024-47081", sources=["tenable"],
                first_found=datetime(2026, 4, 10, tzinfo=timezone.utc),
                raw_finding_count=1,
            )
        ]
        record = RawAssetRecord(
            source="qualys", source_id="q-vuln-003",
            vulnerabilities=[
                VulnerabilityFinding(
                    source="qualys", source_finding_id="qid-378901",
                    cve_ids=["CVE-2024-47081"],
                    # Earlier than the tenable date
                    first_found=datetime(2026, 3, 1, tzinfo=timezone.utc),
                )
            ],
        )
        merger.merge(canonical, record)
        vuln = next(v for v in canonical.vulnerabilities if v.cve_id == "CVE-2024-47081")
        assert vuln.first_found == datetime(2026, 3, 1, tzinfo=timezone.utc)

    def test_open_status_overrides_potential(self, merger):
        canonical = _aws_canonical()
        canonical.vulnerabilities = [
            CanonicalVulnerability(
                cve_id="CVE-2025-10001", sources=["qualys"],
                status="potential", raw_finding_count=1,
            )
        ]
        record = RawAssetRecord(
            source="tenable", source_id="t-vuln-001",
            vulnerabilities=[
                VulnerabilityFinding(
                    source="tenable", source_finding_id="p-999",
                    cve_ids=["CVE-2025-10001"],
                    status="open",
                )
            ],
        )
        merger.merge(canonical, record)
        vuln = next(v for v in canonical.vulnerabilities if v.cve_id == "CVE-2025-10001")
        assert vuln.status == "open"

    def test_highest_cvss_score_retained(self, merger):
        canonical = _aws_canonical()
        canonical.vulnerabilities = [
            CanonicalVulnerability(
                cve_id="CVE-2024-53907", sources=["qualys"],
                cvss3_base=9.0, raw_finding_count=1,
            )
        ]
        record = RawAssetRecord(
            source="tenable", source_id="t-vuln-002",
            vulnerabilities=[
                VulnerabilityFinding(
                    source="tenable", source_finding_id="p-207456",
                    cve_ids=["CVE-2024-53907"],
                    cvss3_base=9.8,  # Higher score
                )
            ],
        )
        merger.merge(canonical, record)
        vuln = next(v for v in canonical.vulnerabilities if v.cve_id == "CVE-2024-53907")
        assert vuln.cvss3_base == 9.8
