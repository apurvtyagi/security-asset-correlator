"""
tests/test_matcher.py

Tests for the 4-layer matching engine.
Covers hard-ID match, hostname match, IP match, metadata match, combination scoring,
and multi-canonical store selection.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta

from src.correlator.models import CanonicalAsset, RawAssetRecord
from src.correlator.matcher import MatchEngine
from src.resolvers.hostname_resolver import HostnameResolver
from src.resolvers.ip_resolver import IPResolver


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> MatchEngine:
    thresholds = {
        "merge_threshold": 0.70,
        "flag_threshold": 0.50,
        "combination_weights": {"hostname": 0.60, "ip": 0.40},
    }
    return MatchEngine(
        thresholds=thresholds,
        hostname_resolver=HostnameResolver(),
        ip_resolver=IPResolver(),
    )


@pytest.fixture
def prod_api_canonical() -> CanonicalAsset:
    """Canonical asset representing the prod-api-07 server after AWS ingestion."""
    return CanonicalAsset(
        canonical_id="canon-001",
        instance_id="i-0a1b2c3d4e5f67890",
        agent_id="agent-uuid-1234",
        hostname="prod-api-07",
        ip_addresses=["10.0.4.22", "52.14.100.200"],
        mac_addresses=["06:ab:cd:ef:01:23"],
        os_name="Amazon Linux 2023",
        cloud_region="us-east-1",
        cloud_account_id="123456789012",
        last_seen=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Layer 1: Hard identifier matching
# ---------------------------------------------------------------------------

class TestHardIDMatching:
    def test_instance_id_match_returns_1_0(self, engine, prod_api_canonical):
        record = RawAssetRecord(
            source="tenable", source_id="t-001",
            instance_id="i-0a1b2c3d4e5f67890",
        )
        asset, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is not None
        assert result.confidence == 1.0
        assert result.match_layer == "hard_id"
        assert result.matched_on["field"] == "instance_id"

    def test_agent_id_match_returns_1_0(self, engine, prod_api_canonical):
        record = RawAssetRecord(
            source="aws", source_id="a-001",
            agent_id="agent-uuid-1234",
        )
        asset, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is not None
        assert result.confidence == 1.0
        assert result.matched_on["field"] == "agent_id"

    def test_real_mac_match_returns_0_95(self, engine, prod_api_canonical):
        record = RawAssetRecord(
            source="qualys", source_id="q-001",
            mac_addresses=["06:ab:cd:ef:01:23"],
        )
        asset, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is not None
        assert result.confidence == 0.95
        assert result.match_layer == "hard_id"

    def test_virtual_mac_excluded_from_hard_match(self, engine):
        # VMware OUI — should not be treated as a hard identifier
        canonical = CanonicalAsset(
            canonical_id="canon-vmware",
            mac_addresses=["00:50:56:ab:cd:ef"],
        )
        record = RawAssetRecord(
            source="qualys", source_id="q-002",
            mac_addresses=["00:50:56:ab:cd:ef"],
        )
        _, result = engine.find_best_match(record, [canonical])
        # Virtual MAC should NOT produce a 0.95 hard_id match
        assert result is None or (result.match_layer == "hard_id" and result.confidence < 0.95)

    def test_different_instance_ids_do_not_match(self, engine, prod_api_canonical):
        record = RawAssetRecord(
            source="aws", source_id="a-002",
            instance_id="i-DIFFERENT99999999",
        )
        _, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is None or result.confidence < 0.50

    def test_none_hard_ids_do_not_match(self, engine, prod_api_canonical):
        record = RawAssetRecord(source="tenable", source_id="t-002")
        # No hard IDs set → fall through to lower layers
        _, result = engine.find_best_match(record, [prod_api_canonical])
        # Without hostname/IP overlap either, no match expected
        assert result is None or result.confidence < 0.50


# ---------------------------------------------------------------------------
# Layer 2: Hostname matching
# ---------------------------------------------------------------------------

class TestHostnameMatching:
    def test_exact_hostname_match(self, engine, prod_api_canonical):
        record = RawAssetRecord(
            source="qualys", source_id="q-003",
            hostnames=["prod-api-07"],
        )
        _, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is not None
        # Hostname-only: 0.85 * 0.60 = 0.51 → flag zone but not None
        assert result.confidence >= 0.50

    def test_hostname_suffix_stripped(self, engine, prod_api_canonical):
        record = RawAssetRecord(
            source="edr", source_id="e-001",
            hostnames=["prod-api-07.internal"],
        )
        _, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is not None
        assert result.confidence >= 0.50

    def test_hostname_corp_suffix_stripped(self, engine, prod_api_canonical):
        record = RawAssetRecord(
            source="edr", source_id="e-002",
            hostnames=["prod-api-07.corp"],
        )
        _, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is not None
        assert result.confidence >= 0.50

    def test_generic_hostname_gets_low_confidence(self, engine):
        canonical = CanonicalAsset(
            canonical_id="canon-generic",
            hostname="ip-10-0-4-22",
            last_seen=datetime.now(timezone.utc),
        )
        record = RawAssetRecord(
            source="tenable", source_id="t-003",
            hostnames=["ip-10-0-4-22"],
        )
        _, result = engine.find_best_match(record, [canonical])
        # Generic hostname: 0.45 * 0.60 = 0.27 → below flag threshold
        assert result is None or result.confidence < 0.50

    def test_different_hostname_no_match(self, engine, prod_api_canonical):
        record = RawAssetRecord(
            source="edr", source_id="e-003",
            hostnames=["completely-different-host"],
        )
        _, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is None or result.confidence < 0.50


# ---------------------------------------------------------------------------
# Layer 3: IP matching
# ---------------------------------------------------------------------------

class TestIPMatching:
    def test_ip_resolver_public_ip_scores_0_75(self):
        """IPResolver directly: public IP overlap → base confidence 0.75."""
        resolver = IPResolver()
        result = resolver.score_ip_overlap(
            ["52.14.100.200"],
            ["52.14.100.200"],
            datetime.now(timezone.utc),
        )
        assert result is not None
        assert abs(result.confidence - 0.75) < 0.01

    def test_ip_resolver_private_ip_scores_0_60(self):
        """IPResolver directly: private IP overlap → base confidence 0.60."""
        resolver = IPResolver()
        result = resolver.score_ip_overlap(
            ["10.0.4.22"],
            ["10.0.4.22"],
            datetime.now(timezone.utc),
        )
        assert result is not None
        assert abs(result.confidence - 0.60) < 0.01

    def test_ip_resolver_stale_reduces_confidence(self):
        """Staleness decay should reduce the IP match confidence."""
        resolver = IPResolver()
        fresh_result = resolver.score_ip_overlap(
            ["10.0.4.22"], ["10.0.4.22"],
            datetime.now(timezone.utc),
        )
        stale_result = resolver.score_ip_overlap(
            ["10.0.4.22"], ["10.0.4.22"],
            datetime.now(timezone.utc) - timedelta(days=20),
        )
        assert stale_result is not None and fresh_result is not None
        assert stale_result.confidence < fresh_result.confidence

    def test_combined_hostname_private_ip_reaches_flag_threshold(self, engine, prod_api_canonical):
        """hostname (0.85*0.60=0.51) + private IP (0.60*0.40=0.24) = 0.75 ≥ 0.50 flag."""
        prod_api_canonical.ip_addresses = ["10.0.4.22"]
        record = RawAssetRecord(
            source="qualys", source_id="q-004",
            hostnames=["prod-api-07"],
            ip_addresses=["10.0.4.22"],
        )
        _, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is not None
        assert result.confidence >= 0.50

    def test_ip_alone_below_flag_threshold_returns_none(self, engine, prod_api_canonical):
        """IP-only match score (0.30) is below flag_threshold (0.50) → no result."""
        record = RawAssetRecord(
            source="tenable", source_id="t-004",
            ip_addresses=["52.14.100.200"],
        )
        _, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is None

    def test_no_shared_ips_no_ip_match(self, engine, prod_api_canonical):
        record = RawAssetRecord(
            source="tenable", source_id="t-005",
            ip_addresses=["10.99.99.99"],
        )
        _, result = engine.find_best_match(record, [prod_api_canonical])
        # No hostname, no hard ID, no shared IPs — may fall to metadata or None
        assert result is None or result.confidence < 0.50


# ---------------------------------------------------------------------------
# Layer 4: Metadata matching
# ---------------------------------------------------------------------------

class TestMetadataMatching:
    def test_full_metadata_match_below_merge_threshold(self, engine):
        canonical = CanonicalAsset(
            canonical_id="canon-meta",
            os_name="Amazon Linux 2023",
            cloud_region="us-east-1",
            cloud_account_id="123456789012",
        )
        record = RawAssetRecord(
            source="qualys", source_id="q-006",
            os_name="Amazon Linux 2023",
            cloud_region="us-east-1",
            cloud_account_id="123456789012",
        )
        _, result = engine.find_best_match(record, [canonical])
        # Max metadata = 0.20+0.15+0.15 = 0.50 → at most at flag threshold, never merges
        if result:
            assert result.confidence <= 0.50
            assert result.confidence >= 0.50  # exactly 0.50 with all three signals
            assert result.match_layer == "metadata"

    def test_os_only_metadata_does_not_reach_flag_threshold(self, engine):
        canonical = CanonicalAsset(
            canonical_id="canon-meta2",
            os_name="Amazon Linux 2023",
        )
        record = RawAssetRecord(
            source="qualys", source_id="q-007",
            os_name="Amazon Linux 2",  # Different version — normalizes to same family
        )
        _, result = engine.find_best_match(record, [canonical])
        if result:
            assert result.confidence <= 0.20

    def test_insufficient_metadata_returns_none(self, engine):
        canonical = CanonicalAsset(
            canonical_id="canon-meta3",
            os_name="Amazon Linux 2023",
        )
        record = RawAssetRecord(
            source="qualys", source_id="q-008",
            os_name="Windows Server 2022",  # Different family entirely
        )
        _, result = engine.find_best_match(record, [canonical])
        assert result is None


# ---------------------------------------------------------------------------
# Combined scoring and multi-store behavior
# ---------------------------------------------------------------------------

class TestCombinedAndMultiStore:
    def test_hostname_plus_public_ip_exceeds_merge_threshold(self, engine, prod_api_canonical):
        """hostname=0.85*0.60=0.51 + public_ip=0.75*0.40=0.30 = 0.81 ≥ 0.70"""
        record = RawAssetRecord(
            source="qualys", source_id="q-009",
            hostnames=["prod-api-07"],
            ip_addresses=["52.14.100.200"],
        )
        _, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is not None
        assert result.confidence >= 0.70
        assert result.match_layer == "hostname+ip"

    def test_best_match_selected_from_multiple_canonicals(self, engine, prod_api_canonical):
        other = CanonicalAsset(
            canonical_id="canon-other",
            hostname="unrelated-host",
            ip_addresses=["10.99.0.1"],
        )
        record = RawAssetRecord(
            source="edr", source_id="e-best",
            instance_id="i-0a1b2c3d4e5f67890",
        )
        matched, result = engine.find_best_match(record, [other, prod_api_canonical])
        assert matched is not None
        assert matched.canonical_id == "canon-001"
        assert result.confidence == 1.0

    def test_empty_store_returns_none(self, engine):
        record = RawAssetRecord(source="aws", source_id="a-empty")
        asset, result = engine.find_best_match(record, [])
        assert asset is None
        assert result is None

    def test_record_with_no_identifiers_returns_none(self, engine, prod_api_canonical):
        record = RawAssetRecord(source="qualys", source_id="q-blank")
        _, result = engine.find_best_match(record, [prod_api_canonical])
        assert result is None
