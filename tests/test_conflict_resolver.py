"""
tests/test_conflict_resolver.py

Tests for field conflict resolution logic and conflict audit logging.
Verifies authority rank ordering, tie-breaking, unknown sources, and log structure.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from src.correlator.models import CanonicalAsset
from src.correlator.conflict_resolver import ConflictResolver


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_AUTHORITY = {
    "hostname":         {"edr": 1, "aws": 2, "tenable": 4, "qualys": 4},
    "instance_id":      {"aws": 1, "edr": 5, "tenable": 10, "qualys": 10},
    "os_name":          {"edr": 1, "tenable": 2, "qualys": 2, "aws": 3},
    "cloud_region":     {"aws": 1, "edr": 8},
    "cloud_account_id": {"aws": 1},
}


@pytest.fixture
def resolver() -> ConflictResolver:
    return ConflictResolver(_AUTHORITY)


@pytest.fixture
def canonical() -> CanonicalAsset:
    return CanonicalAsset(canonical_id="test-001")


# ---------------------------------------------------------------------------
# Resolution logic
# ---------------------------------------------------------------------------

class TestResolutionLogic:
    def test_higher_authority_replaces_value(self, resolver, canonical):
        # edr (rank 1) beats aws (rank 2) for hostname
        value, resolution = resolver.resolve(
            canonical, "hostname",
            current_value="prod-api-07",    current_source="aws",
            incoming_value="prod-api-07-edr", incoming_source="edr",
        )
        assert value == "prod-api-07-edr"
        assert resolution == "replaced_with_higher_authority"

    def test_lower_authority_keeps_existing(self, resolver, canonical):
        # edr (rank 1) beats tenable (rank 4) for hostname
        value, resolution = resolver.resolve(
            canonical, "hostname",
            current_value="prod-api-07",       current_source="edr",
            incoming_value="prod-api-07-scan",  incoming_source="tenable",
        )
        assert value == "prod-api-07"
        assert resolution == "kept_existing"

    def test_equal_authority_keeps_existing(self, resolver, canonical):
        # tenable (rank 4) vs qualys (rank 4) — tie goes to current
        value, resolution = resolver.resolve(
            canonical, "hostname",
            current_value="prod-api-07-a", current_source="tenable",
            incoming_value="prod-api-07-b", incoming_source="qualys",
        )
        assert value == "prod-api-07-a"
        assert resolution == "kept_existing"

    def test_unknown_source_gets_rank_99(self, resolver, canonical):
        # "custom_tool" not in authority config → rank 99; edr has rank 1 → replaces
        value, resolution = resolver.resolve(
            canonical, "hostname",
            current_value="old-hostname",    current_source="custom_tool",
            incoming_value="new-hostname",   incoming_source="edr",
        )
        assert value == "new-hostname"
        assert resolution == "replaced_with_higher_authority"

    def test_both_sources_unknown_keeps_existing(self, resolver, canonical):
        # Both unknown → rank 99 tie → keep existing
        value, resolution = resolver.resolve(
            canonical, "hostname",
            current_value="old", current_source="tool_a",
            incoming_value="new", incoming_source="tool_b",
        )
        assert value == "old"
        assert resolution == "kept_existing"

    def test_unconfigured_field_keeps_existing(self, resolver, canonical):
        # Field not in authority config → both get rank 99 → keep existing
        value, resolution = resolver.resolve(
            canonical, "unconfigured_field",
            current_value="existing",  current_source="edr",
            incoming_value="incoming", incoming_source="aws",
        )
        assert value == "existing"
        assert resolution == "kept_existing"

    def test_authoritative_cloud_region(self, resolver, canonical):
        # aws (rank 1) vs edr (rank 8) for cloud_region
        value, _ = resolver.resolve(
            canonical, "cloud_region",
            current_value="us-east-1", current_source="edr",
            incoming_value="eu-west-1", incoming_source="aws",
        )
        assert value == "eu-west-1"  # aws wins on cloud_region

    def test_os_name_edr_beats_aws(self, resolver, canonical):
        # edr (rank 1) beats aws (rank 3) for os_name
        value, resolution = resolver.resolve(
            canonical, "os_name",
            current_value="Amazon Linux 2",     current_source="aws",
            incoming_value="Amazon Linux 2023", incoming_source="edr",
        )
        assert value == "Amazon Linux 2023"
        assert resolution == "replaced_with_higher_authority"


# ---------------------------------------------------------------------------
# Conflict log structure
# ---------------------------------------------------------------------------

class TestConflictLog:
    def test_conflict_appended_to_canonical(self, resolver, canonical):
        resolver.resolve(
            canonical, "hostname",
            current_value="old", current_source="aws",
            incoming_value="new", incoming_source="edr",
        )
        assert len(canonical.conflicts) == 1

    def test_conflict_contains_required_fields(self, resolver, canonical):
        resolver.resolve(
            canonical, "hostname",
            current_value="prod-api-07", current_source="aws",
            incoming_value="prod-api-07-edr", incoming_source="edr",
        )
        conflict = canonical.conflicts[0]
        required_fields = {
            "field", "existing_value", "existing_source", "existing_authority_rank",
            "incoming_value", "incoming_source", "incoming_authority_rank",
            "resolved_value", "resolution", "timestamp",
        }
        assert required_fields.issubset(set(conflict.keys()))

    def test_authority_ranks_recorded_correctly(self, resolver, canonical):
        resolver.resolve(
            canonical, "hostname",
            current_value="prod-api-07", current_source="aws",    # rank 2
            incoming_value="prod-api-07-edr", incoming_source="edr",  # rank 1
        )
        conflict = canonical.conflicts[0]
        assert conflict["existing_authority_rank"] == 2
        assert conflict["incoming_authority_rank"] == 1

    def test_resolved_value_matches_decision(self, resolver, canonical):
        # edr replaces aws for hostname
        resolver.resolve(
            canonical, "hostname",
            current_value="old-host", current_source="aws",
            incoming_value="new-host", incoming_source="edr",
        )
        assert canonical.conflicts[0]["resolved_value"] == "new-host"

    def test_multiple_conflicts_all_logged(self, resolver, canonical):
        resolver.resolve(canonical, "hostname", "a", "aws", "b", "edr")
        resolver.resolve(canonical, "os_name", "Linux", "aws", "Amazon Linux 2023", "edr")
        resolver.resolve(canonical, "cloud_region", "us-east-1", "edr", "eu-west-1", "aws")
        assert len(canonical.conflicts) == 3
        fields_logged = [c["field"] for c in canonical.conflicts]
        assert "hostname" in fields_logged
        assert "os_name" in fields_logged
        assert "cloud_region" in fields_logged

    def test_timestamp_is_iso_format_string(self, resolver, canonical):
        resolver.resolve(canonical, "hostname", "a", "aws", "b", "edr")
        ts = canonical.conflicts[0]["timestamp"]
        # Should be parseable as ISO 8601
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None
