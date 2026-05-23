"""
src/correlator/conflict_resolver.py

Resolves field-level conflicts when merging source records into a canonical asset.

Every conflict is fully logged: which sources disagreed, the values involved,
the authority ranks used to decide, and the resolution taken. No silent drops.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .models import CanonicalAsset

logger = logging.getLogger(__name__)


class ConflictResolver:
    """
    Determines which value wins when two sources disagree on a scalar field,
    and appends a structured conflict entry to the canonical asset's audit log.

    Authority config format: {field_name: {source_name: rank}}
    Lower rank = more authoritative. Unknown sources get rank 99.
    Equal-rank ties keep the existing value.
    """

    def __init__(self, authority_config: dict[str, dict[str, int]]):
        self.authority_config = authority_config

    def resolve(
        self,
        canonical: CanonicalAsset,
        field_name: str,
        current_value: Any,
        current_source: str,
        incoming_value: Any,
        incoming_source: str,
    ) -> tuple[Any, str]:
        """
        Resolve a conflict between two values for a single scalar field.

        Returns:
            (resolved_value, resolution_label)
            resolution_label is one of: "replaced_with_higher_authority" | "kept_existing"
        """
        authority = self.authority_config.get(field_name, {})
        current_rank = authority.get(current_source, 99)
        incoming_rank = authority.get(incoming_source, 99)

        if incoming_rank < current_rank:
            # Incoming source is more authoritative — replace current value
            resolution = "replaced_with_higher_authority"
            resolved_value = incoming_value
        else:
            # Current wins (equal rank keeps existing to be deterministic)
            resolution = "kept_existing"
            resolved_value = current_value

        canonical.conflicts.append({
            "field": field_name,
            "existing_value": current_value,
            "existing_source": current_source,
            "existing_authority_rank": current_rank,
            "incoming_value": incoming_value,
            "incoming_source": incoming_source,
            "incoming_authority_rank": incoming_rank,
            "resolved_value": resolved_value,
            "resolution": resolution,
            "timestamp": datetime.now(UTC).isoformat(),
        })

        logger.debug(
            "CONFLICT [%s] field=%s: %r (%s, rank %d) vs %r (%s, rank %d) → %s",
            canonical.canonical_id,
            field_name,
            current_value, current_source, current_rank,
            incoming_value, incoming_source, incoming_rank,
            resolution,
        )

        return resolved_value, resolution
