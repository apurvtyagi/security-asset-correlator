"""
src/correlator/matcher.py

4-layer matching engine. Scores an incoming RawAssetRecord against every existing
CanonicalAsset and returns the best match with a confidence score.

Layer execution order (earlier layers short-circuit on high confidence):
  1. Hard identifiers: instance_id, agent_id, MAC address  → 0.95–1.0
  2. Normalized hostname                                    → 0.45–0.85
  3. IP cross-reference with staleness decay                → 0.60–0.75
  4. Metadata correlation: OS + region + cloud account     → up to 0.50

Layers 2–4 combine via weighted sum: (hostname × 0.60) + (ip × 0.40).
Final confidence determines outcome:
  ≥ merge_threshold  → merge into existing canonical
  ≥ flag_threshold   → create new canonical, flag for review
  < flag_threshold   → create new canonical, no relationship inferred
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from .models import CanonicalAsset, MatchResult, RawAssetRecord
from ..resolvers.hostname_resolver import HostnameResolver
from ..resolvers.ip_resolver import IPResolver

logger = logging.getLogger(__name__)


class MatchEngine:
    """
    Stateless matcher. Receives a record and the current canonical store,
    returns the best-matching canonical asset and the match result.
    """

    def __init__(
        self,
        thresholds: dict,
        hostname_resolver: HostnameResolver,
        ip_resolver: IPResolver,
    ):
        self.merge_threshold: float = thresholds.get("merge_threshold", 0.70)
        self.flag_threshold: float = thresholds.get("flag_threshold", 0.50)
        self.hostname_resolver = hostname_resolver
        self.ip_resolver = ip_resolver

        # Layer combination weights
        combo = thresholds.get("combination_weights", {})
        self._hostname_weight: float = combo.get("hostname", 0.60)
        self._ip_weight: float = combo.get("ip", 0.40)

    def find_best_match(
        self,
        record: RawAssetRecord,
        canonical_store: list[CanonicalAsset],
    ) -> tuple[Optional[CanonicalAsset], Optional[MatchResult]]:
        """
        Scan the canonical store for the best match for this record.
        Returns (matched_asset, match_result) or (None, None) if no match found.
        """
        best_asset: Optional[CanonicalAsset] = None
        best_result: Optional[MatchResult] = None

        for canonical in canonical_store:
            result = self._score_match(record, canonical)
            if result is None:
                continue
            if best_result is None or result.confidence > best_result.confidence:
                best_result = result
                best_asset = canonical
                # A perfect hard-ID match is definitive — no need to keep scanning
                if best_result.confidence >= 1.0 and best_result.match_layer == "hard_id":
                    break

        return best_asset, best_result

    # ------------------------------------------------------------------
    # Internal scoring
    # ------------------------------------------------------------------

    def _score_match(
        self, record: RawAssetRecord, canonical: CanonicalAsset
    ) -> Optional[MatchResult]:
        # Layer 1: Hard identifiers
        hard = self._match_hard_ids(record, canonical)
        if hard:
            return hard

        # Layers 2 + 3: Hostname and IP combined
        hostname_result = self._match_hostname(record, canonical)
        ip_result = self._match_ips(record, canonical)

        combined = 0.0
        if hostname_result:
            combined += hostname_result.confidence * self._hostname_weight
        if ip_result:
            combined += ip_result.confidence * self._ip_weight

        if combined >= self.flag_threshold:
            return MatchResult(
                confidence=combined,
                match_layer="hostname+ip",
                matched_on={
                    "hostname": hostname_result.matched_on if hostname_result else None,
                    "ip": ip_result.matched_on if ip_result else None,
                },
            )

        # Layer 4: Metadata correlation (OS + region + account)
        return self._match_metadata(record, canonical)

    def _match_hard_ids(
        self, record: RawAssetRecord, canonical: CanonicalAsset
    ) -> Optional[MatchResult]:
        """Confidence 1.0 for exact ID match; 0.95 for real MAC match."""
        if record.instance_id and canonical.instance_id:
            if record.instance_id == canonical.instance_id:
                return MatchResult(
                    confidence=1.0,
                    match_layer="hard_id",
                    matched_on={"field": "instance_id", "value": record.instance_id},
                )

        if record.agent_id and canonical.agent_id:
            if record.agent_id == canonical.agent_id:
                return MatchResult(
                    confidence=1.0,
                    match_layer="hard_id",
                    matched_on={"field": "agent_id", "value": record.agent_id},
                )

        if record.mac_addresses and canonical.mac_addresses:
            shared = set(record.mac_addresses) & set(canonical.mac_addresses)
            real_macs = [m for m in shared if not self.ip_resolver.is_virtual_mac(m)]
            if real_macs:
                return MatchResult(
                    confidence=0.95,
                    match_layer="hard_id",
                    matched_on={"field": "mac_address", "value": real_macs[0]},
                )

        return None

    def _match_hostname(
        self, record: RawAssetRecord, canonical: CanonicalAsset
    ) -> Optional[MatchResult]:
        """
        Exact normalized hostname match.
        Confidence 0.85 normally; 0.45 for generic hostnames (ip-10-x-x-x, localhost...).
        """
        if not record.hostnames or not canonical.hostname:
            return None

        canonical_norm = self.hostname_resolver.normalize(canonical.hostname)
        for h in record.hostnames:
            norm = self.hostname_resolver.normalize(h)
            if norm and norm == canonical_norm:
                confidence = 0.45 if self.hostname_resolver.is_generic(norm) else 0.85
                return MatchResult(
                    confidence=confidence,
                    match_layer="hostname",
                    matched_on={"field": "hostname", "value": norm},
                )
        return None

    def _match_ips(
        self, record: RawAssetRecord, canonical: CanonicalAsset
    ) -> Optional[MatchResult]:
        """Delegate to IPResolver which handles staleness decay and public/private weighting."""
        if not record.ip_addresses or not canonical.ip_addresses:
            return None
        return self.ip_resolver.score_ip_overlap(
            record.ip_addresses,
            canonical.ip_addresses,
            canonical.last_seen,
        )

    def _match_metadata(
        self, record: RawAssetRecord, canonical: CanonicalAsset
    ) -> Optional[MatchResult]:
        """
        OS + region + account correlation. Max 0.50 — never sufficient alone
        to cross the merge threshold, only useful to surface candidates for review.
        """
        score = 0.0
        matched_on: dict = {}

        if record.os_name and canonical.os_name:
            if _normalize_os(record.os_name) == _normalize_os(canonical.os_name):
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

        return MatchResult(confidence=score, match_layer="metadata", matched_on=matched_on)


def _normalize_os(os_name: str) -> str:
    """Map diverse OS strings to a normalized family for fuzzy comparison."""
    lower = os_name.lower()
    if "windows" in lower:
        return "windows"
    if "ubuntu" in lower or "debian" in lower:
        return "debian_family"
    if "rhel" in lower or "centos" in lower or "rocky" in lower or "alma" in lower:
        return "rhel_family"
    if "amazon linux" in lower:
        return "rhel_family"
    return lower
