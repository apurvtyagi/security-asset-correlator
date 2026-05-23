"""
src/resolvers/ip_resolver.py

IP address matching with staleness decay, public/private weighting,
virtual MAC detection, and NAT exclusion support.

Key design decisions:
- Private IPs score lower than public IPs (RFC-1918 ranges appear across VPCs)
- Staleness decay: IPs from assets last seen >48h ago get a confidence penalty
- Virtual MACs (VMware, QEMU) are excluded from hard-ID matching
- Known NAT/proxy IPs are excluded from IP matching entirely
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime

from ..correlator.models import MatchResult

logger = logging.getLogger(__name__)

# VMware and common hypervisor OUI prefixes — these MACs are not unique per machine
_VIRTUAL_MAC_OUIS: frozenset[str] = frozenset({
    "00:50:56",  # VMware vSphere
    "00:0c:29",  # VMware Workstation (non-registered)
    "00:05:69",  # VMware (legacy)
    "52:54:00",  # QEMU/KVM (libvirt default)
    "00:16:3e",  # Xen hypervisor
    "00:1c:42",  # Parallels Desktop
    "08:00:27",  # VirtualBox
})

# IPs that are known shared infrastructure (NAT gateways, load balancers, proxies).
# Matches on these IPs would incorrectly cluster many distinct assets.
# In production, load this from config or a managed list.
KNOWN_NAT_EXCLUSIONS: set[str] = set()

_STALENESS_THRESHOLD_HOURS = 48
_DECAY_WINDOW_HOURS = 720  # 30 days to reach the floor multiplier
_DECAY_FLOOR = 0.50


class IPResolver:
    """
    Stateless IP matching helper consumed by MatchEngine.
    """

    def is_private(self, ip: str) -> bool:
        """Return True if the IP falls within RFC-1918 private ranges."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            logger.debug("Could not parse IP address: %r", ip)
            return False

    def is_virtual_mac(self, mac: str) -> bool:
        """Return True if the MAC address belongs to a known virtualization OUI."""
        normalized = mac.lower().replace("-", ":").strip()
        return any(normalized.startswith(oui) for oui in _VIRTUAL_MAC_OUIS)

    def score_ip_overlap(
        self,
        record_ips: list[str],
        canonical_ips: list[str],
        canonical_last_seen: datetime | None,
    ) -> MatchResult | None:
        """
        Compute a confidence score for the IP overlap between an incoming record
        and an existing canonical asset.

        Scoring:
        - Shared public IP   → base confidence 0.75
        - Shared private IP  → base confidence 0.60
        - Staleness decay    → applies if canonical_last_seen > 48h ago

        Returns None if there is no meaningful overlap.
        """
        record_set = {ip for ip in record_ips if ip not in KNOWN_NAT_EXCLUSIONS}
        canonical_set = {ip for ip in canonical_ips if ip not in KNOWN_NAT_EXCLUSIONS}

        shared = record_set & canonical_set
        if not shared:
            return None

        shared_public = [ip for ip in shared if not self.is_private(ip)]
        shared_private = [ip for ip in shared if self.is_private(ip)]

        if shared_public:
            confidence = 0.75
            matched_ips = shared_public
        elif shared_private:
            confidence = 0.60
            matched_ips = shared_private
        else:
            return None

        # Apply staleness decay if the canonical asset hasn't been seen recently
        if canonical_last_seen is not None:
            age_hours = (datetime.now(UTC) - canonical_last_seen).total_seconds() / 3600
            if age_hours > _STALENESS_THRESHOLD_HOURS:
                decay = max(_DECAY_FLOOR, 1.0 - (age_hours / _DECAY_WINDOW_HOURS))
                pre_decay = confidence
                confidence *= decay
                logger.debug(
                    "IP staleness decay: age=%.0fh, decay=%.2f, confidence %.2f → %.2f",
                    age_hours, decay, pre_decay, confidence,
                )

        return MatchResult(
            confidence=confidence,
            match_layer="ip",
            matched_on={"field": "ip_addresses", "value": matched_ips},
        )
