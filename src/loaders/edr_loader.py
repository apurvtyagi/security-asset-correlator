"""
src/loaders/edr_loader.py

Ingests raw CrowdStrike Falcon / SentinelOne device records and normalizes them
into RawAssetRecord objects.

Handles:
- device_id → agent_id (EDR-specific hard identifier)
- instance_id → cloud instance ID when EDR reads EC2 metadata
- local_ip + external_ip → ip_addresses
- mac_address → mac_addresses (normalized to lowercase colon format)
- CrowdStrike tag format: ["SensorGroupingTags/prod"] → {"SensorGroupingTags/prod": True}
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from ..correlator.models import RawAssetRecord

logger = logging.getLogger(__name__)


class EDRLoader:
    SOURCE = "edr"

    def load(self, raw_devices: list[dict] | dict) -> list[RawAssetRecord]:
        """Accept a single device dict or a list of them."""
        if isinstance(raw_devices, dict):
            raw_devices = [raw_devices]
        records = []
        for device in raw_devices:
            try:
                records.append(self._normalize(device))
            except Exception:
                logger.exception("Failed to normalize EDR record: %s", device.get("device_id"))
        return records

    def _normalize(self, device: dict) -> RawAssetRecord:
        ips: list[str] = []
        local_ip = device.get("local_ip", "")
        external_ip = device.get("external_ip", "")
        if local_ip:
            ips.append(local_ip)
        if external_ip and external_ip != local_ip:
            ips.append(external_ip)

        mac_addresses: list[str] = []
        raw_mac = device.get("mac_address", "")
        if raw_mac:
            mac_addresses.append(raw_mac.lower().replace("-", ":"))

        # CrowdStrike tags are a list of strings; normalize to dict
        tags: dict = {}
        raw_tags = device.get("tags", [])
        if isinstance(raw_tags, list):
            for tag in raw_tags:
                tags[str(tag)] = True
        elif isinstance(raw_tags, dict):
            tags = raw_tags

        hostnames: list[str] = []
        if device.get("hostname"):
            hostnames.append(device["hostname"])

        return RawAssetRecord(
            source=self.SOURCE,
            source_id=device.get("device_id") or f"edr-{hash(str(device))}",
            agent_id=device.get("device_id"),
            instance_id=device.get("instance_id"),
            hostnames=hostnames,
            ip_addresses=ips,
            mac_addresses=mac_addresses,
            os_name=device.get("os_version"),
            cloud_region=device.get("region"),
            cloud_account_id=device.get("service_provider_account_id"),
            tags=tags,
            last_seen=_parse_iso(device.get("last_seen")),
            raw=device,
        )


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.rstrip("Z")).replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
