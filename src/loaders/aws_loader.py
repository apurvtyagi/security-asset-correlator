"""
src/loaders/aws_loader.py

Ingests raw AWS EC2 instance records (from DescribeInstances or SSM inventory)
and normalizes them into RawAssetRecord objects.

Handles:
- PrivateIpAddress + PublicIpAddress → ip_addresses list
- PrivateDnsName → hostnames (primary AWS-style FQDN)
- Tags list [{Key, Value}] → dict
- Platform field ("windows" | "" means Linux)
- Region from Placement.AvailabilityZone if not explicitly set
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from ..correlator.models import RawAssetRecord

logger = logging.getLogger(__name__)


class AWSLoader:
    SOURCE = "aws"

    def load(self, raw_instances: list[dict] | dict) -> list[RawAssetRecord]:
        """Accept a single instance dict or a list of them."""
        if isinstance(raw_instances, dict):
            raw_instances = [raw_instances]
        records = []
        for inst in raw_instances:
            try:
                records.append(self._normalize(inst))
            except Exception:
                logger.exception("Failed to normalize AWS record: %s", inst.get("InstanceId"))
        return records

    def _normalize(self, inst: dict) -> RawAssetRecord:
        instance_id = inst.get("InstanceId")

        ips: list[str] = []
        if inst.get("PrivateIpAddress"):
            ips.append(inst["PrivateIpAddress"])
        if inst.get("PublicIpAddress"):
            ips.append(inst["PublicIpAddress"])

        hostnames: list[str] = []
        private_dns = inst.get("PrivateDnsName", "")
        public_dns = inst.get("PublicDnsName", "")
        if private_dns:
            hostnames.append(private_dns)
        if public_dns and public_dns != private_dns:
            hostnames.append(public_dns)

        # Tags: [{Key: str, Value: str}] → {str: str}
        tags: dict = {}
        for tag in inst.get("Tags", []):
            if isinstance(tag, dict) and "Key" in tag:
                tags[tag["Key"]] = tag.get("Value", "")

        # Region: explicit or derived from AZ (us-east-1a → us-east-1)
        region = inst.get("Region")
        if not region:
            az = (inst.get("Placement") or {}).get("AvailabilityZone", "")
            if az:
                # Strip final letter: us-east-1a → us-east-1
                region = az[:-1] if az[-1].isalpha() else az

        # Platform: empty string means Linux in AWS
        platform = inst.get("Platform") or ""
        os_name = "Windows" if platform.lower() == "windows" else "Linux"

        last_seen = _parse_iso(inst.get("LaunchTime"))

        return RawAssetRecord(
            source=self.SOURCE,
            source_id=instance_id or f"aws-{hash(str(inst))}",
            instance_id=instance_id,
            hostnames=hostnames,
            ip_addresses=ips,
            os_name=os_name,
            cloud_region=region,
            cloud_account_id=inst.get("OwnerId"),
            tags=tags,
            last_seen=last_seen,
            asset_type="server",
            raw=inst,
        )


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.rstrip("Z")).replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
