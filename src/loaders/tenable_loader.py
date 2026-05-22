"""
src/loaders/tenable_loader.py

Ingests Tenable.io asset and vulnerability records and normalizes them
into RawAssetRecord + VulnerabilityFinding objects.

Tenable-specific handling:
- fqdn is a list (multiple observed FQDNs per scan cycle)
- ipv4 is a list
- operating_system is a list (Tenable may detect multiple)
- aws_ec2_instance_id present on EC2 assets via cloud connector
- vulnerability state: "open" | "resurfaced" | "fixed"
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from ..correlator.models import RawAssetRecord, VulnerabilityFinding

logger = logging.getLogger(__name__)


class TenableLoader:
    SOURCE = "tenable"

    def load(self, raw_assets: list[dict] | dict) -> list[RawAssetRecord]:
        """Accept a single asset dict or a list of them."""
        if isinstance(raw_assets, dict):
            raw_assets = [raw_assets]
        records = []
        for asset in raw_assets:
            try:
                records.append(self._normalize(asset))
            except Exception:
                logger.exception("Failed to normalize Tenable record: %s", asset.get("id"))
        return records

    def _normalize(self, asset: dict) -> RawAssetRecord:
        # fqdn can be a list or a plain string
        fqdns = asset.get("fqdn", [])
        if isinstance(fqdns, str):
            fqdns = [fqdns]

        ipv4 = asset.get("ipv4", [])
        if isinstance(ipv4, str):
            ipv4 = [ipv4]

        # operating_system is a list — take the first, prefer non-empty
        os_list = asset.get("operating_system", [])
        os_name: Optional[str] = None
        if isinstance(os_list, list):
            os_name = next((s for s in os_list if s), None)
        elif isinstance(os_list, str):
            os_name = os_list or None

        # Tags: [{"category": "env", "value": "production"}]
        tags: dict = {}
        for entry in asset.get("tags", []):
            if isinstance(entry, dict):
                category = entry.get("category", "tag")
                value = entry.get("value", "")
                tags[category] = value

        vulns = self._load_vulnerabilities(asset.get("vulnerabilities", []))

        return RawAssetRecord(
            source=self.SOURCE,
            source_id=asset.get("id") or f"tenable-{hash(str(asset))}",
            instance_id=asset.get("aws_ec2_instance_id"),
            hostnames=fqdns,
            ip_addresses=ipv4,
            os_name=os_name,
            cloud_region=asset.get("aws_region"),
            cloud_account_id=asset.get("aws_account_id"),
            tags=tags,
            last_seen=_parse_iso(asset.get("last_scan_time")),
            vulnerabilities=vulns,
            raw=asset,
        )

    def _load_vulnerabilities(self, raw_vulns: list[dict]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for v in raw_vulns:
            cves = v.get("cve", [])
            if isinstance(cves, str):
                cves = [cves]
            findings.append(VulnerabilityFinding(
                source=self.SOURCE,
                source_finding_id=str(v.get("plugin_id", "")),
                cve_ids=cves,
                severity=v.get("severity"),
                cvss3_base=v.get("cvss3_base_score"),
                title=v.get("plugin_name"),
                first_found=_parse_iso(v.get("first_found")),
                last_found=_parse_iso(v.get("last_found")),
                status=v.get("state", "open"),
            ))
        return findings


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.rstrip("Z")).replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
