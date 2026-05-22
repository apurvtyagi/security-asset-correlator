"""
src/loaders/qualys_loader.py

Ingests Qualys VMDR host and detection records and normalizes them
into RawAssetRecord + VulnerabilityFinding objects.

Qualys-specific handling:
- SEVERITY is an integer (1–5); mapped to critical/high/medium/low/info
- DETECTIONS.DETECTION can be a single dict or a list (Qualys XML-to-JSON quirk)
- CVE_LIST.CVE can be a single string or a list
- STATUS "Active" → "open", otherwise "potential"
- Qualys typically lacks EC2_INSTANCE_ID unless the cloud connector is configured
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from ..correlator.models import RawAssetRecord, VulnerabilityFinding

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[int, str] = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}


class QualysLoader:
    SOURCE = "qualys"

    def load(self, raw_hosts: list[dict] | dict) -> list[RawAssetRecord]:
        """Accept a single host dict or a list of them."""
        if isinstance(raw_hosts, dict):
            raw_hosts = [raw_hosts]
        records = []
        for host in raw_hosts:
            try:
                records.append(self._normalize(host))
            except Exception:
                logger.exception("Failed to normalize Qualys record: %s", host.get("ID"))
        return records

    def _normalize(self, host: dict) -> RawAssetRecord:
        ips: list[str] = []
        if host.get("IP"):
            ips.append(host["IP"])

        hostnames: list[str] = []
        if host.get("DNS"):
            hostnames.append(host["DNS"])
        if host.get("NETBIOS") and host["NETBIOS"].strip():
            hostnames.append(host["NETBIOS"].strip())

        # TAGS.TAG can be a list or dict in Qualys JSON output
        tags: dict = {}
        tag_root = host.get("TAGS", {})
        if isinstance(tag_root, dict):
            tag_list = tag_root.get("TAG", [])
            if isinstance(tag_list, dict):
                tag_list = [tag_list]
            for tag in tag_list:
                if isinstance(tag, dict):
                    name = tag.get("NAME", "")
                    tag_id = tag.get("ID", "")
                    if name:
                        tags[name] = tag_id

        vulns = self._load_vulnerabilities(host.get("DETECTIONS", {}))

        return RawAssetRecord(
            source=self.SOURCE,
            source_id=str(host.get("ID", f"qualys-{hash(str(host))}")),
            instance_id=host.get("EC2_INSTANCE_ID"),
            hostnames=hostnames,
            ip_addresses=ips,
            os_name=host.get("OS"),
            tags=tags,
            last_seen=_parse_iso(host.get("LAST_SCAN_DATETIME")),
            vulnerabilities=vulns,
            raw=host,
        )

    def _load_vulnerabilities(self, detections: dict) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        raw_list = detections.get("DETECTION", [])
        # Qualys XML-to-JSON: single detection becomes a dict, not a list
        if isinstance(raw_list, dict):
            raw_list = [raw_list]

        for d in raw_list:
            cves = self._extract_cves(d.get("CVE_LIST", {}))
            severity_int = d.get("SEVERITY", 0)
            severity = _SEVERITY_MAP.get(severity_int, "info")
            raw_status = (d.get("STATUS") or "").lower()
            status = "open" if raw_status in ("active", "open") else "potential"

            findings.append(VulnerabilityFinding(
                source=self.SOURCE,
                source_finding_id=str(d.get("QID", "")),
                cve_ids=cves,
                severity=severity,
                cvss3_base=d.get("CVSS3_BASE"),
                title=d.get("TITLE"),
                first_found=_parse_iso(d.get("FIRST_FOUND_DATETIME")),
                last_found=_parse_iso(d.get("LAST_FOUND_DATETIME")),
                status=status,
            ))
        return findings

    @staticmethod
    def _extract_cves(cve_list: dict | str | list) -> list[str]:
        """Handle the multiple shapes Qualys uses for CVE data."""
        if isinstance(cve_list, str):
            return [cve_list]
        if isinstance(cve_list, list):
            return cve_list
        if isinstance(cve_list, dict):
            raw = cve_list.get("CVE", [])
            if isinstance(raw, str):
                return [raw]
            if isinstance(raw, list):
                return raw
        return []


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.rstrip("Z")).replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
