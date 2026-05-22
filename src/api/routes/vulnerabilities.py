"""
src/api/routes/vulnerabilities.py

REST endpoints for deduplicated vulnerability findings.

All findings are keyed to canonical asset IDs, not source-tool-specific identifiers.
Deduplication happens at ingest time in RecordMerger — the same CVE reported by both
Tenable and Qualys appears once here with both sources listed.

Endpoints:
  GET /                      List all unique findings (filterable)
  GET /by-asset/{id}         All findings for one canonical asset
  GET /summary               Aggregate stats (counts by severity, top CVEs)
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------

class VulnerabilityResponse(BaseModel):
    cve_id: str
    canonical_asset_id: str
    hostname: Optional[str] = None
    severity: Optional[str] = None
    cvss3_base: Optional[float] = None
    title: Optional[str] = None
    sources: list[str] = []
    first_found: Optional[datetime] = None
    last_found: Optional[datetime] = None
    status: str = "open"
    raw_finding_count: int = 0


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

@router.get("/", response_model=list[VulnerabilityResponse])
def list_vulnerabilities(
    severity: Optional[str] = Query(None, description="critical | high | medium | low | info"),
    cve_id: Optional[str] = Query(None, description="Filter by exact CVE ID"),
    status: Optional[str] = Query(None, description="open | potential | fixed"),
    source: Optional[str] = Query(None, description="Filter: must include this source"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Return deduplicated vulnerability findings across all canonical assets."""
    from ..main import get_engine
    engine = get_engine()

    results: list[VulnerabilityResponse] = []
    for asset in engine.canonical_store:
        for vuln in asset.vulnerabilities:
            if severity and vuln.severity != severity:
                continue
            if cve_id and vuln.cve_id != cve_id:
                continue
            if status and vuln.status != status:
                continue
            if source and source not in vuln.sources:
                continue
            results.append(_to_response(vuln, asset.canonical_id, asset.hostname))

    return results[offset: offset + limit]


@router.get("/summary")
def vulnerability_summary():
    """Aggregate vulnerability statistics across all canonical assets."""
    from ..main import get_engine
    engine = get_engine()

    total_unique = 0
    by_severity: dict[str, int] = {}
    cve_asset_count: dict[str, int] = {}

    for asset in engine.canonical_store:
        for vuln in asset.vulnerabilities:
            total_unique += 1
            sev = vuln.severity or "unknown"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cve_asset_count[vuln.cve_id] = cve_asset_count.get(vuln.cve_id, 0) + 1

    top_cves = sorted(cve_asset_count.items(), key=lambda x: x[1], reverse=True)[:10]
    assets_with_findings = sum(1 for a in engine.canonical_store if a.vulnerabilities)

    return {
        "total_unique_findings": total_unique,
        "assets_with_findings": assets_with_findings,
        "total_canonical_assets": len(engine.canonical_store),
        "by_severity": by_severity,
        "top_cves_by_asset_count": [
            {"cve_id": cve, "asset_count": count} for cve, count in top_cves
        ],
    }


@router.get("/by-asset/{canonical_id}", response_model=list[VulnerabilityResponse])
def get_vulnerabilities_for_asset(
    canonical_id: str,
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """Return all deduplicated findings for a specific canonical asset."""
    from ..main import get_engine
    engine = get_engine()

    asset = next(
        (a for a in engine.canonical_store if a.canonical_id == canonical_id), None
    )
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset not found: {canonical_id}")

    vulns = asset.vulnerabilities
    if severity:
        vulns = [v for v in vulns if v.severity == severity]
    if status:
        vulns = [v for v in vulns if v.status == status]

    return [_to_response(v, canonical_id, asset.hostname) for v in vulns]


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------

def _to_response(vuln, canonical_id: str, hostname: Optional[str]) -> VulnerabilityResponse:
    return VulnerabilityResponse(
        cve_id=vuln.cve_id,
        canonical_asset_id=canonical_id,
        hostname=hostname,
        severity=vuln.severity,
        cvss3_base=vuln.cvss3_base,
        title=vuln.title,
        sources=vuln.sources,
        first_found=vuln.first_found,
        last_found=vuln.last_found,
        status=vuln.status,
        raw_finding_count=vuln.raw_finding_count,
    )
