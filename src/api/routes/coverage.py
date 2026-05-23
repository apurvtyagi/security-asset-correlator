"""
src/api/routes/coverage.py

Coverage gap analysis endpoints.

GET /api/v1/coverage           — full gap report (no_edr, no_scanner, shadow_it)
GET /api/v1/coverage/no-edr    — assets not seen by any EDR
GET /api/v1/coverage/no-scanner — assets not seen by any vulnerability scanner
GET /api/v1/coverage/shadow-it  — assets seen only by scanners (possible unmanaged devices)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ...correlator.engine import CorrelationEngine
from ...correlator.models import CanonicalAsset
from ..main import get_engine

router = APIRouter()


def _asset_summary(asset: CanonicalAsset) -> dict:
    return {
        "canonical_id": asset.canonical_id,
        "hostname": asset.hostname,
        "ip_addresses": asset.ip_addresses,
        "asset_type": asset.asset_type,
        "contributing_sources": asset.contributing_sources,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }


@router.get("/", summary="Full coverage gap report")
def coverage_report(engine: CorrelationEngine = Depends(get_engine)):
    """Return a summary of coverage gaps across all canonical assets."""
    return engine.coverage_gaps()


@router.get("/no-edr", summary="Assets without EDR coverage")
def no_edr(engine: CorrelationEngine = Depends(get_engine)):
    """Assets that have no EDR source record — not enrolled in any endpoint agent."""
    gaps = engine.coverage_gaps()
    ids = set(gaps["no_edr"]["canonical_ids"])
    assets = [a for a in engine._store.get_all() if a.canonical_id in ids]
    return {
        "count": len(assets),
        "assets": [_asset_summary(a) for a in assets],
    }


@router.get("/no-scanner", summary="Assets without scanner coverage")
def no_scanner(engine: CorrelationEngine = Depends(get_engine)):
    """Assets never seen by Tenable, Qualys, or similar scanners — no vuln data."""
    gaps = engine.coverage_gaps()
    ids = set(gaps["no_scanner"]["canonical_ids"])
    assets = [a for a in engine._store.get_all() if a.canonical_id in ids]
    return {
        "count": len(assets),
        "assets": [_asset_summary(a) for a in assets],
    }


@router.get("/shadow-it", summary="Possible shadow-IT assets")
def shadow_it(engine: CorrelationEngine = Depends(get_engine)):
    """
    Assets seen only by scanners — no cloud inventory and no EDR record.
    These are candidates for unmanaged / shadow-IT devices that lack both
    agent coverage and cloud-provider tracking.
    """
    gaps = engine.coverage_gaps()
    ids = set(gaps["shadow_it"]["canonical_ids"])
    assets = [a for a in engine._store.get_all() if a.canonical_id in ids]
    return {
        "count": len(assets),
        "assets": [_asset_summary(a) for a in assets],
    }
