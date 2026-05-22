"""
src/api/routes/assets.py

REST endpoints for canonical asset operations.

Endpoints:
  GET  /                        List canonical assets with optional filtering
  GET  /{canonical_id}          Get a single canonical asset by ID
  GET  /{canonical_id}/conflicts Field-level conflict audit log
  POST /ingest                  Ingest raw records from a named source
  GET  /review/flagged          Assets flagged for human review (ambiguous matches)
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

class AssetResponse(BaseModel):
    canonical_id: str
    instance_id: Optional[str] = None
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_addresses: list[str] = []
    mac_addresses: list[str] = []
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_account_id: Optional[str] = None
    tags: dict = {}
    last_seen: Optional[datetime] = None
    asset_type: str = "unknown"
    status: str = "active"
    contributing_sources: list[str] = []
    match_confidence: float = 1.0
    conflict_count: int = 0
    vulnerability_count: int = 0


class IngestRequest(BaseModel):
    source: str          # "aws" | "edr" | "tenable" | "qualys"
    records: list[dict]


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

@router.get("/", response_model=list[AssetResponse])
def list_assets(
    source: Optional[str] = Query(None, description="Filter by contributing source"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    region: Optional[str] = Query(None, description="Filter by cloud region"),
    status: Optional[str] = Query(None, description="Filter by lifecycle status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Return canonical assets with optional server-side filtering and pagination."""
    from ..main import get_engine
    assets = get_engine().canonical_store

    if source:
        assets = [a for a in assets if source in a.contributing_sources]
    if asset_type:
        assets = [a for a in assets if a.asset_type == asset_type]
    if region:
        assets = [a for a in assets if a.cloud_region == region]
    if status:
        assets = [a for a in assets if a.status == status]

    return [_to_response(a) for a in assets[offset: offset + limit]]


@router.get("/review/flagged")
def get_flagged_assets():
    """Return all assets flagged for human review due to ambiguous matching confidence."""
    from ..main import get_engine
    engine = get_engine()
    return {
        "count": len(engine.flagged_for_review),
        "flagged": engine.flagged_for_review,
    }


@router.get("/{canonical_id}", response_model=AssetResponse)
def get_asset(canonical_id: str):
    """Return a single canonical asset by its stable ID."""
    from ..main import get_engine
    for asset in get_engine().canonical_store:
        if asset.canonical_id == canonical_id:
            return _to_response(asset)
    raise HTTPException(status_code=404, detail=f"Asset not found: {canonical_id}")


@router.get("/{canonical_id}/conflicts")
def get_asset_conflicts(canonical_id: str):
    """Return the full field-level conflict audit log for a canonical asset."""
    from ..main import get_engine
    for asset in get_engine().canonical_store:
        if asset.canonical_id == canonical_id:
            return {
                "canonical_id": canonical_id,
                "conflict_count": len(asset.conflicts),
                "conflicts": asset.conflicts,
            }
    raise HTTPException(status_code=404, detail=f"Asset not found: {canonical_id}")


@router.post("/ingest")
def ingest_records(request: IngestRequest):
    """
    Ingest a batch of raw records from a named source and run correlation.
    Returns a summary of the correlation outcome.
    """
    from ..main import get_engine
    from ...loaders.aws_loader import AWSLoader
    from ...loaders.edr_loader import EDRLoader
    from ...loaders.tenable_loader import TenableLoader
    from ...loaders.qualys_loader import QualysLoader

    _loaders = {
        "aws": AWSLoader(),
        "edr": EDRLoader(),
        "tenable": TenableLoader(),
        "qualys": QualysLoader(),
    }

    loader = _loaders.get(request.source.lower())
    if loader is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown source '{request.source}'. Valid sources: {list(_loaders)}",
        )

    engine = get_engine()
    normalized = loader.load(request.records)
    engine.process(normalized)

    return {
        "source": request.source,
        "records_ingested": len(normalized),
        "total_canonical_assets": len(engine.canonical_store),
        "flagged_for_review": len(engine.flagged_for_review),
    }


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------

def _to_response(asset) -> AssetResponse:
    return AssetResponse(
        canonical_id=asset.canonical_id,
        instance_id=asset.instance_id,
        agent_id=asset.agent_id,
        hostname=asset.hostname,
        ip_addresses=asset.ip_addresses,
        mac_addresses=asset.mac_addresses,
        os_name=asset.os_name,
        os_version=asset.os_version,
        cloud_region=asset.cloud_region,
        cloud_account_id=asset.cloud_account_id,
        tags=asset.tags,
        last_seen=asset.last_seen,
        asset_type=asset.asset_type,
        status=asset.status,
        contributing_sources=asset.contributing_sources,
        match_confidence=asset.match_confidence,
        conflict_count=len(asset.conflicts),
        vulnerability_count=len(asset.vulnerabilities),
    )
