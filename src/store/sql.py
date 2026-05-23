"""
src/store/sql.py

SQLAlchemy 2.0 persistent asset store.

SQLiteStore  — local file, no extra dependencies, suitable for single-server deploys.
PostgreSQLStore — swap in for multi-instance / high-availability setups.

Schema design:
  - Scalar fields (hostname, instance_id, etc.) are proper columns for filtering.
  - Complex fields (source_records, conflicts, vulnerabilities) are serialized to JSON
    text columns — they're always read as whole blobs, never filtered by sub-field.

Usage:
    from src.store.sql import SQLiteStore
    store = SQLiteStore("sqlite:///assets.db")
    store.init_schema()
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from sqlalchemy import JSON, Column, DateTime, Float, String, Text, create_engine, event, select
from sqlalchemy.orm import DeclarativeBase, Session

from ..correlator.models import CanonicalAsset, CanonicalVulnerability, RawAssetRecord
from .base import AssetStore

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class AssetRow(Base):
    __tablename__ = "canonical_assets"

    canonical_id = Column(String, primary_key=True)
    instance_id = Column(String, nullable=True, index=True)
    agent_id = Column(String, nullable=True, index=True)
    hostname = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    os_version = Column(String, nullable=True)
    cloud_region = Column(String, nullable=True)
    cloud_account_id = Column(String, nullable=True)
    asset_type = Column(String, nullable=True)
    status = Column(String, default="active")
    match_confidence = Column(Float, default=1.0)
    created_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)

    # JSON blobs for complex nested data
    ip_addresses = Column(JSON, default=list)
    mac_addresses = Column(JSON, default=list)
    tags = Column(JSON, default=dict)
    contributing_sources = Column(JSON, default=list)
    conflicts = Column(JSON, default=list)
    vulnerabilities_json = Column(Text, default="[]")
    source_records_json = Column(Text, default="[]")


class FlagRow(Base):
    __tablename__ = "review_flags"

    id = Column(String, primary_key=True)
    data_json = Column(Text, nullable=False)


def _asset_to_row(asset: CanonicalAsset) -> dict:
    return {
        "canonical_id": asset.canonical_id,
        "instance_id": asset.instance_id,
        "agent_id": asset.agent_id,
        "hostname": asset.hostname,
        "os_name": asset.os_name,
        "os_version": asset.os_version,
        "cloud_region": asset.cloud_region,
        "cloud_account_id": asset.cloud_account_id,
        "asset_type": asset.asset_type,
        "status": asset.status,
        "match_confidence": asset.match_confidence,
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
        "last_seen": asset.last_seen,
        "ip_addresses": asset.ip_addresses,
        "mac_addresses": asset.mac_addresses,
        "tags": asset.tags,
        "contributing_sources": asset.contributing_sources,
        "conflicts": asset.conflicts,
        "vulnerabilities_json": _serialize_vulns(asset.vulnerabilities),
        "source_records_json": _serialize_records(asset.source_records),
    }


def _row_to_asset(row: AssetRow) -> CanonicalAsset:
    return CanonicalAsset(
        canonical_id=row.canonical_id,
        instance_id=row.instance_id,
        agent_id=row.agent_id,
        hostname=row.hostname,
        os_name=row.os_name,
        os_version=row.os_version,
        cloud_region=row.cloud_region,
        cloud_account_id=row.cloud_account_id,
        asset_type=row.asset_type or "unknown",
        status=row.status or "active",
        match_confidence=row.match_confidence or 1.0,
        created_at=row.created_at or datetime.now(UTC),
        updated_at=row.updated_at or datetime.now(UTC),
        last_seen=row.last_seen,
        ip_addresses=row.ip_addresses or [],
        mac_addresses=row.mac_addresses or [],
        tags=row.tags or {},
        contributing_sources=row.contributing_sources or [],
        conflicts=row.conflicts or [],
        vulnerabilities=_deserialize_vulns(row.vulnerabilities_json or "[]"),
        source_records=[],  # Not rehydrated — source_records_json is for lineage only
    )


def _serialize_vulns(vulns: list[CanonicalVulnerability]) -> str:
    return json.dumps([
        {
            "cve_id": v.cve_id,
            "severity": v.severity,
            "cvss3_base": v.cvss3_base,
            "title": v.title,
            "sources": v.sources,
            "first_found": v.first_found.isoformat() if v.first_found else None,
            "last_found": v.last_found.isoformat() if v.last_found else None,
            "status": v.status,
            "raw_finding_count": v.raw_finding_count,
        }
        for v in vulns
    ])


def _deserialize_vulns(text: str) -> list[CanonicalVulnerability]:
    try:
        rows = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    result = []
    for r in rows:
        result.append(CanonicalVulnerability(
            cve_id=r["cve_id"],
            severity=r.get("severity"),
            cvss3_base=r.get("cvss3_base"),
            title=r.get("title"),
            sources=r.get("sources", []),
            first_found=_parse_dt(r.get("first_found")),
            last_found=_parse_dt(r.get("last_found")),
            status=r.get("status", "open"),
            raw_finding_count=r.get("raw_finding_count", 0),
        ))
    return result


def _serialize_records(records: list[RawAssetRecord]) -> str:
    """Serializes source records for lineage. Strips `raw` payload to keep size down."""
    return json.dumps([
        {
            "source": r.source,
            "source_id": r.source_id,
            "hostnames": r.hostnames,
            "ip_addresses": r.ip_addresses,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in records
    ])


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


class SQLiteStore(AssetStore):
    """
    SQLite-backed persistent store. Good for single-server deployments.
    Uses SQLAlchemy so it can be swapped for PostgreSQL with a connection string change.
    """

    def __init__(self, url: str = "sqlite:///assets.db") -> None:
        self._engine = create_engine(url, echo=False)
        # Enable WAL mode for better concurrent read performance on SQLite
        if url.startswith("sqlite"):
            @event.listens_for(self._engine, "connect")
            def set_wal(dbapi_conn, _):
                dbapi_conn.execute("PRAGMA journal_mode=WAL")

    def init_schema(self) -> None:
        Base.metadata.create_all(self._engine)
        logger.info("Schema initialized")

    def save(self, asset: CanonicalAsset) -> None:
        data = _asset_to_row(asset)
        with Session(self._engine) as session:
            existing = session.get(AssetRow, asset.canonical_id)
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
            else:
                session.add(AssetRow(**data))
            session.commit()

    def get(self, canonical_id: str) -> CanonicalAsset | None:
        with Session(self._engine) as session:
            row = session.get(AssetRow, canonical_id)
            return _row_to_asset(row) if row else None

    def get_all(self) -> list[CanonicalAsset]:
        with Session(self._engine) as session:
            rows = session.execute(select(AssetRow)).scalars().all()
            return [_row_to_asset(r) for r in rows]

    def count(self) -> int:
        with Session(self._engine) as session:
            return session.execute(select(AssetRow)).scalars().unique().fetchall().__len__()

    def add_flagged(self, flag: dict) -> None:
        import uuid
        row_id = str(uuid.uuid4())
        with Session(self._engine) as session:
            session.add(FlagRow(id=row_id, data_json=json.dumps(flag)))
            session.commit()

    def get_flagged(self) -> list[dict]:
        with Session(self._engine) as session:
            rows = session.execute(select(FlagRow)).scalars().all()
            result = []
            for r in rows:
                try:
                    result.append(json.loads(r.data_json))
                except json.JSONDecodeError:
                    pass
            return result

    def find_by_instance_id(self, instance_id: str) -> CanonicalAsset | None:
        with Session(self._engine) as session:
            row = session.execute(
                select(AssetRow).where(AssetRow.instance_id == instance_id)
            ).scalar_one_or_none()
            return _row_to_asset(row) if row else None

    def find_by_agent_id(self, agent_id: str) -> CanonicalAsset | None:
        with Session(self._engine) as session:
            row = session.execute(
                select(AssetRow).where(AssetRow.agent_id == agent_id)
            ).scalar_one_or_none()
            return _row_to_asset(row) if row else None


class PostgreSQLStore(SQLiteStore):
    """PostgreSQL backend. Same API as SQLiteStore — just pass a postgres:// URL."""

    def __init__(self, url: str) -> None:
        if not url.startswith("postgresql"):
            raise ValueError("PostgreSQLStore requires a postgresql:// connection string")
        self._engine = create_engine(url, echo=False, pool_pre_ping=True)
