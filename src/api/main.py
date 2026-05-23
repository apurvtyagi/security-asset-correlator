"""
src/api/main.py

FastAPI entrypoint for the security asset correlator.

The CorrelationEngine is initialized once at startup via the lifespan context manager
and shared across all requests through the get_engine() dependency helper.

Routes:
  GET  /health                         — liveness check
  GET  /api/v1/assets/                 — list canonical assets (filterable)
  GET  /api/v1/assets/{id}             — single canonical asset
  GET  /api/v1/assets/{id}/conflicts   — field-level conflict log
  POST /api/v1/assets/ingest           — ingest raw records from a named source
  GET  /api/v1/assets/review/flagged   — assets pending human review
  GET  /api/v1/vulnerabilities/        — deduplicated findings (filterable)
  GET  /api/v1/vulnerabilities/by-asset/{id}
  GET  /api/v1/vulnerabilities/summary — aggregate stats
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..correlator.engine import CorrelationEngine
from .routes import assets, coverage, metrics, vulnerabilities

logger = logging.getLogger(__name__)

# Module-level singleton shared across all requests
_engine: CorrelationEngine | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine
    _engine = CorrelationEngine()
    logger.info("CorrelationEngine initialized and ready")
    yield
    _engine = None
    logger.info("CorrelationEngine shut down")


app = FastAPI(
    title="Security Asset Correlator",
    description=(
        "Cross-tool canonical asset correlation engine. "
        "Ingests raw asset records from AWS, EDR, Tenable, and Qualys; "
        "runs layered matching; merges duplicates into canonical records; "
        "and deduplicates vulnerability findings across sources."
    ),
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])
app.include_router(coverage.router, prefix="/api/v1/coverage", tags=["coverage"])
app.include_router(metrics.router, prefix="/metrics", tags=["metrics"])


@app.get("/health", tags=["health"])
def health_check():
    return {"status": "ok", "engine_ready": _engine is not None}


def get_engine() -> CorrelationEngine:
    """Dependency used by route handlers to access the shared engine instance."""
    if _engine is None:
        raise RuntimeError("CorrelationEngine not initialized — lifespan not running")
    return _engine
