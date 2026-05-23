"""
src/api/routes/metrics.py

Prometheus metrics endpoint.

Exposes live asset-store statistics as Prometheus gauges so teams can
scrape this service with a standard Prometheus stack.

Metrics exported:
  asset_correlator_canonical_assets_total      — total canonical assets in store
  asset_correlator_flagged_assets_total        — assets pending human review
  asset_correlator_vulnerabilities_total       — total open deduplicated CVEs
  asset_correlator_assets_by_severity{level}   — assets bucketed by risk severity
  asset_correlator_assets_no_edr_total         — assets with no EDR coverage
  asset_correlator_assets_no_scanner_total     — assets never scanned for vulns
  asset_correlator_shadow_it_total             — possible unmanaged / shadow-IT devices
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

router = APIRouter()


@router.get("/", response_class=PlainTextResponse, include_in_schema=False)
def metrics():
    """Prometheus text-format scrape endpoint."""
    try:
        from prometheus_client import (
            CONTENT_TYPE_LATEST,
            CollectorRegistry,
            Gauge,
            generate_latest,
        )
        _prometheus_available = True
    except ImportError:
        _prometheus_available = False

    from ..main import get_engine

    engine = get_engine()
    assets = engine.canonical_store
    flagged = engine.flagged_for_review
    gaps = engine.coverage_gaps()

    total_vulns = sum(
        len([v for v in a.vulnerabilities if v.status != "fixed"])
        for a in assets
    )
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for asset in assets:
        sev = asset.risk_severity if asset.risk_severity in severity_counts else "low"
        severity_counts[sev] += 1

    if not _prometheus_available:
        lines = [
            "# HELP asset_correlator_canonical_assets_total Total canonical assets",
            "# TYPE asset_correlator_canonical_assets_total gauge",
            f"asset_correlator_canonical_assets_total {len(assets)}",
            "# HELP asset_correlator_flagged_assets_total Assets pending review",
            "# TYPE asset_correlator_flagged_assets_total gauge",
            f"asset_correlator_flagged_assets_total {len(flagged)}",
            "# HELP asset_correlator_vulnerabilities_total Open deduplicated CVEs",
            "# TYPE asset_correlator_vulnerabilities_total gauge",
            f"asset_correlator_vulnerabilities_total {total_vulns}",
            "# HELP asset_correlator_assets_by_severity Assets by risk severity",
            "# TYPE asset_correlator_assets_by_severity gauge",
        ]
        for level, count in severity_counts.items():
            lines.append(f'asset_correlator_assets_by_severity{{level="{level}"}} {count}')
        lines += [
            "# HELP asset_correlator_assets_no_edr_total Assets with no EDR coverage",
            "# TYPE asset_correlator_assets_no_edr_total gauge",
            f"asset_correlator_assets_no_edr_total {gaps['no_edr']['count']}",
            "# HELP asset_correlator_assets_no_scanner_total Assets never scanned",
            "# TYPE asset_correlator_assets_no_scanner_total gauge",
            f"asset_correlator_assets_no_scanner_total {gaps['no_scanner']['count']}",
            "# HELP asset_correlator_shadow_it_total Possible shadow-IT devices",
            "# TYPE asset_correlator_shadow_it_total gauge",
            f"asset_correlator_shadow_it_total {gaps['shadow_it']['count']}",
            "",
        ]
        return PlainTextResponse("\n".join(lines), media_type="text/plain; version=0.0.4")

    registry = CollectorRegistry()

    def _gauge(name: str, doc: str, value: float) -> None:
        g = Gauge(name, doc, registry=registry)
        g.set(value)

    def _labeled_gauge(name: str, doc: str, label_name: str, label_values: dict[str, float]) -> None:
        g = Gauge(name, doc, [label_name], registry=registry)
        for label, val in label_values.items():
            g.labels(**{label_name: label}).set(val)

    _gauge("asset_correlator_canonical_assets_total", "Total canonical assets", len(assets))
    _gauge("asset_correlator_flagged_assets_total", "Assets pending human review", len(flagged))
    _gauge("asset_correlator_vulnerabilities_total", "Open deduplicated CVEs", total_vulns)
    _labeled_gauge(
        "asset_correlator_assets_by_severity",
        "Assets bucketed by risk severity",
        "level",
        {k: float(v) for k, v in severity_counts.items()},
    )
    _gauge("asset_correlator_assets_no_edr_total", "Assets with no EDR coverage", gaps["no_edr"]["count"])
    _gauge("asset_correlator_assets_no_scanner_total", "Assets never scanned", gaps["no_scanner"]["count"])
    _gauge("asset_correlator_shadow_it_total", "Possible shadow-IT devices", gaps["shadow_it"]["count"])

    return PlainTextResponse(
        generate_latest(registry).decode(),
        media_type=CONTENT_TYPE_LATEST,
    )
