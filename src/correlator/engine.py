"""
src/correlator/engine.py

Core correlation orchestrator. Loads config from YAML files, wires up the matcher
and merger, processes batches of RawAssetRecords, and maintains the canonical store.

Usage as a module:
    from src.correlator.engine import CorrelationEngine
    engine = CorrelationEngine()
    canonical_assets = engine.process(records)

Usage as a CLI:
    python -m src.correlator.engine --sources data/samples/ --output canonical_assets.json
"""

from __future__ import annotations

import argparse
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from .matcher import MatchEngine
from .merger import RecordMerger
from .models import CanonicalAsset, RawAssetRecord
from ..resolvers.hostname_resolver import HostnameResolver
from ..resolvers.ip_resolver import IPResolver

logger = logging.getLogger(__name__)

# Default config directory relative to this file's package root
_CONFIG_DIR = Path(__file__).parents[2] / "config"


def load_config(config_dir: Path = _CONFIG_DIR) -> dict:
    """Load all three YAML config files into a single dict keyed by base filename."""
    configs: dict = {}
    for filename in ("canonical_mapping.yaml", "source_confidence.yaml", "match_thresholds.yaml"):
        path = config_dir / filename
        if path.exists():
            with open(path) as fh:
                configs[filename.replace(".yaml", "")] = yaml.safe_load(fh)
        else:
            logger.warning("Config not found, using defaults: %s", path)
    return configs


def _extract_authority_config(canonical_mapping: dict) -> dict[str, dict[str, int]]:
    """Pull authority_rank dicts out of canonical_mapping for use by ConflictResolver."""
    authority: dict[str, dict[str, int]] = {}
    for field_name, field_cfg in canonical_mapping.get("canonical_fields", {}).items():
        if isinstance(field_cfg, dict) and "authority_rank" in field_cfg:
            authority[field_name] = field_cfg["authority_rank"]
    return authority


class CorrelationEngine:
    """
    Top-level orchestrator. Accepts normalized RawAssetRecords, runs 4-layer matching,
    merges confirmed matches into canonical records, and surfaces ambiguous cases
    in the flagged_for_review queue for human triage.

    The engine maintains state between calls to process(), allowing incremental
    ingestion of records from different sources.
    """

    def __init__(self, config_dir: Path = _CONFIG_DIR):
        configs = load_config(config_dir)

        thresholds_cfg = configs.get("match_thresholds", {})
        thresholds = thresholds_cfg.get("thresholds", {
            "merge_threshold": 0.70,
            "flag_threshold": 0.50,
        })
        # Propagate combination weights so MatchEngine can read them
        thresholds["combination_weights"] = thresholds_cfg.get("combination_weights", {})

        canonical_mapping = configs.get("canonical_mapping", {})
        authority_config = _extract_authority_config(canonical_mapping)

        hostname_norm_cfg = (
            canonical_mapping
            .get("canonical_fields", {})
            .get("hostname", {})
            .get("normalization", {})
        )

        self.match_engine = MatchEngine(
            thresholds=thresholds,
            hostname_resolver=HostnameResolver(hostname_norm_cfg),
            ip_resolver=IPResolver(),
        )
        self.merger = RecordMerger(authority_config)
        self.merge_threshold: float = thresholds["merge_threshold"]
        self.flag_threshold: float = thresholds["flag_threshold"]

        self.canonical_store: list[CanonicalAsset] = []
        self.flagged_for_review: list[dict] = []

    def process(self, records: list[RawAssetRecord]) -> list[CanonicalAsset]:
        """
        Correlate a batch of normalized records against the current canonical store.
        Updates the store in place and returns the full store after processing.
        """
        logger.info("Processing %d raw asset records", len(records))

        for record in records:
            canonical, match_result = self.match_engine.find_best_match(
                record, self.canonical_store
            )

            if match_result and match_result.confidence >= self.merge_threshold:
                logger.debug(
                    "MERGE [%.2f] %s:%s → canonical:%s via %s",
                    match_result.confidence, record.source, record.source_id,
                    canonical.canonical_id, match_result.match_layer,
                )
                self.merger.merge(canonical, record)

            elif match_result and match_result.confidence >= self.flag_threshold:
                new = self._create_canonical(record, match_result.confidence)
                self.canonical_store.append(new)
                self.flagged_for_review.append({
                    "new_canonical_id": new.canonical_id,
                    "possible_duplicate_of": canonical.canonical_id,
                    "confidence": match_result.confidence,
                    "match_layer": match_result.match_layer,
                    "matched_on": match_result.matched_on,
                    "flagged_at": datetime.now(timezone.utc).isoformat(),
                })
                logger.warning(
                    "FLAG [%.2f] %s:%s may duplicate canonical:%s",
                    match_result.confidence, record.source, record.source_id,
                    canonical.canonical_id,
                )

            else:
                new = self._create_canonical(record, 1.0)
                self.canonical_store.append(new)
                logger.debug(
                    "NEW canonical:%s from %s:%s",
                    new.canonical_id, record.source, record.source_id,
                )

        logger.info(
            "Correlation complete. Canonical assets: %d, Flagged for review: %d",
            len(self.canonical_store), len(self.flagged_for_review),
        )
        return self.canonical_store

    def _create_canonical(
        self, record: RawAssetRecord, confidence: float
    ) -> CanonicalAsset:
        return CanonicalAsset(
            canonical_id=str(uuid.uuid4()),
            instance_id=record.instance_id,
            agent_id=record.agent_id,
            hostname=record.hostnames[0] if record.hostnames else None,
            ip_addresses=list(record.ip_addresses),
            mac_addresses=list(record.mac_addresses),
            os_name=record.os_name,
            os_version=record.os_version,
            cloud_region=record.cloud_region,
            cloud_account_id=record.cloud_account_id,
            tags={f"{record.source}:{k}": v for k, v in record.tags.items()},
            last_seen=record.last_seen,
            asset_type=record.asset_type or "unknown",
            contributing_sources=[record.source],
            source_records=[record],
            vulnerabilities=list(record.vulnerabilities),
            match_confidence=confidence,
        )


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def _serialize_asset(asset: CanonicalAsset) -> dict:
    return {
        "canonical_id": asset.canonical_id,
        "instance_id": asset.instance_id,
        "agent_id": asset.agent_id,
        "hostname": asset.hostname,
        "ip_addresses": asset.ip_addresses,
        "mac_addresses": asset.mac_addresses,
        "os_name": asset.os_name,
        "cloud_region": asset.cloud_region,
        "cloud_account_id": asset.cloud_account_id,
        "tags": asset.tags,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        "asset_type": asset.asset_type,
        "status": asset.status,
        "contributing_sources": asset.contributing_sources,
        "match_confidence": asset.match_confidence,
        "conflicts": asset.conflicts,
        "vulnerabilities": [
            {
                "cve_id": v.cve_id,
                "severity": v.severity,
                "cvss3_base": v.cvss3_base,
                "sources": v.sources,
                "first_found": v.first_found.isoformat() if v.first_found else None,
                "last_found": v.last_found.isoformat() if v.last_found else None,
                "status": v.status,
                "raw_finding_count": v.raw_finding_count,
            }
            for v in asset.vulnerabilities
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the asset correlation engine")
    parser.add_argument("--sources", required=True, help="Directory containing sample JSON files")
    parser.add_argument("--output", required=True, help="Output path for canonical assets JSON")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    from ..loaders.aws_loader import AWSLoader
    from ..loaders.edr_loader import EDRLoader
    from ..loaders.tenable_loader import TenableLoader
    from ..loaders.qualys_loader import QualysLoader

    loaders = {
        "aws_sample.json": AWSLoader(),
        "edr_sample.json": EDRLoader(),
        "tenable_sample.json": TenableLoader(),
        "qualys_sample.json": QualysLoader(),
    }

    sources_dir = Path(args.sources)
    records: list[RawAssetRecord] = []
    for filename, loader in loaders.items():
        path = sources_dir / filename
        if path.exists():
            with open(path) as fh:
                raw = json.load(fh)
            loaded = loader.load(raw if isinstance(raw, list) else [raw])
            records.extend(loaded)
            logger.info("Loaded %d records from %s", len(loaded), filename)
        else:
            logger.debug("Sample file not found (skipped): %s", path)

    engine = CorrelationEngine()
    assets = engine.process(records)

    output = [_serialize_asset(a) for a in assets]
    with open(args.output, "w") as fh:
        json.dump(output, fh, indent=2)

    logger.info("Wrote %d canonical assets to %s", len(output), args.output)
    if engine.flagged_for_review:
        logger.warning("%d assets flagged for review", len(engine.flagged_for_review))


if __name__ == "__main__":
    main()
