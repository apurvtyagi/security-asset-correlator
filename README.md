# security-asset-correlator

[![CI](https://github.com/apurvtyagi/security-asset-correlator/actions/workflows/ci.yml/badge.svg)](https://github.com/apurvtyagi/security-asset-correlator/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/security-asset-correlator)](https://pypi.org/project/security-asset-correlator/)
[![Python](https://img.shields.io/pypi/pyversions/security-asset-correlator)](https://pypi.org/project/security-asset-correlator/)
[![codecov](https://codecov.io/gh/apurvtyagi/security-asset-correlator/branch/main/graph/badge.svg)](https://codecov.io/gh/apurvtyagi/security-asset-correlator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Cross-tool canonical asset correlation engine for security operations.

Most security programs don't have a vulnerability problem. They have an asset identity problem. The same EC2 instance appears as four distinct records across your cloud inventory, EDR platform, and vulnerability scanners — each with different findings attached. This project is the glue layer that shouldn't have to exist but usually does.

---

## The Problem

| Tool | How It Knows Your Asset |
|------|------------------------|
| AWS / Cloud Provider | `instanceId: i-0a1b2c3d4e5f` |
| CrowdStrike / EDR | `hostname: prod-api-07.internal` |
| Tenable / Nessus | `ip: 10.0.4.22` (scan-time) |
| Qualys | `ip: 10.0.4.23` (different scan window, NATted) |
| ServiceNow CMDB | `name: PRODAPI007` (manual entry, 8 months stale) |

Each tool reports vulnerabilities against its own asset identifier. Without correlation, a single critical CVE appears 3–4 times in your dashboard. Patch coverage looks worse than it is. MTTR metrics are wrong. Prioritization is impossible.

---

## What This Does

Builds a **canonical asset graph** — one record per real-world entity — by:

1. Ingesting raw asset records from multiple security tool sources
2. Running layered matching logic with explicit confidence scoring
3. Merging duplicates into a canonical record with full source lineage
4. Mapping vulnerability findings to canonical assets (not tool-specific representations)
5. Flagging conflicts with resolution strategy and audit trail

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SOURCE INGESTION                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │  AWS API │  │ EDR API  │  │  Tenable │  │Qualys  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘  │
└───────┼─────────────┼─────────────┼─────────────┼───────┘
        │             │             │             │
        ▼             ▼             ▼             ▼
┌─────────────────────────────────────────────────────────┐
│                  NORMALIZATION LAYER                     │
│  - Hostname sanitization (.local, -prod, case folding)  │
│  - IP deduplication (public vs private, staleness TTL)  │
│  - Metadata normalization (OS, region, tags)            │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│               LAYERED MATCHING ENGINE                    │
│                                                         │
│  Layer 1: Hard ID match (instanceId, MAC, agentUUID)    │
│           → confidence: 0.95–1.00, STOP if matched      │
│                                                         │
│  Layer 2: Hostname match (normalized)                   │
│           → confidence: 0.45–0.85                       │
│                                                         │
│  Layer 3: IP cross-reference (with staleness decay)     │
│           → confidence: 0.60–0.75                       │
│                                                         │
│  Layers 2+3 combined: hostname×0.60 + ip×0.40          │
│                                                         │
│  Layer 4: Metadata correlation (OS + region + account)  │
│           → confidence: up to 0.50                      │
│                                                         │
│  Threshold: merge if score ≥ 0.70, flag if 0.50–0.69   │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              CANONICAL ASSET STORE                      │
│  - One record per physical/virtual entity               │
│  - Source lineage (all contributing records)            │
│  - Conflict log (field disagreements + resolution)      │
│  - Source confidence ranking per field                  │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│            VULNERABILITY DEDUPLICATION                  │
│  - CVE findings mapped to canonical_id                  │
│  - Deduplication by (canonical_id, cve_id)              │
│  - Unified risk score per asset (not per tool record)   │
└─────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
security-asset-correlator/
├── README.md
├── pyproject.toml
├── requirements.txt
├── docker-compose.yml
├── config/
│   ├── source_mappings.yaml         # ★ Field mappings for every source tool (YAML, no Python)
│   ├── canonical_mapping.yaml       # Authority ranks + staleness TTL per field
│   ├── source_confidence.yaml       # Per-source and per-field trust weights
│   └── match_thresholds.yaml        # Merge/flag thresholds + layer score weights
├── src/
│   ├── correlator/
│   │   ├── models.py                # Shared data models (RawAssetRecord, CanonicalAsset, etc.)
│   │   ├── engine.py                # Orchestration + CLI entrypoint
│   │   ├── matcher.py               # 4-layer matching logic
│   │   ├── merger.py                # Canonical record construction
│   │   └── conflict_resolver.py     # Field conflict resolution + audit log
│   ├── loaders/
│   │   ├── base_loader.py           # BaseLoader ABC + LoaderRegistry (auto-discovers YAML sources)
│   │   └── generic_loader.py        # ★ Config-driven loader engine + transform functions
│   ├── store/
│   │   ├── base.py                  # AssetStore interface
│   │   ├── memory.py                # InMemoryStore with O(1) hard-ID indexes (default)
│   │   └── sql.py                   # SQLiteStore + PostgreSQLStore (SQLAlchemy 2.0)
│   ├── resolvers/
│   │   ├── hostname_resolver.py     # Hostname normalization + generic detection
│   │   ├── ip_resolver.py           # IP staleness decay + multi-NIC handling
│   │   └── metadata_resolver.py     # OS family normalization + tag similarity
│   └── api/
│       ├── main.py                  # FastAPI entrypoint
│       └── routes/
│           ├── assets.py            # Canonical asset endpoints
│           ├── vulnerabilities.py   # Deduplicated vuln endpoints
│           └── coverage.py          # Coverage gap analysis endpoints
├── data/
│   └── samples/
│       ├── aws_sample.json
│       ├── edr_sample.json
│       ├── tenable_sample.json
│       └── qualys_sample.json
├── tests/
│   ├── test_matcher.py              # 4-layer matching + confidence scoring
│   ├── test_merger.py               # Record merge + vuln deduplication
│   └── test_conflict_resolver.py    # Authority ranking + conflict log
└── docs/
    ├── design_considerations.md     # Architecture rationale + tuning guide
    └── edge_cases.md                # 8 documented edge cases with mitigations
```

---

## Quick Start

**Install from PyPI**

```bash
pip install security-asset-correlator
```

**Local (development)**

```bash
git clone https://github.com/apurvtyagi/security-asset-correlator
cd security-asset-correlator
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run correlation against sample data
python -m src.correlator.engine --sources data/samples/ --output canonical_assets.json

# Start API server
uvicorn src.api.main:app --reload
```

**Docker**

```bash
docker-compose up
# API available at http://localhost:8000
# Docs at http://localhost:8000/docs
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check |
| `GET` | `/api/v1/assets/` | List canonical assets (filter by source, region, type) |
| `GET` | `/api/v1/assets/{id}` | Single canonical asset |
| `GET` | `/api/v1/assets/{id}/conflicts` | Field-level conflict audit log |
| `POST` | `/api/v1/assets/ingest` | Ingest raw records from a named source |
| `GET` | `/api/v1/assets/review/flagged` | Assets pending human review |
| `GET` | `/api/v1/vulnerabilities/` | Deduplicated findings (filter by severity, CVE, source) |
| `GET` | `/api/v1/vulnerabilities/by-asset/{id}` | Findings for one canonical asset |
| `GET` | `/api/v1/vulnerabilities/summary` | Aggregate stats and top CVEs |
| `GET` | `/api/v1/coverage/` | Full coverage gap report |
| `GET` | `/api/v1/coverage/no-edr` | Assets without EDR agent coverage |
| `GET` | `/api/v1/coverage/no-scanner` | Assets never scanned for vulnerabilities |
| `GET` | `/api/v1/coverage/shadow-it` | Possible unmanaged / shadow-IT devices |

---

## Testing

```bash
pytest tests/
```

59 tests covering:
- Hard ID, hostname, IP, and metadata matching paths
- Confidence score calculation and threshold behaviour
- Scalar field merge with authority-ranked conflict resolution
- List union, tag namespacing, and `last_seen` max logic
- Cross-source CVE deduplication (earliest `first_found`, highest CVSS, source union)
- Full conflict audit log structure and field attribution

---

## Adding a new security tool

The loader layer is fully config-driven. Adding support for a new tool — Lacework, Wiz, Microsoft Defender, Prisma Cloud, or anything else — takes two steps and no new Python files.

**Step 1 — Add a block to `config/source_mappings.yaml`**

```yaml
# Microsoft Defender for Endpoint example
mde:
  source_id_field: id          # which field in the API response is the unique ID
  asset_type: workstation
  fields:
    agent_id: id
    hostnames:
      pick: [computerDnsName]
    ip_addresses:
      field: lastIpAddress
      transform: ensure_list   # built-in: wraps scalar or list → list
    os_name: osPlatform
    os_version: osVersion
    last_seen:
      field: lastSeen
      transform: iso_datetime  # built-in: ISO 8601 string → datetime
```

That's it for most tools. The engine auto-discovers it:

```python
from src.loaders.base_loader import LoaderRegistry

loader = LoaderRegistry.get("mde")          # works immediately
records = loader.load(raw_api_response)     # returns [RawAssetRecord, ...]
```

**Step 2 (only if the tool has an unusual data shape) — add a `@transform` function**

For example, if your tool returns tags as `[{"k": "env", "v": "prod"}]` instead of the common formats:

```python
# src/loaders/generic_loader.py — add alongside the other transforms
@transform("mytool_tags")
def _mytool_tags(value: Any) -> dict:
    if not isinstance(value, list):
        return {}
    return {entry["k"]: entry["v"] for entry in value if "k" in entry}
```

Then reference it by name in the YAML:

```yaml
mytool:
  fields:
    tags:
      field: asset_tags
      transform: mytool_tags
```

**Built-in transforms** (no custom code needed for these common patterns):

| Transform | Input | Output |
|---|---|---|
| `iso_datetime` | ISO 8601 string | `datetime` |
| `ensure_list` | scalar or list | `list` |
| `first_of_list` | list | first non-empty element |
| `dedup_list` | list | deduplicated list |
| `aws_platform_to_os` | `"windows"` / `""` | `"Windows"` / `"Linux"` |
| `az_to_region` | `"us-east-1a"` | `"us-east-1"` |
| `aws_tags_list` | `[{Key, Value}]` | `{key: value}` |
| `mac_to_list` | single MAC string | `["aa:bb:cc:dd:ee:ff"]` |
| `edr_tags` | list of strings or dict | `{str: True}` or passthrough |
| `tenable_tags` | `[{category, value}]` | `{category: value}` |
| `tenable_vulns` | Tenable findings array | `[VulnerabilityFinding]` |
| `qualys_vulns` | Qualys `DETECTIONS` dict | `[VulnerabilityFinding]` |

See [CONTRIBUTING.md](CONTRIBUTING.md) for a full walkthrough.

---

## Configuration

All thresholds and authority rankings are in `config/` — no hardcoded values in the matching or merge logic.

| File | Controls |
|------|----------|
| `source_mappings.yaml` | Field mappings for every source tool — edit to add new tools |
| `canonical_mapping.yaml` | Authority ranks per field per source, staleness TTL |
| `source_confidence.yaml` | Per-source and per-field trust weights |
| `match_thresholds.yaml` | Merge/flag thresholds, layer scores, combination weights |

To adjust who wins a hostname conflict between EDR and AWS, change `canonical_fields.hostname.authority_rank` in `canonical_mapping.yaml`. To make IP matching more conservative in a heavy-NAT environment, lower `layer_scores.ip.private_ip_match` in `match_thresholds.yaml`.

---

## Design Principles

- **Prefer explicit over inferred** — hard identifiers always win over heuristic matches
- **Source authority is per-field, not per-source** — AWS is authoritative for `region` but not `hostname`; EDR is authoritative for `hostname` but not `instanceId`
- **Conflicts are data** — every field disagreement is logged with both values, both sources, both authority ranks, and the resolution taken
- **Merge threshold is tunable** — default 0.70 works for most environments; high-churn ephemeral infra may need adjustment
- **No silent drops** — unmatched records are surfaced, not discarded; ambiguous matches are flagged for human review

---

## Storage backends

The engine uses a pluggable `AssetStore` interface with two built-in backends:

| Backend | When to use |
|---------|-------------|
| `InMemoryStore` (default) | Single-process, ephemeral, tests |
| `SQLiteStore` | Single-server persistent deployments |
| `PostgreSQLStore` | Multi-instance / high-availability |

```python
from src.correlator.engine import CorrelationEngine
from src.store.sql import SQLiteStore

store = SQLiteStore("sqlite:///assets.db")
store.init_schema()
engine = CorrelationEngine(store=store)
```

For PostgreSQL, install the extra and pass a `postgresql://` URL:

```bash
pip install security-asset-correlator[postgres]
```

```python
from src.store.sql import PostgreSQLStore
store = PostgreSQLStore("postgresql://user:pass@host/dbname")
```

---

## Coverage gap analysis

After ingesting records, call the coverage report to find blind spots:

```bash
GET /api/v1/coverage/
```

```json
{
  "total_assets": 142,
  "no_edr":     { "count": 18, "canonical_ids": ["..."] },
  "no_scanner": { "count": 9,  "canonical_ids": ["..."] },
  "shadow_it":  { "count": 3,  "canonical_ids": ["..."] }
}
```

- **no_edr** — assets not enrolled in any endpoint agent (CrowdStrike, SentinelOne)
- **no_scanner** — assets that have never been scanned by Tenable or Qualys
- **shadow_it** — assets seen only by scanners with no cloud inventory or EDR record — possible unmanaged devices

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide, including how to add a new source loader in ~30 minutes.

Issues for new source loaders, edge case coverage, and confidence model improvements especially appreciated.

---

## License

MIT
