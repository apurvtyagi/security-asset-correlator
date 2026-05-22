# security-asset-correlator

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
│           → confidence: 1.00, STOP if matched           │
│                                                         │
│  Layer 2: Hostname match (normalized)                   │
│           → confidence: 0.85                            │
│                                                         │
│  Layer 3: IP cross-reference (with staleness decay)     │
│           → confidence: 0.60 - 0.75                     │
│                                                         │
│  Layer 4: Metadata correlation (OS + region + tags)     │
│           → confidence: 0.40                            │
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
│  - Deduplication by (canonical_id, cve_id, component)  │
│  - Unified risk score per asset (not per tool record)   │
└─────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
security-asset-correlator/
├── README.md
├── config/
│   ├── canonical_mapping.yaml       # Field mapping rules per source
│   ├── source_confidence.yaml       # Source trust weights per field type
│   └── match_thresholds.yaml        # Tunable merge/flag thresholds
├── src/
│   ├── correlator/
│   │   ├── engine.py                # Core correlation orchestration
│   │   ├── matcher.py               # Layered matching logic
│   │   ├── merger.py                # Canonical record construction
│   │   └── conflict_resolver.py     # Field conflict resolution
│   ├── loaders/
│   │   ├── aws_loader.py            # AWS EC2/SSM inventory ingestion
│   │   ├── edr_loader.py            # CrowdStrike/SentinelOne loader
│   │   ├── tenable_loader.py        # Tenable.io asset + vuln loader
│   │   └── qualys_loader.py         # Qualys VMDR loader
│   ├── resolvers/
│   │   ├── hostname_resolver.py     # Hostname normalization + matching
│   │   ├── ip_resolver.py           # IP staleness + multi-NIC handling
│   │   └── metadata_resolver.py     # Tag/OS/region correlation
│   └── api/
│       ├── main.py                  # FastAPI entrypoint
│       └── routes/
│           ├── assets.py            # Canonical asset endpoints
│           └── vulnerabilities.py   # Deduplicated vuln endpoints
├── data/
│   └── samples/
│       ├── aws_sample.json          # Sample AWS asset data
│       ├── edr_sample.json          # Sample EDR asset data
│       ├── tenable_sample.json      # Sample Tenable findings
│       └── qualys_sample.json       # Sample Qualys findings
├── tests/
│   ├── test_matcher.py
│   ├── test_merger.py
│   └── test_conflict_resolver.py
├── docs/
│   ├── design_considerations.md
│   └── edge_cases.md
├── docker-compose.yml
└── requirements.txt
```

---

## Quick Start

```bash
git clone https://github.com/your-org/security-asset-correlator
cd security-asset-correlator
pip install -r requirements.txt

# Run correlation against sample data
python -m src.correlator.engine --sources data/samples/ --output canonical_assets.json

# Start API
uvicorn src.api.main:app --reload
```

---

## Configuration

See `config/canonical_mapping.yaml` for full field mapping. See `config/source_confidence.yaml` for tunable trust weights per source and field type.

---

## Design Principles

- **Prefer explicit over inferred** — hard identifiers always win over heuristic matches
- **Source confidence is per-field, not per-source** — AWS is authoritative for `region` but not `hostname`; EDR is authoritative for `hostname` but not `instanceId`
- **Conflicts are data** — every disagreement is logged, not silently resolved
- **Merge threshold is tunable** — default 0.70 works for most environments; high-churn ephemeral infra may need adjustment
- **No silent drops** — unmatched records are surfaced, not discarded

---

## Contributing

PRs welcome. Issues for new source loaders, edge case coverage, and confidence model improvements especially appreciated.

---

## License

MIT
