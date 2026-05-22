# Design Considerations

## Conflict Resolution Strategy

### Field-Level Authority Model

Conflict resolution operates at the **field level**, not the source level. A source that is authoritative for `cloud_region` may not be authoritative for `hostname`. The mapping is:

| Field | Most Authoritative | Least Authoritative |
|-------|-------------------|---------------------|
| `instance_id` | AWS/Azure/GCP APIs | Scanners (may observe, not own) |
| `hostname` | EDR agent (OS-reported) | CMDB (manual, often stale) |
| `os_name` | EDR agent | Cloud metadata |
| `ip_addresses` | Cloud provider | Scanner (point-in-time observation) |
| `cloud_region` | Cloud provider API | Any other source |

Authority ranks are configured in `config/canonical_mapping.yaml` and loaded at startup. To change who wins a conflict, edit the config — not the code.

### IP Address Conflict Resolution

IPs are not a scalar field — treat them as a **time-bound set**. The strategy:

1. **Union-merge** all observed IPs across sources, preserving observation timestamps
2. Apply **staleness decay**: IPs observed >48h ago from non-EDR sources get reduced confidence in future matches
3. Mark IPs as `stale` rather than removing them — they may re-appear and are useful for historical correlation
4. Never use a stale IP as a primary match signal, but include it in the union

```
ip_history:
  - address: 10.0.4.22
    observed_by: [aws, edr, tenable]
    last_seen: 2026-05-22T08:44:12Z
    status: current

  - address: 10.0.4.23
    observed_by: [qualys]
    last_seen: 2026-05-19T14:30:00Z
    status: stale   # 3 days old, secondary NIC
```

---

## Matching Architecture

### Why 4 Layers?

Each successive layer is less reliable and requires the previous layers to have failed:

| Layer | Signal | Reliability | Risk of false positive |
|-------|--------|-------------|----------------------|
| Hard ID | instance_id, agent_id, MAC | Near-certain | Very low |
| Hostname | Normalized FQDN | High | Medium (generic hostnames) |
| IP | Shared IPs w/ staleness | Medium | Higher (NAT, DHCP churn) |
| Metadata | OS + region + account | Low | High alone, useful as tiebreaker |

The combination weight system (`hostname × 0.60 + ip × 0.40`) means:
- Strong hostname + strong public IP = 0.81 → auto-merge
- Hostname only = 0.51 → flag for review
- Weak IP only = 0.24 → new asset

### Threshold Tuning

The `config/match_thresholds.yaml` values `merge_threshold: 0.70` and `flag_threshold: 0.50` are appropriate for most production environments. Adjust if:

- **High-churn ephemeral infra (ECS/Lambda)**: Raise `flag_threshold` to 0.55–0.60 to reduce false reviews
- **Very stable infrastructure with consistent naming**: Lower `merge_threshold` to 0.65 to be more aggressive about merging
- **Heavy NIC/NAT environments**: Lower the private IP confidence score or add known NAT IPs to `KNOWN_NAT_EXCLUSIONS` in `ip_resolver.py`

---

## Source Loaders

### Design Principles

Each loader is responsible for:
1. Accepting the raw tool API response format (lists or single objects)
2. Mapping source-specific field names to `RawAssetRecord` fields
3. Normalizing types (list fields, datetime parsing, MAC case normalization)
4. Extracting vulnerability findings into `VulnerabilityFinding` objects
5. Graceful error handling — one bad record should not block the batch

### Adding a New Source

1. Create `src/loaders/{source}_loader.py` with a class extending the loader pattern
2. Set `SOURCE = "your_source_name"`
3. Add field mappings to `config/canonical_mapping.yaml` under `source_mappings`
4. Add authority ranks for each field in `canonical_fields[field_name].authority_rank`
5. Register the loader in `src/correlator/engine.py` CLI and `src/api/routes/assets.py`

---

## Vulnerability Deduplication

Deduplication key: `(canonical_id, cve_id)`. A CVE reported by both Tenable and Qualys against the same canonical asset produces exactly one `CanonicalVulnerability` with:
- `sources: ["tenable", "qualys"]`
- `first_found`: earliest observation date across all sources
- `last_found`: most recent observation date
- `cvss3_base`: highest score reported
- `raw_finding_count`: total number of individual findings collapsed

This means MTTR and coverage metrics operate on real unique vulnerabilities, not inflated scanner counts.

---

## Performance Considerations

### Matching Complexity

Naively, matching is O(n²) — each incoming record compared to every existing canonical. For large environments this breaks down fast.

**Current optimizations (implemented)**:
- Hard-ID short-circuit: first 1.0-confidence match stops scanning
- Layer ordering: cheap hard-ID check before expensive hostname/IP comparison

**For scale (not yet implemented)**:
1. **Inverted indexes** for hard IDs — `instance_id` → `canonical_id` lookup is O(1)
2. **IP set intersection** — use Python `set` operations (already done at IP level)
3. **Hostname prefix index** — bucket by first 4 chars for pre-filtering
4. **Batch processing** — group by source and cloud account before correlation

### Scale Targets

| Environment Size | Records/Day | Expected Correlation Time |
|-----------------|-------------|--------------------------|
| Small (<1,000 assets) | ~5,000 | <30 seconds |
| Medium (1,000–20,000) | ~100,000 | 2–5 minutes |
| Large (20,000–200,000) | ~1,000,000 | 15–45 minutes (requires indexing) |
| Enterprise (>200,000) | >5,000,000 | Stream processing required (Kafka/Flink) |
