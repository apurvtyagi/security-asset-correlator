# Design Considerations & Edge Cases

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

### IP Address Conflict Resolution

IPs are not a scalar field — treat them as a **time-bound set**. The strategy:

1. **Union-merge** all observed IPs across sources, preserving observation timestamps
2. Apply **staleness decay**: IPs observed >48h ago from non-EDR sources get a freshness flag
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

## Edge Cases

### 1. Hostname Collision (Different Assets, Same Hostname)

**Scenario**: Two dev boxes both named `test-01.local` in different VPCs.

**Risk**: Hostname match layer merges them incorrectly.

**Mitigation**:
- When matching on hostname alone (no hard ID match), require at least one corroborating signal (overlapping IP range, same cloud account, same region)
- Hostnames in RFC-1918 "generic" patterns (`ip-10-x-x-x`, `localhost`, `ubuntu`) automatically downgrade to confidence 0.40
- Log all hostname-only merges separately for audit review

---

### 2. Container / Ephemeral Asset Churn

**Scenario**: EKS pods or Lambda functions spin up/down frequently. Each has a new IP, possibly a new hostname, no EDR agent.

**Risk**: Every pod becomes a new canonical asset; store bloats with thousands of dead records.

**Mitigation**:
- Separate asset type classification: `container`, `cloud_function` vs `server`
- For containers: match on **cluster ARN + pod name prefix** rather than IP or hostname
- Implement TTL-based archiving: assets not seen in 7 days (containers) or 90 days (servers) move to `archived` status, not deleted
- Archived assets are still searchable for historical finding attribution

---

### 3. NAT Gateway / Shared Egress IP

**Scenario**: 40 servers all share the same public egress IP through a NAT gateway. External scanner sees one IP for all of them.

**Risk**: IP match layer incorrectly clusters 40 hosts into one canonical asset.

**Mitigation**:
- Maintain a **known NAT/proxy IP exclusion list** — these IPs are blacklisted from the match layer
- Flag any canonical asset with >3 contributing sources matched on the same public IP for human review
- Prefer private IP matching over public IP matching (private IPs are more likely to be per-host)

---

### 4. Agent Re-Registration (New agent_id, Same Host)

**Scenario**: EDR agent is reinstalled after an OS rebuild. New `agent_id`, same hostname and instance_id.

**Risk**: New canonical asset created for what is functionally the same host, breaking vulnerability history continuity.

**Mitigation**:
- When a new `agent_id` arrives, check if `instance_id` already exists in another canonical record
- If so: merge into existing canonical, log `agent_id` rotation event, archive the old agent_id as a historical reference
- Keep both agent IDs in the record's `historical_agent_ids` list for audit trail

---

### 5. Cloud Provider API Lag

**Scenario**: Instance terminated in AWS. EC2 API still returns it for up to 1 hour. Scanner finds nothing. EDR agent went offline.

**Risk**: Asset appears alive in canonical store longer than it actually is.

**Mitigation**:
- Track **per-source last_seen** timestamps, not just overall last_seen
- Asset state transitions:
  - `active` → `possibly_offline` when any source stops reporting (>24h gap)
  - `possibly_offline` → `offline` when all sources report absence or last_seen >72h
  - `offline` → `terminated` when cloud API explicitly confirms termination
- Never delete terminated assets immediately — retain for 30 days for finding attribution

---

### 6. Multi-NIC / Dual-Stack Assets

**Scenario**: A server has 3 NICs: one management, one data, one HA/heartbeat. Each scanner might observe a different NIC.

**Risk**: IP-based matching fails because each scanner sees a different "primary" IP.

**Mitigation**:
- Treat `ip_addresses` as a set, always union-merge
- Do not use IP as a primary match signal when the source already has a hard ID match path
- For assets with >4 observed IPs from different sources: flag for manual review (potential NAT issue vs legitimate multi-NIC)

---

### 7. Organizational Rename / Hostname Change

**Scenario**: Company renames hostnames from `app-01` to `svc-prod-01` during a migration.

**Risk**: Post-rename records create new canonical assets, breaking vulnerability history.

**Mitigation**:
- Store `previous_hostnames` in canonical record
- When a hard ID match exists, always prefer it over hostname — renaming an asset doesn't break the hard ID trail
- If only hostname match is available: log rename event and preserve historical hostname in `hostname_history`

---

## Recommended Alerting / Observability

| Metric | Threshold | Action |
|--------|-----------|--------|
| `flagged_for_review` queue depth | >50 | Page on-call |
| Canonical assets with 0 EDR coverage | >5% of total | Weekly report |
| Assets seen by scanner but not cloud API | >0 | Alert (shadow IT signal) |
| IP match-only merges | >10% of daily merges | Investigate NAT/proxy list |
| Assets not seen in any source >30 days | >0 | Archive review |
| Conflict log volume increase >2x | Week-over-week | Possible schema change in source tool |

---

## Performance Considerations

### Matching Complexity

Naively, matching is O(n²) — each incoming record compared to every existing canonical. For large environments this breaks down fast.

**Optimizations**:
1. **Inverted indexes** for hard IDs — `instance_id` → `canonical_id` lookup is O(1)
2. **IP bloom filter** — probabilistic membership check before full IP comparison
3. **Hostname prefix index** — bucket by first 4 chars for hostname pre-filtering
4. **Batch processing** — group incoming records by source and cloud account before correlation

### Scale Targets

| Environment Size | Records/Day | Expected Correlation Time |
|-----------------|-------------|--------------------------|
| Small (<1,000 assets) | ~5,000 | <30 seconds |
| Medium (1,000–20,000) | ~100,000 | 2–5 minutes |
| Large (20,000–200,000) | ~1,000,000 | 15–45 minutes (requires indexing) |
| Enterprise (>200,000) | >5,000,000 | Stream processing required (Kafka/Flink) |
