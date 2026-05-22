# Edge Cases

Documented edge cases for the asset correlation engine, with the scenario, the risk, and the mitigation implemented or recommended.

---

## 1. Hostname Collision (Different Assets, Same Hostname)

**Scenario**: Two dev boxes both named `test-01.local` in different VPCs.

**Risk**: Hostname match layer merges them incorrectly.

**Mitigation**:
- When matching on hostname alone (no hard ID match), the combined confidence (`0.85 × 0.60 = 0.51`) falls in the *flag for review* zone, not the *auto-merge* zone
- Generic hostname patterns (`ip-10-x-x-x`, `localhost`, `ubuntu`) automatically downgrade to confidence 0.45, producing 0.45 × 0.60 = 0.27 — below the flag threshold
- Hostname-only merges are distinguishable in the conflict log via `match_layer = "hostname"`

**Config lever**: Lower `layer_scores.hostname.exact_normalized_match` in `config/match_thresholds.yaml` to further reduce hostname-only confidence.

---

## 2. Container / Ephemeral Asset Churn

**Scenario**: EKS pods or Lambda functions spin up/down frequently. Each has a new IP, possibly a new hostname, no EDR agent.

**Risk**: Every pod becomes a new canonical asset; store bloats with thousands of dead records.

**Mitigation**:
- Separate `asset_type` classification: `container`, `cloud_function` vs `server`
- For containers: match on **cluster ARN + pod name prefix** rather than IP or hostname (requires custom loader)
- TTL-based archiving: assets not seen in 7 days (containers) or 90 days (servers) transition to `archived` status via `lifecycle.archive_days_ephemeral` config
- Archived assets remain searchable for historical finding attribution

---

## 3. NAT Gateway / Shared Egress IP

**Scenario**: 40 servers all share the same public egress IP through a NAT gateway. An external scanner sees one IP for all of them.

**Risk**: IP match layer incorrectly clusters 40 hosts into one canonical asset.

**Mitigation**:
- `src/resolvers/ip_resolver.py` maintains a `KNOWN_NAT_EXCLUSIONS` set — add shared egress IPs here
- Any canonical asset with >3 contributing sources matched on the same public IP should be flagged for manual review
- Private IP matching (RFC-1918) is preferred over public IP matching in environments with consistent NAT

**Config lever**: Populate `KNOWN_NAT_EXCLUSIONS` in `ip_resolver.py` or load from config. Per-VPC NAT gateway IPs should always be excluded.

---

## 4. Agent Re-Registration (New `agent_id`, Same Host)

**Scenario**: EDR agent is reinstalled after an OS rebuild. New `agent_id`, same hostname and `instance_id`.

**Risk**: New canonical asset created for what is functionally the same host, breaking vulnerability history continuity.

**Mitigation**:
- When a new `agent_id` arrives, the `instance_id` hard-ID match (confidence 1.0) will still match the existing canonical record — the new agent ID is simply added via the merger
- The old `agent_id` is preserved in `source_records` for audit trail
- If `instance_id` is also absent: hostname + IP combination match (0.81 if both present) will auto-merge

**Recommended enhancement**: Add a `historical_agent_ids` list to `CanonicalAsset` to explicitly track agent rotations.

---

## 5. Cloud Provider API Lag

**Scenario**: Instance terminated in AWS. EC2 API still returns it for up to 1 hour. Scanner finds nothing. EDR agent went offline.

**Risk**: Asset appears alive in canonical store longer than it actually is.

**Mitigation**:
- Track per-source last_seen (stored in `source_records` list) in addition to overall `last_seen`
- Asset lifecycle status transitions (driven by `config/match_thresholds.yaml → lifecycle`):
  - `active` → `possibly_offline`: no source reporting for >24h
  - `possibly_offline` → `offline`: >72h
  - `offline` → `terminated`: cloud API explicit confirmation
- Terminated assets are retained for 30 days (`lifecycle.terminated_retention_days`) for finding attribution before archival

**Status transitions are not yet automated** — they require a scheduled job that reads `last_seen` per asset and compares against current time.

---

## 6. Multi-NIC / Dual-Stack Assets

**Scenario**: A server has 3 NICs: management, data, and HA/heartbeat. Each scanner might observe a different NIC.

**Risk**: IP-based matching fails because each scanner sees a different "primary" IP.

**Mitigation**:
- `ip_addresses` is always union-merged — all NICs from all sources end up in the canonical record
- IP matching uses set intersection, so any overlap on *any* NIC triggers a match
- Assets with >4 observed IPs from different sources are candidates for the NAT/proxy check

---

## 7. Organizational Rename / Hostname Change

**Scenario**: Company renames hostnames from `app-01` to `svc-prod-01` during a migration.

**Risk**: Post-rename records create new canonical assets, breaking vulnerability history.

**Mitigation**:
- If `instance_id` is present (cloud assets): hard-ID match (confidence 1.0) catches the rename regardless of hostname change
- If only hostname match is available: old hostname triggers a flag-for-review (confidence 0.51 without IP corroboration) rather than a new asset + silent drop of history
- Post-rename: operator should manually merge the flagged record into the existing canonical

**Recommended enhancement**: Add `previous_hostnames: list[str]` to `CanonicalAsset` and populate it when a hostname conflict resolves via replacement.

---

## 8. Qualys IP Tracking Mode

**Scenario**: Qualys tracks assets by IP (its default `TRACKING_METHOD`). If an IP is reassigned to a new host, Qualys treats it as the same asset.

**Risk**: Qualys findings for a new host get attributed to the previous host's canonical record via IP match.

**Mitigation**:
- Qualys IP matches only score 0.60 (private) or 0.75 (public), and only contribute 40% of the combined score
- Without a corroborating hostname or hard ID, the Qualys record will be flagged for review rather than auto-merged
- After IP reassignment: operator should check flagged records for any Qualys records matching on a previously-active IP

---

## Recommended Observability Metrics

| Metric | Alert Threshold | Action |
|--------|----------------|--------|
| `flagged_for_review` queue depth | >50 | Page on-call |
| Canonical assets with 0 EDR coverage | >5% of total | Weekly report |
| Assets seen by scanner but not cloud API | >0 | Alert (shadow IT signal) |
| IP-only merges | >10% of daily merges | Investigate NAT/proxy list |
| Assets not seen in any source >30 days | Any | Archive review |
| Conflict volume increase >2× week-over-week | Any | Possible schema change upstream |
| Same CVE in >50 canonical assets | Any | Check for false-positive finding |
