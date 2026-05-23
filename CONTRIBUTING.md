# Contributing to security-asset-correlator

This guide covers everything you need to add a new source loader, fix a bug, or improve the matching logic.

---

## Setup

```bash
git clone https://github.com/apurvtyagi/security-asset-correlator
cd security-asset-correlator
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Run the test suite to confirm everything works:

```bash
pytest tests/ -q
```

---

## Adding a new source loader (~15 min, no Python required)

The loader layer is config-driven. For most tools you only need to edit one YAML file.
Python is only needed if the tool uses an unusual data shape that no built-in transform covers.

### Path A — YAML only (most tools)

**Step 1 — Add a block to `config/source_mappings.yaml`**

```yaml
mytool:
  source_id_field: id          # field in the API response that uniquely identifies the asset
  asset_type: server           # default asset type for this source
  fields:
    # Direct field mapping — source field name on the right
    instance_id: cloud_vm_id
    os_name: os_platform

    # Collect multiple source fields into a list
    hostnames:
      pick: [fqdn, netbios_name]

    # Scalar field with a built-in transform
    ip_addresses:
      field: primary_ip
      transform: ensure_list   # wraps a scalar or list → list

    last_seen:
      field: last_contact_time
      transform: iso_datetime  # ISO 8601 string → datetime
```

**Step 2 — Verify it works**

```python
from src.loaders.base_loader import LoaderRegistry

loader = LoaderRegistry.get("mytool")   # auto-discovered from YAML
records = loader.load(raw_api_response)
print(records[0].hostnames, records[0].ip_addresses)
```

That's all. No new Python files.

---

### Path B — YAML + one transform function (unusual data shapes)

If the tool serialises a field in a shape that no built-in transform handles, add a
function to `src/loaders/generic_loader.py` and reference it by name in the YAML.

```python
# src/loaders/generic_loader.py — add alongside the other @transform functions
@transform("mytool_tags")
def _mytool_tags(value: Any) -> dict:
    """[{"k": "env", "v": "prod"}] → {"env": "prod"}"""
    if not isinstance(value, list):
        return {}
    return {entry["k"]: entry["v"] for entry in value if "k" in entry}
```

```yaml
# config/source_mappings.yaml
mytool:
  fields:
    tags:
      field: asset_tags
      transform: mytool_tags   # name matches the @transform decorator argument
```

For tools that also expose vulnerability data, add a `vulnerabilities` block:

```yaml
mytool:
  fields:
    # ... asset fields ...
  vulnerabilities:
    field: findings            # path to the findings array in the API response
    transform: mytool_vulns    # transform that returns list[VulnerabilityFinding]
```

---

### Built-in transforms reference

| Transform | Input | Output |
|---|---|---|
| `iso_datetime` | ISO 8601 string | `datetime` |
| `ensure_list` | scalar or list | `list` |
| `first_of_list` | list | first non-empty element |
| `dedup_list` | list | deduplicated, order-preserving list |
| `aws_platform_to_os` | `"windows"` / `""` | `"Windows"` / `"Linux"` |
| `az_to_region` | `"us-east-1a"` | `"us-east-1"` |
| `aws_tags_list` | `[{Key, Value}]` | `{key: value}` |
| `mac_to_list` | single MAC string | `["aa:bb:cc:dd:ee:ff"]` |
| `edr_tags` | list of strings or dict | `{str: True}` or passthrough |
| `tenable_tags` | `[{category, value}]` | `{category: value}` |
| `tenable_vulns` | Tenable findings array | `list[VulnerabilityFinding]` |
| `qualys_vulns` | Qualys `DETECTIONS` dict | `list[VulnerabilityFinding]` |

---

### Fields that drive match confidence

Populate as many of these as your tool exposes — the more hard IDs, the fewer false merges:

| Field | Confidence impact |
|---|---|
| `instance_id` | 1.00 — hard ID, stops search immediately |
| `agent_id` | 1.00 — hard ID, stops search immediately |
| `mac_addresses` | 0.95 — hard ID (real NICs only; virtual OUIs are excluded) |
| `hostnames` | 0.45–0.85 — normalised hostname match |
| `ip_addresses` | 0.60–0.75 — with staleness decay after 48 h |

---

### Checklist before opening a PR

- [ ] Block added to `config/source_mappings.yaml`
- [ ] `LoaderRegistry.get("mytool")` works and returns correct `RawAssetRecord` fields
- [ ] Sample data added to `data/samples/<tool>_sample.json` (anonymised)
- [ ] Tests added (in `tests/test_loaders.py` or a new file)
- [ ] `ruff check src/ tests/` passes
- [ ] `pytest tests/ -q` passes

Use the **New Source Loader Request** issue template if you want feedback before building.

---

## Improving matching logic

All thresholds live in `config/match_thresholds.yaml`. No hardcoded values in Python. To experiment:

- Raise `layer_scores.hostname.exact_normalized_match` for environments where hostnames are highly reliable
- Lower `layer_scores.ip.private_ip_match` for heavy-NAT environments
- Adjust `thresholds.merge_threshold` to 0.80 for stricter auto-merge (more human review)

See `docs/design_considerations.md` for the reasoning behind the defaults.

---

## Code style

- Lint: `ruff check src/ tests/`
- Format: `ruff format src/ tests/`
- Type check: `mypy src/ --ignore-missing-imports`

CI runs all three. The type check is non-blocking for now (annotating gradually).

---

## PR process

1. Fork, create a branch from `main`
2. Make changes, add/update tests
3. Run `pytest tests/ -q` — all tests must pass
4. Open a PR against `main` — fill in the template

For new loaders, use the **New Source Loader Request** issue template first if you want feedback before building.

---

## Project structure quick reference

```
config/
  source_mappings.yaml    ← edit this to add a new source tool (no Python needed)
  match_thresholds.yaml   ← tune merge/flag confidence thresholds
  canonical_mapping.yaml  ← per-field authority rankings across sources

src/
  loaders/
    generic_loader.py     ← config-driven loader engine + all @transform functions
    base_loader.py        ← BaseLoader ABC + LoaderRegistry (auto-discovers YAML sources)
  correlator/             ← matching, merging, conflict resolution, engine orchestration
  resolvers/              ← hostname/IP/metadata normalisation helpers
  store/                  ← pluggable persistence: InMemoryStore, SQLiteStore, PostgreSQLStore
  api/                    ← FastAPI routes (assets, vulnerabilities, coverage)

tests/                    ← pytest suite covering all matching/merge/conflict paths
docs/                     ← architecture rationale + edge case documentation
```
