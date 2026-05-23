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

## Adding a new source loader (30 min)

Each loader is ~80 lines. The pattern is always the same:

1. **Create `src/loaders/<tool>_loader.py`**

```python
from ..loaders.base_loader import BaseLoader, register_loader
from ..correlator.models import RawAssetRecord

@register_loader("mytool")
class MyToolLoader(BaseLoader):
    SOURCE = "mytool"

    def load(self, raw_records: list[dict]) -> list[RawAssetRecord]:
        return [self._normalize(r) for r in raw_records if r]

    def _normalize(self, record: dict) -> RawAssetRecord:
        return RawAssetRecord(
            source=self.SOURCE,
            source_id=record["id"],
            hostnames=[record.get("hostname", "")],
            ip_addresses=record.get("ips", []),
            # ... map other fields to the canonical model
        )
```

The fields that enable high-confidence matches are:

| Field | Confidence impact |
|---|---|
| `instance_id` | 1.00 (hard ID, stops search) |
| `agent_id` | 1.00 (hard ID, stops search) |
| `mac_addresses` | 0.95 (hard ID if real NIC) |
| `hostnames` | 0.45–0.85 (normalized match) |
| `ip_addresses` | 0.60–0.75 (with staleness decay) |

2. **Add sample data to `data/samples/<tool>_sample.json`** — anonymised, representative.

3. **Write tests in `tests/test_loaders.py`** (or a new file):

```python
def test_mytool_loader_maps_hostname():
    loader = MyToolLoader()
    records = loader.load([{"id": "abc", "hostname": "web-01"}])
    assert records[0].hostnames == ["web-01"]
```

4. **Open a PR** — the CI will run lint + tests automatically.

The `@register_loader("mytool")` decorator makes your loader available via `LoaderRegistry.get("mytool")` so the engine and API can discover it without hardcoding.

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
src/
  correlator/       Core engine: models, matcher, merger, conflict resolver
  loaders/          One file per source tool. base_loader.py has the interface.
  resolvers/        Hostname/IP/metadata normalization and scoring helpers
  store/            Pluggable asset persistence (in-memory + SQLite/PostgreSQL)
  api/              FastAPI app and route handlers
config/             Tunable thresholds and authority rankings (YAML, no hardcoded values)
tests/              Pytest suite — unit tests for each layer
docs/               Design rationale and edge case documentation
```
