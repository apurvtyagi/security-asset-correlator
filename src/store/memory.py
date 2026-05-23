"""
src/store/memory.py

In-memory asset store with O(1) inverted indexes for hard-ID lookups.
Default backend — no external dependencies, suitable for single-process deployments
and tests. State is lost on process restart.
"""

from __future__ import annotations

from typing import Optional

from ..correlator.models import CanonicalAsset
from .base import AssetStore


class InMemoryStore(AssetStore):
    def __init__(self) -> None:
        self._assets: dict[str, CanonicalAsset] = {}
        # Inverted indexes for O(1) hard-ID lookup
        self._by_instance_id: dict[str, str] = {}   # instance_id → canonical_id
        self._by_agent_id: dict[str, str] = {}       # agent_id → canonical_id
        self._flagged: list[dict] = []

    def save(self, asset: CanonicalAsset) -> None:
        existing = self._assets.get(asset.canonical_id)
        if existing:
            # Clean up stale index entries if hard IDs changed
            if existing.instance_id and existing.instance_id != asset.instance_id:
                self._by_instance_id.pop(existing.instance_id, None)
            if existing.agent_id and existing.agent_id != asset.agent_id:
                self._by_agent_id.pop(existing.agent_id, None)

        self._assets[asset.canonical_id] = asset

        if asset.instance_id:
            self._by_instance_id[asset.instance_id] = asset.canonical_id
        if asset.agent_id:
            self._by_agent_id[asset.agent_id] = asset.canonical_id

    def get(self, canonical_id: str) -> Optional[CanonicalAsset]:
        return self._assets.get(canonical_id)

    def get_all(self) -> list[CanonicalAsset]:
        return list(self._assets.values())

    def count(self) -> int:
        return len(self._assets)

    def add_flagged(self, flag: dict) -> None:
        self._flagged.append(flag)

    def get_flagged(self) -> list[dict]:
        return list(self._flagged)

    def find_by_instance_id(self, instance_id: str) -> Optional[CanonicalAsset]:
        cid = self._by_instance_id.get(instance_id)
        return self._assets.get(cid) if cid else None

    def find_by_agent_id(self, agent_id: str) -> Optional[CanonicalAsset]:
        cid = self._by_agent_id.get(agent_id)
        return self._assets.get(cid) if cid else None
