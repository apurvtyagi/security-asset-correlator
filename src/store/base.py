"""
src/store/base.py

Abstract interface for canonical asset persistence.
Swap InMemoryStore for SQLiteStore (or a PostgreSQL variant) without changing
any engine or API code — only the store implementation changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..correlator.models import CanonicalAsset


class AssetStore(ABC):
    """Pluggable persistence backend for canonical assets and review flags."""

    # --- canonical asset CRUD ---

    @abstractmethod
    def save(self, asset: CanonicalAsset) -> None:
        """Upsert a canonical asset. Insert on first call, update on subsequent."""

    @abstractmethod
    def get(self, canonical_id: str) -> CanonicalAsset | None:
        """Return the asset for the given ID, or None if not found."""

    @abstractmethod
    def get_all(self) -> list[CanonicalAsset]:
        """Return all canonical assets in the store."""

    @abstractmethod
    def count(self) -> int:
        """Return the total number of canonical assets."""

    # --- review flag queue ---

    @abstractmethod
    def add_flagged(self, flag: dict) -> None:
        """Add a review flag (ambiguous match that needs human triage)."""

    @abstractmethod
    def get_flagged(self) -> list[dict]:
        """Return all pending review flags."""

    # --- convenience lookups (optional O(1) fast path) ---

    def find_by_instance_id(self, instance_id: str) -> CanonicalAsset | None:
        """Linear scan default — override for O(1) in production stores."""
        for asset in self.get_all():
            if asset.instance_id == instance_id:
                return asset
        return None

    def find_by_agent_id(self, agent_id: str) -> CanonicalAsset | None:
        """Linear scan default — override for O(1) in production stores."""
        for asset in self.get_all():
            if asset.agent_id == agent_id:
                return asset
        return None
