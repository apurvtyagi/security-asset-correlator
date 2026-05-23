"""
src/loaders/base_loader.py

Abstract base class and registry for source loaders.

Every loader must:
  1. Inherit from BaseLoader
  2. Set SOURCE = "<tool_name>"
  3. Implement load(raw_records) → list[RawAssetRecord]
  4. Decorate with @register_loader("<tool_name>") to be discoverable at runtime

Usage:
    from src.loaders.base_loader import LoaderRegistry
    loader = LoaderRegistry.get("aws")
    records = loader.load(raw_data)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import ClassVar

from ..correlator.models import RawAssetRecord

logger = logging.getLogger(__name__)

_REGISTRY: dict[str, type[BaseLoader]] = {}


def register_loader(name: str):
    """Class decorator that registers a loader under the given source name."""
    def decorator(cls: type[BaseLoader]) -> type[BaseLoader]:
        _REGISTRY[name.lower()] = cls
        logger.debug("Registered loader: %s → %s", name, cls.__name__)
        return cls
    return decorator


class BaseLoader(ABC):
    """
    Common interface for all source loaders.

    Subclasses normalize source-specific JSON payloads into RawAssetRecord objects.
    Each loader is responsible for exactly one source tool.
    """
    SOURCE: ClassVar[str] = ""

    @abstractmethod
    def load(self, raw_records: list[dict]) -> list[RawAssetRecord]:
        """
        Parse a list of raw JSON records from the source tool and return
        normalized RawAssetRecord objects. Implementations should log and
        skip individual records that fail to parse rather than raising.
        """

    def load_one(self, raw_record: dict) -> RawAssetRecord | None:
        """Convenience wrapper for single-record ingestion. Returns None on failure."""
        try:
            results = self.load([raw_record])
            return results[0] if results else None
        except Exception:
            logger.exception("Loader %s failed on single record", self.__class__.__name__)
            return None


class LoaderRegistry:
    """
    Lookup and instantiate loaders by source name.

    Resolution order:
      1. Python classes decorated with @register_loader  (custom/override loaders)
      2. YAML-configured sources in config/source_mappings.yaml  (zero-code path)

    This means any source defined in the YAML config is immediately available
    via LoaderRegistry.get("mytool") with no Python code changes.
    """

    @staticmethod
    def get(source: str) -> BaseLoader:
        """Return a loader for the given source name."""
        key = source.lower()

        # Python-registered loader takes precedence
        cls = _REGISTRY.get(key)
        if cls is not None:
            return cls()

        # Fall back to YAML-configured GenericLoader
        from .generic_loader import _DEFAULT_MAPPINGS, GenericLoader
        try:
            return GenericLoader.from_config(key, _DEFAULT_MAPPINGS)
        except (KeyError, FileNotFoundError):
            pass

        available = ", ".join(LoaderRegistry.available())
        raise KeyError(
            f"No loader for source '{source}'. "
            f"Available (Python + YAML): {available or '(none)'}"
        )

    @staticmethod
    def available() -> list[str]:
        """Return all source names: Python-registered + YAML-configured."""
        sources: set[str] = set(_REGISTRY.keys())
        try:
            import yaml

            from .generic_loader import _DEFAULT_MAPPINGS
            config = yaml.safe_load(_DEFAULT_MAPPINGS.read_text())
            sources.update(config.get("sources", {}).keys())
        except Exception:
            pass
        return sorted(sources)
