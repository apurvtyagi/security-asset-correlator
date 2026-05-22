"""
src/resolvers/hostname_resolver.py

Normalizes hostnames for cross-source comparison and identifies generic/ambiguous
hostnames that should receive reduced confidence scores in the matching layer.

Normalization rules are driven by canonical_mapping.yaml → hostname.normalization.
"""

from __future__ import annotations

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Patterns whose matching hostnames are too generic to be reliable match signals.
# "ip-10-0-1-5" is a valid hostname in AWS but shared naming makes it ambiguous.
_GENERIC_PATTERNS: list[re.Pattern] = [
    re.compile(r"^ip-\d"),       # AWS generic: ip-10-0-4-22
    re.compile(r"^ec2-\d"),      # AWS public DNS prefix
    re.compile(r"^localhost$"),
    re.compile(r"^ubuntu$"),
    re.compile(r"^centos$"),
    re.compile(r"^windows$"),
    re.compile(r"^host-\d"),
    re.compile(r"^node-\d"),
    re.compile(r"^server-\d"),
    re.compile(r"^linux$"),
]

_DEFAULT_STRIP_SUFFIXES = [".local", ".internal", ".corp", ".lan", ".home"]
_DEFAULT_REPLACE_PATTERNS: list[tuple[str, str]] = [
    (r"-prod$", ""),
    (r"-dev$", ""),
    (r"-staging$", ""),
    (r"-stg$", ""),
    (r"-prd$", ""),
]


class HostnameResolver:
    """
    Stateless hostname normalizer and comparator.
    Configuration mirrors the normalization block in canonical_mapping.yaml.
    """

    def __init__(self, normalization_config: Optional[dict] = None):
        cfg = normalization_config or {}
        self.lowercase: bool = cfg.get("lowercase", True)
        self.strip_suffixes: list[str] = cfg.get("strip_suffixes", _DEFAULT_STRIP_SUFFIXES)
        self.strip_prefixes: list[str] = cfg.get("strip_prefixes", [])

        raw_patterns = cfg.get("replace_patterns")
        if raw_patterns:
            self.replace_patterns = [
                (p["pattern"], p["replacement"]) for p in raw_patterns
            ]
        else:
            self.replace_patterns = _DEFAULT_REPLACE_PATTERNS

    def normalize(self, hostname: str) -> str:
        """
        Return a normalized hostname string suitable for equality comparison.
        Empty input returns empty string.
        """
        if not hostname:
            return ""

        h = hostname.strip()
        if self.lowercase:
            h = h.lower()

        # Strip domain suffixes — only first match to avoid double-stripping
        for suffix in self.strip_suffixes:
            if h.endswith(suffix):
                h = h[: -len(suffix)]
                break

        for prefix in self.strip_prefixes:
            if h.startswith(prefix):
                h = h[len(prefix):]
                break

        for pattern, replacement in self.replace_patterns:
            h = re.sub(pattern, replacement, h)

        return h

    def is_generic(self, normalized_hostname: str) -> bool:
        """
        Return True if the hostname is too generic to be a reliable match signal.
        Should be called on the already-normalized form.
        """
        return any(p.match(normalized_hostname) for p in _GENERIC_PATTERNS)

    def match(self, hostname_a: str, hostname_b: str) -> tuple[bool, float]:
        """
        Compare two raw hostnames. Returns (is_match, confidence).
        Generic hostnames get confidence 0.45 instead of 0.85.
        """
        norm_a = self.normalize(hostname_a)
        norm_b = self.normalize(hostname_b)
        if not norm_a or not norm_b:
            return False, 0.0
        if norm_a == norm_b:
            confidence = 0.45 if self.is_generic(norm_a) else 0.85
            return True, confidence
        return False, 0.0
