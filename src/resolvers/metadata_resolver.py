"""
src/resolvers/metadata_resolver.py

Normalizes OS names, cloud regions, and tag structures for cross-source comparison.
Used by the metadata correlation layer (Layer 4) in the matching engine
and optionally by loaders for enrichment during normalization.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Map OS substrings to canonical family names for fuzzy OS comparison
_OS_FAMILIES: dict[str, list[str]] = {
    "windows": ["windows server", "windows 10", "windows 11", "windows"],
    "debian_family": ["ubuntu", "debian", "kali", "mint", "pop!_os"],
    "rhel_family": [
        "red hat", "rhel", "centos", "rocky linux", "almalinux",
        "amazon linux", "fedora", "oracle linux",
    ],
    "suse_family": ["suse", "opensuse"],
    "arch_family": ["arch linux", "manjaro"],
    "macos": ["macos", "mac os x", "darwin"],
}

# Strip trailing AZ letter (us-east-1a → us-east-1)
_AZ_SUFFIX_PATTERN = re.compile(r"[a-z]$")


class MetadataResolver:
    """
    Stateless normalizer for OS names, cloud regions, and tag dictionaries.
    All methods are pure functions — no state required.
    """

    def normalize_os(self, os_name: str) -> str:
        """
        Map a raw OS string to a normalized OS family name.
        Returns the original lowercased string if no family matches.
        """
        if not os_name:
            return "unknown"
        lower = os_name.lower()
        for family, patterns in _OS_FAMILIES.items():
            if any(p in lower for p in patterns):
                return family
        return lower

    def normalize_region(self, region: str) -> str:
        """
        Strip trailing availability-zone characters from a cloud region string.
        e.g. "us-east-1a" → "us-east-1", "eastus" → "eastus" (unchanged)
        """
        if not region:
            return ""
        r = region.lower().strip()
        # Only strip the AZ suffix when the region has the "x-y-1" AWS pattern
        if re.match(r"^[a-z]+-[a-z]+-\d+[a-z]$", r):
            r = _AZ_SUFFIX_PATTERN.sub("", r)
        return r

    def tag_similarity(self, tags_a: dict, tags_b: dict) -> float:
        """
        Return a Jaccard-like similarity score [0.0, 1.0] between two tag dicts.
        Strips source namespace prefixes before comparing so that
        "aws:env"="prod" and "edr:env"="prod" are treated as the same key-value.
        """
        if not tags_a or not tags_b:
            return 0.0

        def strip_namespace(tags: dict) -> dict[str, str]:
            result: dict[str, str] = {}
            for k, v in tags.items():
                key = k.split(":", 1)[-1].lower() if ":" in k else k.lower()
                result[key] = str(v).lower()
            return result

        a_norm = strip_namespace(tags_a)
        b_norm = strip_namespace(tags_b)

        if not a_norm or not b_norm:
            return 0.0

        shared_keys = set(a_norm.keys()) & set(b_norm.keys())
        if not shared_keys:
            return 0.0

        matching_pairs = sum(1 for k in shared_keys if a_norm[k] == b_norm[k])
        union_size = len(set(a_norm.keys()) | set(b_norm.keys()))
        return matching_pairs / union_size if union_size else 0.0

    def normalize_mac(self, mac: str) -> str:
        """Normalize MAC address to lowercase colon-separated format."""
        if not mac:
            return ""
        # Accept both colon and hyphen separators
        normalized = mac.lower().replace("-", ":").strip()
        return normalized
