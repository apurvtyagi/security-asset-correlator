"""
src/correlator/risk_scorer.py

Composite risk scoring for canonical assets.

Score is 0.0–10.0 (CVSS-aligned scale) built from four weighted components:

  Vulnerabilities  — up to 5.0  (worst CVE severity + count bonus)
  Exposure         — up to 2.5  (public IP, asset type)
  Coverage gaps    — up to 1.5  (no EDR, no scanner)
  Environment      — up to 1.0  (prod/critical tags)

Severity buckets:  critical ≥ 9.0 | high ≥ 7.0 | medium ≥ 4.0 | low < 4.0

All weights are tunable — subclass RiskScorer and override the component
methods, or adjust the WEIGHTS dict.
"""

from __future__ import annotations

from .models import CanonicalAsset, CanonicalVulnerability

_SEVERITY_BASE: dict[str, float] = {
    "critical": 5.0,
    "high": 3.5,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.0,
}

_EDR_SOURCES = {"edr", "crowdstrike", "sentinelone", "mde", "defender"}
_SCANNER_SOURCES = {"tenable", "qualys", "nessus", "lacework", "wiz", "prisma", "snyk"}
_CLOUD_SOURCES = {"aws", "azure", "gcp"}

_PROD_TAGS = {"prod", "production", "prd", "live", "critical", "tier-1", "tier1"}


class RiskScorer:
    """
    Scores a CanonicalAsset and writes risk_score, risk_severity, risk_factors
    back onto the asset in place.
    """

    def score(self, asset: CanonicalAsset) -> float:
        factors: dict[str, float] = {}

        factors["vulnerabilities"] = round(self._vuln_score(asset.vulnerabilities), 2)
        factors["exposure"] = round(self._exposure_score(asset), 2)
        factors["coverage_gap"] = round(self._coverage_gap_score(asset), 2)
        factors["environment"] = round(self._environment_score(asset), 2)

        total = min(10.0, sum(factors.values()))
        total = round(total, 2)

        asset.risk_score = total
        asset.risk_severity = _severity_label(total)
        asset.risk_factors = factors
        return total

    # ------------------------------------------------------------------
    # Component scorers
    # ------------------------------------------------------------------

    def _vuln_score(self, vulns: list[CanonicalVulnerability]) -> float:
        if not vulns:
            return 0.0
        open_vulns = [v for v in vulns if v.status != "fixed"]
        if not open_vulns:
            return 0.0

        # Base score from worst severity
        worst = max(
            (_SEVERITY_BASE.get(v.severity or "info", 0.0) for v in open_vulns),
            default=0.0,
        )
        # Bonus for volume: each additional vuln adds 0.1 up to 0.5
        count_bonus = min(0.5, (len(open_vulns) - 1) * 0.1)
        return min(5.0, worst + count_bonus)

    def _exposure_score(self, asset: CanonicalAsset) -> float:
        score = 0.0
        # Public IP means internet-reachable
        if any(_is_public(ip) for ip in asset.ip_addresses):
            score += 1.5
        # Servers are higher value targets than workstations
        if asset.asset_type == "server":
            score += 0.5
        elif asset.asset_type == "unknown":
            score += 0.5  # unknown exposure is risky too
        return min(2.5, score)

    def _coverage_gap_score(self, asset: CanonicalAsset) -> float:
        score = 0.0
        sources = set(asset.contributing_sources)
        if not (sources & _EDR_SOURCES):
            score += 0.5   # no endpoint agent
        if not (sources & _SCANNER_SOURCES):
            score += 1.0   # unknown vuln status is the bigger gap
        return min(1.5, score)

    def _environment_score(self, asset: CanonicalAsset) -> float:
        score = 0.0
        all_tag_values = {
            str(v).lower()
            for v in {**asset.tags}.values()
        } | {str(k).lower() for k in asset.tags}
        if all_tag_values & _PROD_TAGS:
            score += 1.0
        return min(1.0, score)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _severity_label(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _is_public(ip: str) -> bool:
    """Return True if the IP is not in a private/loopback/link-local range."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        return False
