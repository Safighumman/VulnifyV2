"""Turn a ranked CVE into a one-sentence, plain-English risk summary.

The target reader is the non-specialist sysadmin in Use Case 1 of the brief:
the output must be actionable without security expertise. Each summary states
what is affected, how likely exploitation is (EPSS), whether it is already
being exploited (KEV), and a clear recommended action.
"""

from __future__ import annotations

from . import config
from .ranking import RankedCve


def _epss_band(epss: float | None) -> str:
    if epss is None:
        return "an unrated"
    if epss >= config.EPSS_HIGH:
        return "a high"
    if epss >= config.EPSS_MODERATE:
        return "a moderate"
    return "a low"


def _severity_word(score: float | None) -> str:
    if score is None:
        return "unrated"
    if score >= config.CVSS_CRITICAL:
        return "critical"
    if score >= config.CVSS_HIGH:
        return "high"
    if score >= config.CVSS_MEDIUM:
        return "medium"
    return "low"


def recommended_action(r: RankedCve) -> str:
    """A short, prioritised next step for the administrator."""
    if r.in_kev and r.kev_ransomware:
        return "Patch immediately: actively exploited in ransomware campaigns."
    if r.in_kev:
        return "Patch immediately: confirmed exploited in the wild (CISA KEV)."
    if (r.epss or 0.0) >= config.EPSS_HIGH:
        return "Patch urgently: high probability of exploitation."
    if (r.epss or 0.0) >= config.EPSS_MODERATE:
        return "Schedule a patch soon: moderate exploitation probability."
    return "Patch during routine maintenance: low immediate risk."


def risk_sentence(r: RankedCve) -> str:
    """Build the one-sentence plain-English risk description."""
    product = r.asset_display or "a tracked product"
    severity = _severity_word(r.cvss_score)
    band = _epss_band(r.epss)

    parts = [f"{r.cve_id} affects {product}"]

    if r.cvss_score is not None:
        parts.append(
            f"and carries a {severity} severity rating "
            f"(CVSS {r.cvss_display})"
        )

    if r.epss is not None:
        pct = ""
        if r.epss_percentile is not None:
            pct_val = r.epss_percentile * 100
            if pct_val >= 99.5:
                pct = ", in the top 1 percent of all CVEs by exploitation probability"
            else:
                pct = f", higher than {pct_val:.0f} percent of all CVEs"
        epss_clause = (
            f"EPSS puts exploitation at {band} probability "
            f"({r.epss * 100:.1f} percent in the next 30 days{pct})"
        )
    else:
        epss_clause = "No EPSS exploitation estimate is available"

    if r.in_kev and r.kev_ransomware:
        kev_clause = (
            "and CISA confirms active exploitation in ransomware campaigns"
        )
    elif r.in_kev:
        kev_clause = "and CISA confirms it is being exploited in the wild"
    else:
        kev_clause = "and it is not currently in the CISA exploited catalogue"

    return f"{' '.join(parts)}. {epss_clause}, {kev_clause}."
