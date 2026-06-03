"""Serialise a pipeline result to a JSON-ready dict.

This is the single source of truth for the structured output shared by the web
dashboard and the command line ``--json`` export: KPIs and dashboard aggregates,
the ranked CVE rows (with full detail for a drawer or integration), the per
asset rollup, and the import and feed metadata.
"""

from __future__ import annotations

from typing import List, Optional

from . import analytics
from .pipeline import PipelineResult
from .risk_summary import recommended_action, risk_sentence


def row_to_dict(rank: int, r) -> dict:
    return {
        "rank": rank,
        "cve_id": r.cve_id,
        "asset": r.asset_display,
        "asset_raw": r.asset_raw,
        "status": r.status,
        "cvss": r.cvss_display,
        "cvss_raw": r.cvss_score,
        "cvss_severity": r.severity_band,
        "cvss_vector": r.cvss_vector,
        "cvss_version": r.cvss_version,
        "epss": r.epss_display,
        "epss_raw": r.epss if r.epss is not None else None,
        "epss_pct": (round(r.epss_percentile * 100, 1)
                     if r.epss_percentile is not None else None),
        "kev": r.in_kev,
        "ransomware": r.kev_ransomware,
        "kev_date": r.kev_date_added,
        "kev_desc": r.kev_short_desc,
        "confidence": r.confidence,
        "confidence_band": r.confidence_band,
        "urgency": round(r.urgency, 4),
        "cpe": r.matched_cpes,
        "cwes": [{"id": c, "name": analytics.cwe_name(c)} for c in r.cwes],
        "description": r.description,
        "references": r.references,
        "vuln_status": r.vuln_status,
        "published": r.published,
        "last_modified": r.last_modified,
        "action": recommended_action(r),
        "summary": risk_sentence(r),
    }


def assets_to_dict(result: PipelineResult) -> List[dict]:
    asset_cve: dict = {}
    asset_kev: dict = {}
    for r in result.ranked:
        for name in (r.asset_display or "").split("; "):
            asset_cve[name] = asset_cve.get(name, 0) + 1
            if r.in_kev:
                asset_kev[name] = asset_kev.get(name, 0) + 1
    out = []
    for a in result.assets:
        out.append({
            "raw": a.raw_name,
            "version": a.raw_version,
            "product": a.display_name,
            "category": a.product.category if a.product else "Unrecognised",
            "cpe": a.cpe_targets,
            "score": round(a.score, 0),
            "recognised": a.recognised,
            "cves": asset_cve.get(a.display_name, 0),
            "kev": asset_kev.get(a.display_name, 0),
        })
    return out


def result_to_dict(result: PipelineResult, max_rows: Optional[int] = None) -> dict:
    """Build the full structured payload for a pipeline result."""
    ranked = result.ranked if max_rows is None else result.ranked[:max_rows]
    return {
        "generated_by": "Lodestar 2.0",
        "stats": result.stats,
        "dashboard": analytics.build_dashboard(result.ranked, result.assets),
        "results": [row_to_dict(i, r) for i, r in enumerate(ranked, 1)],
        "results_total": len(result.ranked),
        "assets": assets_to_dict(result),
        "unrecognised": [a.raw_name for a in result.unrecognised_assets],
    }
