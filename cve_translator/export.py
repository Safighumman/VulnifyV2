"""Serialise a pipeline result to a JSON-ready dict.

This is the single source of truth for the structured output shared by the web
dashboard and the command line ``--json`` export: KPIs and dashboard aggregates,
the ranked CVE rows (with full detail, risk mitigation, official documentation
links, and zero-day treatment for a drawer or integration), the per asset
rollup, and the import and feed metadata.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from . import analytics, mitigation, sectors
from .pipeline import PipelineResult
from .risk_summary import recommended_action, risk_sentence


def row_to_dict(rank: int, r, asset_sectors: Dict[str, str]) -> dict:
    sector_key = sectors.sector_for_ranked(r, asset_sectors)
    sec = sectors.sector_meta(sector_key)
    zero_day = mitigation.zero_day_details(r)
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
        "kev_name": r.kev_vuln_name,
        "kev_due": r.kev_due_date,
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
        "sector": sector_key,
        "sector_name": sec["name"],
        "sector_color": sec["color"],
        "action": recommended_action(r),
        "summary": risk_sentence(r),
        "mitigation": mitigation.mitigation_for(r),
        "zero_day": zero_day,
        "is_zero_day": zero_day is not None,
        "doc_url": f"https://nvd.nist.gov/vuln/detail/{r.cve_id}",
    }


def assets_to_dict(result: PipelineResult,
                   asset_sectors: Dict[str, str]) -> List[dict]:
    asset_cve: dict = {}
    asset_kev: dict = {}
    for r in result.ranked:
        for name in (r.asset_display or "").split("; "):
            asset_cve[name] = asset_cve.get(name, 0) + 1
            if r.in_kev:
                asset_kev[name] = asset_kev.get(name, 0) + 1
    out = []
    for a in result.assets:
        skey = asset_sectors.get(a.display_name, "common")
        sec = sectors.sector_meta(skey)
        out.append({
            "raw": a.raw_name,
            "version": a.raw_version,
            "product": a.display_name,
            "category": a.product.category if a.product else "Unrecognised",
            "sector": skey,
            "sector_name": sec["name"],
            "sector_color": sec["color"],
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
    asset_sectors = sectors.build_asset_sector_map(result.assets)
    return {
        "generated_by": "Vulnify 3.0",
        "stats": result.stats,
        "dashboard": analytics.build_dashboard(result.ranked, result.assets),
        "results": [row_to_dict(i, r, asset_sectors)
                    for i, r in enumerate(ranked, 1)],
        "results_total": len(result.ranked),
        "assets": assets_to_dict(result, asset_sectors),
        "unrecognised": [a.raw_name for a in result.unrecognised_assets],
        "sectors": sectors.all_sector_meta(),
    }
