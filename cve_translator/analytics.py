"""Aggregate a ranked CVE list into the figures a dashboard needs.

Everything here is pure and JSON serialisable so it can feed both the web
dashboard and any reporting. The aggregations are deliberately the ones a
security analyst expects from an intelligence platform: severity and EPSS
distributions, confirmed versus unconfirmed exploitation, breakdowns by product
category, vendor, and weakness type (CWE), plus publication and exploitation
timelines.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean
from typing import Dict, List

from . import geo, sectors
from .normalization import NormalisationResult
from .ranking import RankedCve

# A small lookup of common CWE identifiers to readable names, so the dashboard
# can label weakness categories instead of showing bare numbers.
CWE_NAMES: Dict[str, str] = {
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-119": "Memory Buffer Errors",
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Information Exposure",
    "CWE-269": "Improper Privilege Management",
    "CWE-287": "Improper Authentication",
    "CWE-094": "Code Injection",
    "CWE-352": "Cross-site Request Forgery",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-77": "Command Injection",
    "CWE-284": "Improper Access Control",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-770": "Allocation Without Limits",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-401": "Missing Release of Memory",
    "CWE-617": "Reachable Assertion",
    "CWE-59": "Link Following",
    "CWE-426": "Untrusted Search Path",
    "CWE-862": "Missing Authorization",
    "CWE-306": "Missing Authentication",
    "CWE-798": "Hard-coded Credentials",
    "CWE-1333": "Inefficient Regex Complexity",
    "CWE-358": "Improper Security Check",
    "CWE-668": "Exposure to Wrong Sphere",
    "CWE-noinfo": "Unclassified",
    "NVD-CWE-noinfo": "Unclassified",
    "NVD-CWE-Other": "Other",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNRATED"]
SEVERITY_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH": "#ff7a3c",
    "MEDIUM": "#ffc24b",
    "LOW": "#3ba9ff",
    "UNRATED": "#5b6b86",
}


def _month(date_str: str) -> str:
    return date_str[:7] if len(date_str) >= 7 else ""


def cwe_name(cwe_id: str) -> str:
    return CWE_NAMES.get(cwe_id, cwe_id.replace("NVD-", ""))


def build_dashboard(
    ranked: List[RankedCve],
    assets: List[NormalisationResult],
) -> dict:
    """Compute every aggregate the dashboard renders."""
    total = len(ranked)
    kev = [r for r in ranked if r.in_kev]
    ransomware = [r for r in ranked if r.kev_ransomware]
    epss_values = [r.epss for r in ranked if r.epss is not None]
    confidences = [r.confidence for r in ranked]

    severity_counts = Counter(r.severity_band for r in ranked)
    severity = [
        {"label": s.title(), "value": severity_counts.get(s, 0),
         "color": SEVERITY_COLORS[s]}
        for s in SEVERITY_ORDER if severity_counts.get(s, 0) > 0
    ]

    # EPSS probability bands.
    bands = [("Very high (>= 0.5)", 0.5, 1.01), ("High (0.1 to 0.5)", 0.1, 0.5),
             ("Moderate (0.01 to 0.1)", 0.01, 0.1), ("Low (< 0.01)", -1, 0.01)]
    epss_bands = []
    for label, lo, hi in bands:
        n = sum(1 for v in epss_values if lo <= v < hi)
        epss_bands.append({"label": label, "value": n})

    # Category and vendor breakdowns.
    cat_counts: Counter = Counter()
    vendor_counts: Counter = Counter()
    for r in ranked:
        cat = _category_for(r, assets)
        if cat:
            cat_counts[cat] += 1
        for cpe in r.matched_cpes:
            vendor_counts[cpe.split(":")[0]] += 1

    # Weakness (CWE) breakdown.
    cwe_counts: Counter = Counter()
    for r in ranked:
        for c in r.cwes:
            cwe_counts[c] += 1

    # Timelines (by month).
    pub_months: Counter = Counter()
    for r in ranked:
        m = _month(r.published)
        if m:
            pub_months[m] += 1
    kev_months: Counter = Counter()
    for r in kev:
        m = _month(r.kev_date_added)
        if m:
            kev_months[m] += 1

    # Per-asset rollup.
    asset_counts: defaultdict = defaultdict(lambda: {"cves": 0, "kev": 0})
    for r in ranked:
        for name in (r.asset_display or "").split("; "):
            if not name:
                continue
            asset_counts[name]["cves"] += 1
            if r.in_kev:
                asset_counts[name]["kev"] += 1
    top_assets = sorted(
        ({"asset": k, **v} for k, v in asset_counts.items()),
        key=lambda x: (-x["kev"], -x["cves"]),
    )[:12]

    conf_bands = Counter(r.confidence_band for r in ranked)

    # Sector exposure and the sector x severity heatmap.
    asset_sectors = sectors.build_asset_sector_map(assets)
    sector_counts: defaultdict = defaultdict(lambda: {"cves": 0, "kev": 0})
    heat: defaultdict = defaultdict(lambda: Counter())
    for r in ranked:
        skey = sectors.sector_for_ranked(r, asset_sectors)
        sector_counts[skey]["cves"] += 1
        if r.in_kev:
            sector_counts[skey]["kev"] += 1
        heat[skey][r.severity_band] += 1

    by_sector = []
    for skey, v in sorted(sector_counts.items(), key=lambda x: -x[1]["cves"]):
        meta = sectors.sector_meta(skey)
        by_sector.append({**meta, "cves": v["cves"], "kev": v["kev"]})

    heatmap = []
    for skey in [s["key"] for s in by_sector]:
        row = heat[skey]
        meta = sectors.sector_meta(skey)
        heatmap.append({
            "key": skey, "name": meta["name"], "color": meta["color"],
            "cells": [{"sev": s, "value": row.get(s, 0)} for s in SEVERITY_ORDER],
            "total": sum(row.values()),
        })

    kpis = {
        "relevant_cves": total,
        "kev": len(kev),
        "ransomware": len(ransomware),
        "confirmed": len(kev),
        "unconfirmed": total - len(kev),
        "critical": severity_counts.get("CRITICAL", 0),
        "high": severity_counts.get("HIGH", 0),
        "medium": severity_counts.get("MEDIUM", 0),
        "low": severity_counts.get("LOW", 0),
        "assets_supplied": len(assets),
        "assets_recognised": sum(1 for a in assets if a.recognised),
        "assets_unrecognised": sum(1 for a in assets if not a.recognised),
        "avg_epss": round(mean(epss_values), 4) if epss_values else 0.0,
        "max_epss": round(max(epss_values), 4) if epss_values else 0.0,
        "high_epss": sum(1 for v in epss_values if v >= 0.5),
        "avg_confidence": round(mean(confidences)) if confidences else 0,
        "avg_cvss": round(mean([r.cvss_score for r in ranked if r.cvss_score is not None]), 1)
        if any(r.cvss_score is not None for r in ranked) else 0.0,
    }

    return {
        "kpis": kpis,
        "severity": severity,
        "epss_bands": epss_bands,
        "status_split": [
            {"label": "Confirmed", "value": len(kev), "color": "#ff3b5c"},
            {"label": "Unconfirmed", "value": total - len(kev), "color": "#18d39a"},
        ],
        "by_category": _top(cat_counts, 8),
        "by_vendor": _top(vendor_counts, 10),
        "by_sector": by_sector,
        "heatmap": heatmap,
        "by_cwe": [
            {"label": c, "name": cwe_name(c), "value": n}
            for c, n in cwe_counts.most_common(8)
        ],
        "pub_timeline": _timeline(pub_months),
        "kev_timeline": _timeline(kev_months),
        "top_assets": top_assets,
        "confidence_bands": [
            {"label": b, "value": conf_bands.get(b, 0)}
            for b in ("High", "Medium", "Low") if conf_bands.get(b, 0) > 0
        ],
        "gauges": _gauges(kpis),
        "threat_map": geo.build_threat_map(ranked),
        "regions": geo.region_rollup(ranked),
    }


def _gauges(k: dict) -> dict:
    """Three SOC risk gauges, each a 0 to 100 value with a band label."""
    confirmed, critical = k["confirmed"], k["critical"]
    norm_kev = min(1.0, confirmed / 20.0)
    norm_crit = min(1.0, critical / 30.0)
    overall = round(100 * (0.45 * norm_kev + 0.30 * norm_crit
                           + 0.25 * k["max_epss"]))
    coverage = round(100 * (k["assets_recognised"] / k["assets_supplied"])) \
        if k["assets_supplied"] else 0
    exploitation = round(k["max_epss"] * 100)

    def band(v: int) -> str:
        return "Critical" if v >= 75 else "Elevated" if v >= 45 \
            else "Guarded" if v >= 20 else "Low"

    return {
        "overall": {"value": overall, "label": band(overall),
                    "caption": "Composite exposure index"},
        "exploitation": {"value": exploitation, "label": band(exploitation),
                         "caption": "Peak EPSS probability"},
        "coverage": {"value": coverage,
                     "label": "Good" if coverage >= 80 else "Partial" if coverage >= 50 else "Low",
                     "caption": "Assets resolved to CPE"},
    }


def _category_for(r: RankedCve, assets: List[NormalisationResult]) -> str:
    for a in assets:
        if a.recognised and a.product and a.product.name in (r.asset_display or ""):
            return a.product.category
    return "Other"


def _top(counter: Counter, n: int) -> List[dict]:
    return [{"label": k, "value": v} for k, v in counter.most_common(n)]


def _timeline(counter: Counter) -> List[dict]:
    return [{"date": k, "value": counter[k]} for k in sorted(counter.keys())]
