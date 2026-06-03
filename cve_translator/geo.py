"""Heuristic geography for the stylised threat map.

The CVE feeds carry no attack-origin geography, so plotting "where attacks come
from" honestly is impossible offline. What we can show is where the *affected
technology* originates, by mapping each CPE vendor to its headquarters region.
The frontend renders this as a glowing-node world map for the SOC aesthetic, and
the UI labels it clearly as a vendor-headquarters heuristic, not attack telemetry.

Coordinates are equirectangular-friendly latitude/longitude so the frontend can
project them onto a simple world map with x = (lon+180)/360, y = (90-lat)/180.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .ranking import RankedCve

# Vendor -> (display location, country code, latitude, longitude).
_VENDOR_GEO: Dict[str, tuple] = {
    "microsoft": ("Redmond, US", "US", 47.64, -122.13),
    "google": ("Mountain View, US", "US", 37.42, -122.08),
    "adobe": ("San Jose, US", "US", 37.33, -121.89),
    "cisco": ("San Jose, US", "US", 37.41, -121.95),
    "vmware": ("Palo Alto, US", "US", 37.40, -122.12),
    "oracle": ("Austin, US", "US", 30.27, -97.74),
    "apache": ("Wakefield, US", "US", 42.50, -71.07),
    "openssl": ("Global (distributed)", "INT", 50.11, 8.68),
    "zoom": ("San Jose, US", "US", 37.34, -121.88),
    "wordpress": ("San Francisco, US", "US", 37.77, -122.42),
    "moodle": ("Perth, AU", "AU", -31.95, 115.86),
    "fortinet": ("Sunnyvale, US", "US", 37.37, -122.04),
    "f5": ("Seattle, US", "US", 47.61, -122.33),
    "nginx": ("Seattle, US", "US", 47.61, -122.33),
    "mozilla": ("Mountain View, US", "US", 37.39, -122.08),
    "postgresql": ("Global (distributed)", "INT", 52.52, 13.40),
    "php": ("Global (distributed)", "INT", 51.51, -0.13),
    "nodejs": ("Global (distributed)", "INT", 45.42, -75.70),
    "apple": ("Cupertino, US", "US", 37.33, -122.03),
    "7-zip": ("Global (distributed)", "INT", 55.75, 37.62),
}

_DEFAULT = ("Unknown vendor region", "INT", 20.0, 0.0)


def build_threat_map(ranked: List[RankedCve]) -> List[dict]:
    """Aggregate matched CVEs into geo nodes for the stylised threat map."""
    agg: Dict[str, dict] = {}
    for r in ranked:
        vendors = {c.split(":")[0] for c in r.matched_cpes}
        for v in vendors:
            loc, cc, lat, lon = _VENDOR_GEO.get(v, _DEFAULT)
            node = agg.get(v)
            if node is None:
                node = {"vendor": v, "location": loc, "country": cc,
                        "lat": lat, "lon": lon, "cves": 0, "kev": 0,
                        "critical": 0, "x": round((lon + 180) / 360, 4),
                        "y": round((90 - lat) / 180, 4)}
                agg[v] = node
            node["cves"] += 1
            if r.in_kev:
                node["kev"] += 1
            if r.severity_band == "CRITICAL":
                node["critical"] += 1
    nodes = sorted(agg.values(), key=lambda n: (-n["kev"], -n["cves"]))
    return nodes


def region_rollup(ranked: List[RankedCve]) -> List[dict]:
    """CVE counts grouped by vendor-HQ country for a compact legend."""
    counts: defaultdict = defaultdict(lambda: {"cves": 0, "kev": 0})
    for r in ranked:
        seen = set()
        for c in r.matched_cpes:
            _, cc, _, _ = _VENDOR_GEO.get(c.split(":")[0], _DEFAULT)
            if cc in seen:
                continue
            seen.add(cc)
            counts[cc]["cves"] += 1
            if r.in_kev:
                counts[cc]["kev"] += 1
    return [{"country": k, **v} for k, v in
            sorted(counts.items(), key=lambda x: -x[1]["cves"])]
