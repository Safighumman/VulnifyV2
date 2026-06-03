"""Organisation-sector classification for assets and the CVEs that affect them.

The project brief frames the tool around real organisation types: an SMB
accountancy firm (finance), a school or university IT team (education), a GP
surgery (healthcare) and a housing charity (non-profit). This module turns that
framing into a first-class dimension so the dashboard can answer "how exposed is
my sector?" and so a user can configure the platform to the sectors they run.

Classification is deliberately simple and explainable (the dashboard must be
understandable to a non-specialist): a product resolves to exactly one display
sector. Ubiquitous software that every organisation runs (Windows, Office, web
browsers, PDF readers) resolves to "Cross-sector", which the UI explains as
"affects all organisation types". Specialised software resolves to the sector it
characterises (Moodle -> Education, Sage Payroll -> Banking & Finance).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from .normalization import NormalisationResult
from .ranking import RankedCve


@dataclass(frozen=True)
class Sector:
    key: str
    name: str
    short: str
    description: str
    color: str
    icon: str          # icon key resolved to an SVG in the frontend


# The sector taxonomy. Ordered roughly by how often each appears in the brief's
# use cases, then by general prevalence. "common" is the cross-sector bucket.
SECTORS: List[Sector] = [
    Sector("common", "Cross-sector", "Common",
           "Ubiquitous software every organisation runs. Affects all sectors.",
           "#8aa0c6", "globe"),
    Sector("education", "Education", "Edu",
           "Schools, colleges and universities. Moodle, research and lab estates.",
           "#18d39a", "cap"),
    Sector("finance", "Banking & Finance", "Finance",
           "Accountancy, payroll, banking and fintech. High-value, regulated.",
           "#f5b73d", "bank"),
    Sector("healthcare", "Healthcare", "Health",
           "GP surgeries, clinics and hospitals. Patient data and clinical kit.",
           "#ff6b8b", "cross"),
    Sector("government", "Government & Public", "Gov",
           "Local and central government, public services and defence suppliers.",
           "#5fb3ff", "shield"),
    Sector("technology", "Technology & SaaS", "Tech",
           "Web, data and platform infrastructure: servers, databases, runtimes.",
           "#a78bfa", "chip"),
    Sector("retail", "Retail & eCommerce", "Retail",
           "Shops, online stores and payment-handling estates.",
           "#34d399", "cart"),
    Sector("manufacturing", "Manufacturing & OT", "Mfg",
           "Industrial, operational technology and supply-chain estates.",
           "#fbbf24", "factory"),
    Sector("energy", "Energy & Utilities", "Energy",
           "Power, water and critical national infrastructure operators.",
           "#fb923c", "bolt"),
    Sector("nonprofit", "Charity & Non-profit", "Charity",
           "Third-sector organisations, often volunteer-run with no security team.",
           "#2dd4bf", "heart"),
]

_BY_KEY: Dict[str, Sector] = {s.key: s for s in SECTORS}

# Map the catalogue's product categories to a sector. Categories come from
# cpe_catalog.Product.category. Anything not listed falls through to "common".
_CATEGORY_SECTOR: Dict[str, str] = {
    "Learning management": "education",
    "Virtualisation": "technology",
    "Web server": "technology",
    "Database": "technology",
    "Runtime": "technology",
    "Logging library": "technology",
    "Cryptography library": "technology",
    "Content management": "technology",
    "Mail server": "technology",
    "Network firmware": "technology",
}

# Specific product-name keywords that pin a sector more precisely than category.
# Checked against the canonical product name and the raw user input (lowercased).
_KEYWORD_SECTOR: List[tuple[tuple[str, ...], str]] = [
    (("moodle", "blackboard", "canvas lms", "schoology", "campus", "sims",
      "turnitin", "research"), "education"),
    (("sage", "payroll", "quickbooks", "xero", "banking", "finance",
      "accountanc", "swift", "core banking", "fis ", "temenos"), "finance"),
    (("emis", "systmone", "epic", "cerner", "nhs", "clinical", "patient",
      "pacs", "dicom", "meditech", "health"), "healthcare"),
    (("gov", "council", "defence", "defense", "public sector"), "government"),
    (("scada", "plc", "modbus", "ot ", "ics", "industrial", "siemens s7",
      "rockwell", "manufactur"), "manufacturing"),
    (("substation", "grid", "energy", "utility", "water treatment",
      "power plant"), "energy"),
    (("magento", "shopify", "woocommerce", "retail", "point of sale", "pos ",
      "payment", "checkout"), "retail"),
    (("donor", "charity", "non-profit", "nonprofit", "fundrais"), "nonprofit"),
]

# Vendors whose products are effectively universal across every sector.
_COMMON_VENDORS = {
    "microsoft", "google", "mozilla", "adobe", "apple", "7-zip", "zoom",
}


def get_sector(key: str) -> Optional[Sector]:
    return _BY_KEY.get(key)


def sector_for_asset(asset: NormalisationResult) -> str:
    """Resolve one normalised asset to a single display-sector key."""
    raw = (asset.raw_name or "").lower()
    name = (asset.display_name or "").lower()
    haystack = f"{raw} {name}"

    for keywords, sector in _KEYWORD_SECTOR:
        if any(k in haystack for k in keywords):
            return sector

    if asset.recognised and asset.product:
        # Ubiquitous desktop/productivity software is cross-sector.
        vendors = {c.split(":")[0] for c in asset.product.cpe}
        if vendors & _COMMON_VENDORS and asset.product.category in {
            "Productivity", "Operating system", "Web browser",
            "Document reader", "Video conferencing", "Utility",
        }:
            return "common"
        return _CATEGORY_SECTOR.get(asset.product.category, "common")

    return "common"


def sector_for_ranked(r: RankedCve, asset_sectors: Dict[str, str]) -> str:
    """Resolve a ranked CVE to a sector via its first matched display asset."""
    for name in (r.asset_display or "").split("; "):
        name = name.strip()
        if name and name in asset_sectors:
            return asset_sectors[name]
    return "common"


def build_asset_sector_map(assets: List[NormalisationResult]) -> Dict[str, str]:
    """Map each recognised asset's display name to its sector key."""
    out: Dict[str, str] = {}
    for a in assets:
        out[a.display_name] = sector_for_asset(a)
    return out


def sector_meta(key: str) -> dict:
    s = _BY_KEY.get(key) or _BY_KEY["common"]
    return {"key": s.key, "name": s.name, "short": s.short,
            "description": s.description, "color": s.color, "icon": s.icon}


def all_sector_meta() -> List[dict]:
    return [sector_meta(s.key) for s in SECTORS]
