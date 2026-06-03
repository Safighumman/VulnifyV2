"""Load the three offline data feeds and the user asset list.

Resolution order for the CVE and EPSS data:

  1. Full feeds in ``data/feeds/`` (downloaded by ``scripts/fetch_data.py``).
  2. The bundled real subset in ``data/bundled/`` that ships with the repo.

This means the tool produces real results immediately after a clone, and
scales up to the complete feeds the moment they are fetched, with no code
change. All loading is offline: no API is ever called at run time.

The NVD reader accepts the Fraunhofer FKIE per-year JSON format (the offline
replacement for the retired NVD 1.1 feeds) in plain ``.json``, ``.json.xz`` or
``.json.gz`` form. Each CVE record is reduced to a compact, typed dict holding
only the fields the pipeline needs.
"""

from __future__ import annotations

import gzip
import json
import lzma
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import pandas as pd

from . import config


# Internal record shape
@dataclass
class CpeMatch:
    criteria: str
    vendor: str
    product: str
    version: str                       # exact version in the CPE, or "*"/"-"
    vuln: bool
    start_inc: Optional[str] = None    # versionStartIncluding
    start_exc: Optional[str] = None    # versionStartExcluding
    end_inc: Optional[str] = None      # versionEndIncluding
    end_exc: Optional[str] = None      # versionEndExcluding

    @property
    def vendor_product(self) -> str:
        return f"{self.vendor}:{self.product}"


@dataclass
class CveRecord:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_severity: str
    cvss_vector: str
    cvss_version: str
    published: str
    cpe_matches: List[CpeMatch] = field(default_factory=list)
    vuln_status: str = ""
    cwes: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    last_modified: str = ""


# Low level file readers
def _open_json(path: Path):
    """Open a .json, .json.xz or .json.gz file and return parsed JSON."""
    name = path.name.lower()
    if name.endswith(".xz"):
        with lzma.open(path, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    if name.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _first_english_description(descriptions: List[dict]) -> str:
    for d in descriptions or []:
        if d.get("lang") == "en":
            return (d.get("value") or "").strip()
    if descriptions:
        return (descriptions[0].get("value") or "").strip()
    return ""


def _best_cvss(metrics: dict) -> tuple[Optional[float], str, str, str]:
    """Pick the most authoritative CVSS metric available.

    Preference order: v3.1, then v3.0, then v2. Returns
    (base_score, severity, vector, version).
    """
    order = [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]
    for key, version in order:
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = (
            data.get("baseSeverity")
            or entries[0].get("baseSeverity")
            or ""
        ).upper()
        vector = data.get("vectorString", "")
        if score is not None:
            return float(score), severity, vector, version
    return None, "", "", ""


def _parse_cpe_matches(configurations: List[dict]) -> List[CpeMatch]:
    matches: List[CpeMatch] = []
    for cfg in configurations or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                criteria = m.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue
                matches.append(
                    CpeMatch(
                        criteria=criteria,
                        vendor=parts[3],
                        product=parts[4],
                        version=parts[5],
                        vuln=bool(m.get("vulnerable", True)),
                        start_inc=m.get("versionStartIncluding"),
                        start_exc=m.get("versionStartExcluding"),
                        end_inc=m.get("versionEndIncluding"),
                        end_exc=m.get("versionEndExcluding"),
                    )
                )
    return matches


def _extract_cwes(weaknesses: List[dict]) -> List[str]:
    out: List[str] = []
    for w in weaknesses or []:
        for d in w.get("description", []) or []:
            value = (d.get("value") or "").strip()
            if value.startswith("CWE-") and value not in out and value != "CWE-noinfo":
                out.append(value)
    return out


def _extract_refs(references: List[dict], limit: int = 6) -> List[str]:
    out: List[str] = []
    for r in references or []:
        url = r.get("url")
        if url and url not in out:
            out.append(url)
        if len(out) >= limit:
            break
    return out


def _record_from_item(item: dict) -> CveRecord:
    score, severity, vector, version = _best_cvss(item.get("metrics", {}) or {})
    return CveRecord(
        cve_id=item.get("id", ""),
        description=_first_english_description(item.get("descriptions", [])),
        cvss_score=score,
        cvss_severity=severity,
        cvss_vector=vector,
        cvss_version=version,
        published=item.get("published", ""),
        cpe_matches=_parse_cpe_matches(item.get("configurations", [])),
        vuln_status=item.get("vulnStatus", ""),
        cwes=_extract_cwes(item.get("weaknesses", [])),
        references=_extract_refs(item.get("references", [])),
        last_modified=item.get("lastModified", ""),
    )


# Public loaders
def _resolve_nvd_paths() -> List[Path]:
    """Return the NVD file paths to load (full feeds first, else bundled)."""
    feed_paths: List[Path] = []
    for year in config.env_year_list():
        for ext in (".json", ".json.xz", ".json.gz"):
            candidate = config.FEEDS_DIR / f"CVE-{year}{ext}"
            if candidate.exists():
                feed_paths.append(candidate)
                break
    if feed_paths:
        return feed_paths
    if config.BUNDLED_NVD.exists():
        return [config.BUNDLED_NVD]
    raise FileNotFoundError(
        "No NVD CVE data found. Expected full feeds in data/feeds/ or the "
        "bundled subset at data/bundled/nvd_cve_relevant.json.gz. "
        "Run: python scripts/fetch_data.py"
    )


def load_cve_records(paths: Optional[List[Path]] = None) -> List[CveRecord]:
    """Load and flatten every CVE record from the resolved NVD files."""
    paths = paths or _resolve_nvd_paths()
    records: List[CveRecord] = []
    for path in paths:
        payload = _open_json(path)
        items = payload.get("cve_items") or payload.get("CVE_Items") or []
        for item in items:
            records.append(_record_from_item(item))
    return records


def load_kev_set() -> tuple[Set[str], Dict[str, dict]]:
    """Load the CISA KEV catalogue.

    Returns a set of CVE IDs (for O(1) membership tests) and a detail map
    keyed by CVE ID so the ransomware flag and notes are available later.
    """
    path = config.FEEDS_DIR / "known_exploited_vulnerabilities.json"
    if not path.exists():
        path = config.BUNDLED_KEV
    if not path.exists():
        return set(), {}

    payload = _open_json(path)
    kev_ids: Set[str] = set()
    detail: Dict[str, dict] = {}
    for v in payload.get("vulnerabilities", []) or []:
        cid = v.get("cveID", "")
        if not cid:
            continue
        kev_ids.add(cid)
        detail[cid] = {
            "vendorProject": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "shortDescription": v.get("shortDescription", ""),
            "dateAdded": v.get("dateAdded", ""),
            "ransomware": (
                str(v.get("knownRansomwareCampaignUse", "")).strip().lower()
                == "known"
            ),
        }
    return kev_ids, detail


def _resolve_epss_path() -> Optional[Path]:
    """Find an EPSS CSV: a full dated feed first, else the bundled subset."""
    if config.FEEDS_DIR.exists():
        candidates = sorted(config.FEEDS_DIR.glob("epss_scores*.csv*"))
        if candidates:
            return candidates[-1]
    if config.BUNDLED_EPSS.exists():
        return config.BUNDLED_EPSS
    return None


def load_epss_map() -> Dict[str, dict]:
    """Load EPSS scores into a dict keyed by CVE ID for O(1) lookup.

    Each value is {"epss": float, "percentile": float}. The Cyentia CSV files
    begin with a ``#model_version`` comment line, which pandas skips via the
    ``comment`` argument.
    """
    path = _resolve_epss_path()
    if path is None:
        return {}

    compression = "gzip" if path.name.endswith(".gz") else "infer"
    frame = pd.read_csv(
        path, comment="#", compression=compression,
        usecols=["cve", "epss", "percentile"],
    )
    epss_map: Dict[str, dict] = {}
    for cve, epss, pct in zip(frame["cve"], frame["epss"], frame["percentile"]):
        epss_map[str(cve)] = {"epss": float(epss), "percentile": float(pct)}
    return epss_map


# Asset list
_VERSION_HINT = re.compile(r"\b(v?\d[\w.\-]*|current|latest)\b", re.IGNORECASE)


def parse_asset_list(text: str) -> List[tuple[str, str]]:
    """Parse raw asset list text into (name, version) tuples.

    Accepts several informal layouts a real user might paste or upload:

        Name, Version          comma separated
        Name | Version         pipe separated (the sample list export format)
        Name  Version          name with a trailing version token
        Name                   no version at all

    Blank lines and lines beginning with ``#`` are ignored. A leading header row
    from a spreadsheet or CMDB export (for example ``Product,Version,Owner``) is
    detected and skipped so structured exports work without editing.
    """
    assets: List[tuple[str, str]] = []
    first_data_seen = False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if not first_data_seen and _looks_like_header(line):
            first_data_seen = True
            continue
        first_data_seen = True

        name, version = line, ""
        if "|" in line:
            name, _, version = line.partition("|")
        elif "," in line:
            # Comma or multi-column CSV: take the first two fields.
            parts = [p.strip() for p in line.split(",")]
            name = parts[0]
            version = parts[1] if len(parts) > 1 else ""
        elif "\t" in line:
            parts = [p.strip() for p in line.split("\t")]
            name = parts[0]
            version = parts[1] if len(parts) > 1 else ""
        else:
            # Try to peel a trailing version token off a space-separated line,
            # but keep names like "Windows 10" intact by only splitting when a
            # clear version-looking token sits at the very end.
            tokens = line.rsplit(" ", 1)
            if len(tokens) == 2 and _looks_like_version(tokens[1]):
                name, version = tokens[0], tokens[1]

        name = name.strip()
        version = version.strip()
        if name:
            assets.append((name, version))
    return assets


def _looks_like_header(line: str) -> bool:
    """Detect a spreadsheet or CMDB header row so it can be skipped."""
    lowered = line.lower()
    keywords = ("product", "software", "application", "asset", "name",
                "version", "vendor", "hostname", "component")
    hits = sum(1 for k in keywords if k in lowered)
    has_digit = any(ch.isdigit() for ch in line)
    return hits >= 2 and not has_digit


def _looks_like_version(token: str) -> bool:
    t = token.strip().lower()
    if t in {"current", "latest"}:
        return True
    # Must contain a digit and look like a version, not a product word.
    return bool(re.fullmatch(r"v?\d[\w.\-]*", t))


def load_asset_file(path: Path) -> List[tuple[str, str]]:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_asset_list(fh.read())
