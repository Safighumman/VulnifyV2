"""Feed and import metadata, presented in the style of an ingestion platform.

The pipeline records how many records each feed produced and how long it took to
load. This module turns those raw numbers into the import-job descriptors the
dashboard shows: source, format, record count, ingest speed, status, and the
category of intelligence each feed contributes. This mirrors how a platform such
as OpenCTI surfaces its connectors and import runs.
"""

from __future__ import annotations

from typing import Dict, List

# Static description of every offline feed the platform ingests.
FEED_CATALOG: List[dict] = [
    {
        "key": "nvd",
        "source": "NVD CVE",
        "provider": "Fraunhofer FKIE reconstruction",
        "format": "JSON (.json.xz)",
        "category": "Vulnerabilities",
        "contributes": "CVE records, descriptions, CVSS scores, CPE applicability",
        "confidence": "Authoritative",
    },
    {
        "key": "kev",
        "source": "CISA KEV",
        "provider": "Cybersecurity and Infrastructure Security Agency",
        "format": "JSON",
        "category": "Confirmed exploitation",
        "contributes": "Known Exploited Vulnerabilities and ransomware flags",
        "confidence": "Confirmed",
    },
    {
        "key": "epss",
        "source": "EPSS",
        "provider": "FIRST.org via empiricalsecurity",
        "format": "CSV (.csv.gz)",
        "category": "Exploitation forecast",
        "contributes": "Daily exploitation probability and percentile",
        "confidence": "Predictive",
    },
]

_BY_KEY = {f["key"]: f for f in FEED_CATALOG}


def build_import_jobs(
    counts: Dict[str, int],
    timings: Dict[str, float],
) -> List[dict]:
    """Build per-feed import-job descriptors with computed ingest speed.

    Args:
        counts: records loaded per feed key (nvd, kev, epss).
        timings: seconds spent loading per feed key.
    """
    from .mitigation import feed_mitigation
    jobs: List[dict] = []
    for feed in FEED_CATALOG:
        key = feed["key"]
        records = int(counts.get(key, 0))
        seconds = float(timings.get(key, 0.0))
        speed = int(records / seconds) if seconds > 0 else records
        jobs.append({
            **feed,
            "records": records,
            "duration_s": round(seconds, 3),
            "speed": speed,
            "status": "completed" if records > 0 else "empty",
            "mitigation": feed_mitigation(key),
        })
    return jobs


def source_for(key: str) -> dict:
    return _BY_KEY.get(key, {})
