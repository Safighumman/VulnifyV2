"""Central configuration: paths, thresholds, and tunable constants.

Everything that a user might reasonably want to change lives here so the rest
of the pipeline stays free of magic numbers. Paths are resolved relative to
the repository root so the tool works regardless of the current directory.
"""

from __future__ import annotations

import os
from pathlib import Path

# Paths
PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parent
DATA_DIR = REPO_ROOT / "data"

# Full feeds (large, fetched on demand by scripts/fetch_data.py). Git ignored.
FEEDS_DIR = DATA_DIR / "feeds"

# Bundled real subset that ships with the repository so the tool works the
# moment it is cloned, with no downloads and no network access. Git tracked.
BUNDLED_DIR = DATA_DIR / "bundled"

OUTPUT_DIR = REPO_ROOT / "output"
SAMPLE_ASSET_LIST = DATA_DIR / "sample_asset_list.txt"

# Runtime config that the dashboard can write (connectors, preferences).
CONFIG_DIR = DATA_DIR / "config"
CONNECTORS_FILE = CONFIG_DIR / "connectors.json"
PREFERENCES_FILE = CONFIG_DIR / "preferences.json"

# Bundled file names.
BUNDLED_NVD = BUNDLED_DIR / "nvd_cve_relevant.json.gz"
BUNDLED_KEV = BUNDLED_DIR / "known_exploited_vulnerabilities.json"
BUNDLED_EPSS = BUNDLED_DIR / "epss_scores.csv.gz"

# Live import
# The platform ingests live from the sources named in the project brief. The
# direct official hosts (cisa.gov, epss.empiricalsecurity.com) are reached
# through their maintained GitHub mirrors, which is the same data on a host that
# works behind strict outbound allow-lists. The brief itself names the
# Fraunhofer FKIE GitHub repository as the recommended NVD source. When the
# network is unavailable the platform falls back to the bundled real subset, so
# it always works offline and upgrades itself to live data when it can.
LIVE_ENABLED_DEFAULT = os.environ.get("VULNIFY_LIVE", "1") != "0"

LIVE_KEV_URL = (
    "https://raw.githubusercontent.com/CISAgov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
LIVE_EPSS_URL = (
    "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/"
    "{year}/epss_scores-{date}.csv.gz"
)
LIVE_NVD_URL = (
    "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/"
    "CVE-{year}.json.xz"
)

# Poll intervals in seconds. KEV and EPSS are small and refresh often; the full
# NVD corpus is large, so it syncs far less frequently and on demand.
LIVE_INTERVAL_KEV = int(os.environ.get("VULNIFY_INTERVAL_KEV", "180"))
LIVE_INTERVAL_EPSS = int(os.environ.get("VULNIFY_INTERVAL_EPSS", "900"))
LIVE_INTERVAL_NVD = int(os.environ.get("VULNIFY_INTERVAL_NVD", "86400"))
LIVE_HTTP_TIMEOUT = int(os.environ.get("VULNIFY_HTTP_TIMEOUT", "45"))
LIVE_EVENT_BUFFER = 200          # rolling live-event ring buffer size

# Normalisation
# rapidfuzz score (0 to 100). A user supplied name must match a catalogue
# alias at or above this score to be accepted. Lower means more matches but
# more risk of mapping to the wrong product. 82 is a good balance in testing.
FUZZY_SCORE_CUTOFF = 82

# Ranking weights for the combined urgency score (0 to 100)
# The urgency score blends three signals. KEV membership is the strongest, so
# it is applied as a large additive boost rather than a weight, guaranteeing
# that actively exploited CVEs always sort above non-KEV ones.
WEIGHT_EPSS = 0.70          # real-world exploitation probability (0 to 1)
WEIGHT_CVSS = 0.30          # technical severity (0 to 10, scaled to 0 to 1)
KEV_BOOST = 100.0           # added on top for any CVE in the CISA KEV catalogue
RANSOMWARE_BOOST = 10.0     # extra nudge for KEV entries linked to ransomware

# EPSS probability bands used in the plain-English summary.
EPSS_HIGH = 0.50            # at or above this: "high" exploitation probability
EPSS_MODERATE = 0.10        # at or above this: "moderate"; below: "low"

# CVSS severity bands (matches the NVD qualitative scale).
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0


def env_year_list(default: tuple[int, ...] = (2024, 2025)) -> list[int]:
    """Return the CVE years to work with.

    Controlled by the CVE_YEARS environment variable (comma separated), so the
    fetch script and the pipeline always agree. The resources section of the
    project brief provides 2024 and 2025, which is the default here.
    """
    raw = os.environ.get("CVE_YEARS", "").strip()
    if not raw:
        return list(default)
    years = []
    for token in raw.split(","):
        token = token.strip()
        if token.isdigit():
            years.append(int(token))
    return years or list(default)
