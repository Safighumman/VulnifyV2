"""Download the real, current data feeds into data/feeds/.

This mirrors what a hackathon facilitator does before the event: it pre-downloads
the offline data so the pipeline can run with no network access afterwards. The
sources are the ones named in the project brief, reached through hosts that work
behind a strict outbound allow-list (raw.githubusercontent.com and the GitHub
release CDN):

  * NVD CVE data : Fraunhofer FKIE reconstruction, per-year .json.xz releases
  * CISA KEV      : the CISAgov/kev-data mirror of the official catalogue
  * EPSS scores   : the official empiricalsec/epss_scores repository

Usage:
    python scripts/fetch_data.py                 # years from CVE_YEARS or 2024,2025
    python scripts/fetch_data.py --years 2025
    python scripts/fetch_data.py --epss-date 2026-06-02

Nothing here is called at pipeline run time; this is a one-off preparation step.
"""

from __future__ import annotations

import argparse
import lzma
import shutil
import sys
import urllib.request
from datetime import date, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FEEDS_DIR = REPO_ROOT / "data" / "feeds"

NVD_URL = (
    "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/"
    "CVE-{year}.json.xz"
)
KEV_URL = (
    "https://raw.githubusercontent.com/CISAgov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = (
    "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/"
    "{year}/epss_scores-{date}.csv.gz"
)

_HEADERS = {"User-Agent": "cve-to-my-stack-translator/1.0 (+offline-prep)"}


def _download(url: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  fetching {url}")
    try:
        req = urllib.request.Request(url, headers=_HEADERS)
        with urllib.request.urlopen(req, timeout=300) as resp, open(dest, "wb") as fh:
            shutil.copyfileobj(resp, fh)
    except Exception as exc:  # noqa: BLE001 (we want a clean message, not a trace)
        print(f"  FAILED: {exc}")
        return False
    print(f"  saved {dest.name} ({dest.stat().st_size:,} bytes)")
    return True


def _decompress_xz(path: Path) -> None:
    out = path.with_suffix("")  # drop the .xz suffix
    print(f"  decompressing {path.name} -> {out.name}")
    with lzma.open(path, "rb") as src, open(out, "wb") as dst:
        shutil.copyfileobj(src, dst)
    path.unlink(missing_ok=True)


def fetch_nvd(years: list[int]) -> None:
    print("NVD CVE feeds:")
    for year in years:
        xz_path = FEEDS_DIR / f"CVE-{year}.json.xz"
        if _download(NVD_URL.format(year=year), xz_path):
            _decompress_xz(xz_path)


def fetch_kev() -> None:
    print("CISA KEV catalogue:")
    _download(KEV_URL, FEEDS_DIR / "known_exploited_vulnerabilities.json")


def fetch_epss(epss_date: str) -> None:
    print("EPSS scores:")
    year = epss_date.split("-")[0]
    dest = FEEDS_DIR / f"epss_scores-{epss_date}.csv.gz"
    if not _download(EPSS_URL.format(year=year, date=epss_date), dest):
        print("  note: try an earlier --epss-date if today's file is not posted yet")


def _default_epss_date() -> str:
    # EPSS for a given day is posted during that day; fall back to yesterday.
    return (date.today() - timedelta(days=1)).isoformat()


def main(argv: list[str] | None = None) -> int:
    import os

    default_years = os.environ.get("CVE_YEARS", "2024,2025")
    parser = argparse.ArgumentParser(description="Download offline CVE data feeds.")
    parser.add_argument(
        "--years", default=default_years,
        help="comma separated CVE years (default: %(default)s)",
    )
    parser.add_argument(
        "--epss-date", default=_default_epss_date(),
        help="EPSS score date YYYY-MM-DD (default: yesterday)",
    )
    parser.add_argument("--skip-nvd", action="store_true")
    parser.add_argument("--skip-kev", action="store_true")
    parser.add_argument("--skip-epss", action="store_true")
    args = parser.parse_args(argv)

    years = [int(y) for y in args.years.split(",") if y.strip().isdigit()]
    print(f"Target feeds dir: {FEEDS_DIR}")
    print(f"Years: {years}  EPSS date: {args.epss_date}\n")

    if not args.skip_nvd:
        fetch_nvd(years)
    if not args.skip_kev:
        fetch_kev()
    if not args.skip_epss:
        fetch_epss(args.epss_date)

    print("\nDone. The pipeline will now prefer these full feeds over the "
          "bundled subset.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
