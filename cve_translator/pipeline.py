"""End-to-end orchestration: asset list in, prioritised CVEs out.

    parse assets -> normalise -> load feeds -> match -> enrich -> rank -> filter

The pipeline keeps everything in memory (no database, per the brief). The feed
data is loaded once and cached, so the command line tool runs cleanly and the
web dashboard can answer repeated queries instantly without re-reading the data.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from . import data_loader, feeds, normalization
from .data_loader import CveRecord
from .matcher import match_assets
from .normalization import NormalisationResult
from .ranking import RankedCve, rank_matches


@dataclass
class LoadedData:
    """The three feeds loaded into memory, with load timings and counts."""

    records: List[CveRecord]
    kev_ids: Set[str]
    kev_detail: Dict[str, dict]
    epss_map: Dict[str, dict]
    counts: Dict[str, int]
    timings: Dict[str, float]


@dataclass
class PipelineResult:
    assets: List[NormalisationResult]
    ranked: List[RankedCve]
    stats: dict = field(default_factory=dict)

    @property
    def recognised_assets(self) -> List[NormalisationResult]:
        return [a for a in self.assets if a.recognised]

    @property
    def unrecognised_assets(self) -> List[NormalisationResult]:
        return [a for a in self.assets if not a.recognised]


_CACHE: Optional[LoadedData] = None


def current_data() -> Optional[LoadedData]:
    """Return the currently cached corpus without triggering a load."""
    return _CACHE


def set_cache(data: LoadedData) -> None:
    """Atomically replace the cached corpus (used by the live ingest engine)."""
    global _CACHE
    _CACHE = data


def load_data(force: bool = False) -> LoadedData:
    """Load and cache the feed data. Subsequent calls reuse the loaded copy."""
    global _CACHE
    if _CACHE is not None and not force:
        return _CACHE

    t0 = time.perf_counter()
    records = data_loader.load_cve_records()
    t_nvd = time.perf_counter() - t0

    t0 = time.perf_counter()
    kev_ids, kev_detail = data_loader.load_kev_set()
    t_kev = time.perf_counter() - t0

    t0 = time.perf_counter()
    epss_map = data_loader.load_epss_map()
    t_epss = time.perf_counter() - t0

    _CACHE = LoadedData(
        records=records,
        kev_ids=kev_ids,
        kev_detail=kev_detail,
        epss_map=epss_map,
        counts={"nvd": len(records), "kev": len(kev_ids), "epss": len(epss_map)},
        timings={"nvd": t_nvd, "kev": t_kev, "epss": t_epss},
    )
    return _CACHE


def run_pipeline(
    asset_text: str,
    top_n: Optional[int] = None,
    min_epss: float = 0.0,
    kev_only: bool = False,
    data: Optional[LoadedData] = None,
) -> PipelineResult:
    """Run the full translation pipeline against raw asset list text.

    Args:
        asset_text: the raw asset list, in any of the supported layouts.
        top_n: keep only the N most urgent CVEs (None keeps all).
        min_epss: drop CVEs below this EPSS score (0.0 keeps all).
        kev_only: keep only CVEs in the CISA KEV catalogue.
        data: pre-loaded feed data (defaults to the cached load).
    """
    timings: Dict[str, float] = {}
    data = data or load_data()

    t0 = time.perf_counter()
    raw_assets = data_loader.parse_asset_list(asset_text)
    assets = normalization.normalise_assets(raw_assets)
    timings["normalise_s"] = round(time.perf_counter() - t0, 3)
    timings["load_s"] = round(sum(data.timings.values()), 3)

    t0 = time.perf_counter()
    matches = match_assets(data.records, assets)
    timings["match_s"] = round(time.perf_counter() - t0, 3)

    t0 = time.perf_counter()
    ranked = rank_matches(matches, data.epss_map, data.kev_ids, data.kev_detail)
    timings["rank_s"] = round(time.perf_counter() - t0, 3)

    # Optional filtering for a shorter, sharper action list.
    if kev_only:
        ranked = [r for r in ranked if r.in_kev]
    if min_epss > 0.0:
        ranked = [r for r in ranked if (r.epss or 0.0) >= min_epss]
    if top_n is not None:
        ranked = ranked[:top_n]

    stats = {
        "cve_records_scanned": data.counts["nvd"],
        "kev_catalogue_size": data.counts["kev"],
        "epss_scores_loaded": data.counts["epss"],
        "assets_supplied": len(assets),
        "assets_recognised": sum(1 for a in assets if a.recognised),
        "relevant_cves": len(ranked),
        "kev_matches": sum(1 for r in ranked if r.in_kev),
        "timings": timings,
        "import_jobs": feeds.build_import_jobs(data.counts, data.timings),
    }
    return PipelineResult(assets=assets, ranked=ranked, stats=stats)


def run_pipeline_file(path: Path, **kwargs) -> PipelineResult:
    with open(path, "r", encoding="utf-8") as fh:
        return run_pipeline(fh.read(), **kwargs)
