"""Build the bundled real data subset that ships with the repository.

The full NVD year files are far too large to commit (hundreds of MB each), but
the tool should still produce real, verifiable results the moment it is cloned.
This script distils the full feeds down to a compact, fully real subset:

  * NVD  : every CVE whose CPE configuration references a vendor:product in our
           normalisation catalogue, trimmed to the fields the pipeline uses.
  * KEV  : the complete CISA catalogue (already small, copied verbatim).
  * EPSS : scores for exactly the CVEs kept in the NVD subset.

The output lands in data/bundled/ and is what data_loader falls back to when no
full feed is present. Records are real and untouched in meaning: only unused
fields (references, weaknesses, non-English descriptions) are dropped to shrink
the file.

Usage (defaults assume the full feeds already sit in a source directory):
    python scripts/build_sample_dataset.py \
        --nvd-dir /path/to/full/feeds \
        --kev /path/to/known_exploited_vulnerabilities.json \
        --epss /path/to/epss_scores.csv.gz \
        --years 2024,2025
"""

from __future__ import annotations

import argparse
import gzip
import json
import lzma
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cve_translator.cpe_catalog import all_cpe_targets  # noqa: E402

BUNDLED_DIR = REPO_ROOT / "data" / "bundled"

_TARGETS = all_cpe_targets()
_EXACT = {t for t in _TARGETS if not t.endswith("*")}
_PREFIXES = tuple(t[:-1] for t in _TARGETS if t.endswith("*"))


def _vp_is_relevant(vendor_product: str) -> bool:
    if vendor_product in _EXACT:
        return True
    return any(vendor_product.startswith(p) for p in _PREFIXES)


def _open_json(path: Path):
    name = path.name.lower()
    if name.endswith(".xz"):
        with lzma.open(path, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    if name.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _trim_record(item: dict) -> dict:
    """Keep only the fields the pipeline reads; preserve them faithfully."""
    en_desc = [
        d for d in item.get("descriptions", []) or [] if d.get("lang") == "en"
    ][:1]

    metrics_in = item.get("metrics", {}) or {}
    metrics_out = {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics_in.get(key) or []
        if entries:
            first = entries[0]
            metrics_out[key] = [{
                "cvssData": first.get("cvssData", {}),
                "baseSeverity": first.get("baseSeverity"),
            }]

    configs_out = []
    for cfg in item.get("configurations", []) or []:
        nodes_out = []
        for node in cfg.get("nodes", []) or []:
            cpe_out = []
            for m in node.get("cpeMatch", []) or []:
                entry = {"criteria": m.get("criteria", ""),
                         "vulnerable": m.get("vulnerable", True)}
                for vk in ("versionStartIncluding", "versionStartExcluding",
                           "versionEndIncluding", "versionEndExcluding"):
                    if m.get(vk) is not None:
                        entry[vk] = m[vk]
                cpe_out.append(entry)
            nodes_out.append({"operator": node.get("operator", "OR"),
                              "cpeMatch": cpe_out})
        configs_out.append({"nodes": nodes_out})

    # Keep CWE weaknesses and a handful of references for the detail view.
    weaknesses_out = []
    for w in item.get("weaknesses", []) or []:
        descs = [{"lang": d.get("lang"), "value": d.get("value")}
                 for d in w.get("description", []) or []
                 if str(d.get("value", "")).startswith("CWE-")]
        if descs:
            weaknesses_out.append({"type": w.get("type", ""), "description": descs})

    refs_out = [{"url": r.get("url")} for r in (item.get("references", []) or [])[:6]
                if r.get("url")]

    return {
        "id": item.get("id", ""),
        "published": item.get("published", ""),
        "lastModified": item.get("lastModified", ""),
        "vulnStatus": item.get("vulnStatus", ""),
        "descriptions": en_desc,
        "metrics": metrics_out,
        "weaknesses": weaknesses_out,
        "references": refs_out,
        "configurations": configs_out,
    }


def _record_touches_catalog(item: dict) -> bool:
    for cfg in item.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                parts = m.get("criteria", "").split(":")
                if len(parts) > 5 and _vp_is_relevant(f"{parts[3]}:{parts[4]}"):
                    return True
    return False


def build_nvd_subset(nvd_dir: Path, years: list[int]) -> set[str]:
    kept: list[dict] = []
    kept_ids: set[str] = set()
    for year in years:
        path = None
        for ext in (".json", ".json.xz", ".json.gz"):
            cand = nvd_dir / f"CVE-{year}{ext}"
            if cand.exists():
                path = cand
                break
        if path is None:
            print(f"  WARNING: no NVD file for {year} in {nvd_dir}")
            continue
        print(f"  scanning {path.name} ...")
        payload = _open_json(path)
        items = payload.get("cve_items") or payload.get("CVE_Items") or []
        for item in items:
            if _record_touches_catalog(item):
                kept.append(_trim_record(item))
                kept_ids.add(item.get("id", ""))
        print(f"    kept {len(kept_ids):,} relevant CVEs so far")

    out = BUNDLED_DIR / "nvd_cve_relevant.json.gz"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "feed_name": "CVE-to-My-Stack bundled subset (real NVD records)",
        "cve_count": len(kept),
        "source": "Fraunhofer FKIE nvd-json-data-feeds, filtered to catalogue vendors",
        "cve_items": kept,
    }
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        json.dump(payload, fh)
    print(f"  wrote {out} ({out.stat().st_size:,} bytes, {len(kept):,} CVEs)")
    return kept_ids


def copy_kev(kev_path: Path) -> None:
    dest = BUNDLED_DIR / "known_exploited_vulnerabilities.json"
    payload = _open_json(kev_path)
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    print(f"  wrote {dest} ({dest.stat().st_size:,} bytes, "
          f"{len(payload.get('vulnerabilities', []))} entries)")


def build_epss_subset(epss_path: Path, keep_ids: set[str]) -> None:
    import pandas as pd

    compression = "gzip" if epss_path.name.endswith(".gz") else "infer"
    frame = pd.read_csv(epss_path, comment="#", compression=compression)
    subset = frame[frame["cve"].isin(keep_ids)]
    dest = BUNDLED_DIR / "epss_scores.csv.gz"
    subset.to_csv(dest, index=False, compression="gzip")
    print(f"  wrote {dest} ({dest.stat().st_size:,} bytes, "
          f"{len(subset):,} of {len(frame):,} EPSS rows)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the bundled real subset.")
    parser.add_argument("--nvd-dir", required=True, type=Path)
    parser.add_argument("--kev", required=True, type=Path)
    parser.add_argument("--epss", required=True, type=Path)
    parser.add_argument("--years", default="2024,2025")
    args = parser.parse_args(argv)

    years = [int(y) for y in args.years.split(",") if y.strip().isdigit()]
    print(f"Catalogue CPE targets: {len(_TARGETS)} "
          f"({len(_EXACT)} exact, {len(_PREFIXES)} prefix)")
    print("Building NVD subset:")
    keep_ids = build_nvd_subset(args.nvd_dir, years)
    print("Copying KEV catalogue:")
    copy_kev(args.kev)
    print("Building EPSS subset:")
    build_epss_subset(args.epss, keep_ids)
    print("\nBundled real dataset ready in data/bundled/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
