#!/usr/bin/env python3
"""Command-line interface for the CVE-to-My-Stack Translator.

Accepts an asset list file (a stretch goal) and prints a prioritised CVE table,
optionally writing the full CSV and a one-page brief.

Examples:
    python cli.py data/sample_asset_list.txt
    python cli.py my_assets.txt --top 15 --csv output/report.csv --brief output/brief.txt
    python cli.py my_assets.txt --kev-only
    python cli.py my_assets.txt --min-epss 0.1
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cve_translator import config
from cve_translator.pipeline import run_pipeline
from cve_translator.report import console_table, write_brief, write_csv


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cve-to-my-stack",
        description="Translate a software asset list into a prioritised CVE "
                    "action list, ranked by real-world exploitability.",
    )
    parser.add_argument(
        "asset_list", nargs="?", default=str(config.SAMPLE_ASSET_LIST),
        help="path to the asset list file (default: the bundled sample list)",
    )
    parser.add_argument("--top", type=int, default=None,
                        help="show only the N most urgent CVEs")
    parser.add_argument("--min-epss", type=float, default=0.0,
                        help="drop CVEs below this EPSS score (0 to 1)")
    parser.add_argument("--kev-only", action="store_true",
                        help="show only CVEs in the CISA KEV catalogue")
    parser.add_argument("--csv", type=Path, default=None,
                        help="write the full prioritised table to this CSV path")
    parser.add_argument("--brief", type=Path, default=None,
                        help="write a one-page summary brief to this path")
    parser.add_argument("--json", type=Path, default=None,
                        help="write the full structured result (dashboard, "
                             "rows, assets, feeds) to this JSON path")
    parser.add_argument("--limit", type=int, default=25,
                        help="rows to print in the console table (default: 25)")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the stats and asset diagnostics")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    asset_path = Path(args.asset_list)
    if not asset_path.exists():
        print(f"error: asset list not found: {asset_path}", file=sys.stderr)
        return 2

    result = run_pipeline(
        asset_path.read_text(encoding="utf-8"),
        top_n=args.top,
        min_epss=args.min_epss,
        kev_only=args.kev_only,
    )

    if not args.quiet:
        s = result.stats
        print()
        print(f"Scanned {s['cve_records_scanned']:,} CVE records | "
              f"KEV catalogue {s['kev_catalogue_size']:,} | "
              f"EPSS scores {s['epss_scores_loaded']:,}")
        print(f"Assets: {s['assets_recognised']}/{s['assets_supplied']} recognised "
              f"| Relevant CVEs: {s['relevant_cves']} "
              f"| Actively exploited (KEV): {s['kev_matches']}")

        unrecognised = result.unrecognised_assets
        if unrecognised:
            print("\nUnrecognised assets (no confident CPE mapping, review these):")
            for a in unrecognised:
                hint = f" (best guess scored {a.score:.0f})" if a.score else ""
                print(f"  - {a.raw_name}{hint}")
        print()

    print(console_table(result.ranked, limit=args.limit))
    print()

    if args.csv:
        path = write_csv(result.ranked, args.csv)
        print(f"CSV written: {path}")
    if args.brief:
        path = write_brief(result.ranked, result.assets, args.brief,
                           top_n=args.top or 10)
        print(f"Brief written: {path}")
    if args.json:
        import json
        from cve_translator.export import result_to_dict
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result_to_dict(result), indent=2),
                             encoding="utf-8")
        print(f"JSON written: {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
