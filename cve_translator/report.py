"""Render the ranked results: CSV, console table, and a one-page brief.

Three output forms, all driven from the same ranked list:

  * ``write_csv``       the structured prioritised table (the core deliverable)
  * ``console_table``   a readable table for the terminal demo
  * ``write_brief``     a one-page plain-text briefing (a stretch goal)
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from tabulate import tabulate

from .normalization import NormalisationResult
from .ranking import RankedCve
from .risk_summary import recommended_action, risk_sentence

CSV_COLUMNS = [
    "rank",
    "cve_id",
    "affected_asset",
    "asset_as_supplied",
    "status",
    "cvss_score",
    "cvss_severity",
    "epss_score",
    "epss_percentile",
    "kev_flag",
    "kev_ransomware",
    "confidence",
    "confidence_band",
    "urgency_score",
    "weaknesses",
    "matched_cpe",
    "recommended_action",
    "risk_summary",
]


def _row_dict(rank: int, r: RankedCve) -> dict:
    return {
        "rank": rank,
        "cve_id": r.cve_id,
        "affected_asset": r.asset_display,
        "asset_as_supplied": r.asset_raw,
        "status": r.status,
        "cvss_score": r.cvss_display,
        "cvss_severity": r.cvss_severity or "n/a",
        "epss_score": r.epss_display,
        "epss_percentile": (
            f"{r.epss_percentile:.4f}" if r.epss_percentile is not None else "n/a"
        ),
        "kev_flag": "Yes" if r.in_kev else "No",
        "kev_ransomware": "Yes" if r.kev_ransomware else "No",
        "confidence": r.confidence,
        "confidence_band": r.confidence_band,
        "urgency_score": f"{r.urgency:.4f}",
        "weaknesses": ", ".join(r.cwes),
        "matched_cpe": ", ".join(r.matched_cpes),
        "recommended_action": recommended_action(r),
        "risk_summary": risk_sentence(r),
    }


def write_csv(ranked: List[RankedCve], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for i, r in enumerate(ranked, start=1):
            writer.writerow(_row_dict(i, r))
    return path


def console_table(ranked: List[RankedCve], limit: int = 20) -> str:
    headers = ["#", "CVE", "Asset", "CVSS", "EPSS", "KEV", "Urgency", "Action"]
    rows = []
    for i, r in enumerate(ranked[:limit], start=1):
        rows.append([
            i,
            r.cve_id,
            _truncate(r.asset_display, 22),
            r.cvss_display,
            r.epss_display,
            r.kev_display,
            f"{r.urgency:.3f}",
            _truncate(recommended_action(r), 46),
        ])
    if not rows:
        return "No relevant CVEs found for the supplied asset list."
    return tabulate(rows, headers=headers, tablefmt="github")


def _truncate(text: str, width: int) -> str:
    text = text or ""
    return text if len(text) <= width else text[: width - 1] + "…"


def write_brief(
    ranked: List[RankedCve],
    assets: List[NormalisationResult],
    path: Path,
    top_n: int = 10,
) -> Path:
    """Write a one-page plain-text briefing suitable for a manager or CISO."""
    path.parent.mkdir(parents=True, exist_ok=True)

    recognised = [a for a in assets if a.recognised]
    unrecognised = [a for a in assets if not a.recognised]
    kev_hits = [r for r in ranked if r.in_kev]
    ransomware_hits = [r for r in ranked if r.kev_ransomware]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("CVE-TO-MY-STACK TRANSLATOR : PATCH PRIORITISATION BRIEF")
    lines.append(f"Generated {now}")
    lines.append("=" * 72)
    lines.append("")
    lines.append("SUMMARY")
    lines.append(f"  Assets supplied      : {len(assets)}")
    lines.append(f"  Assets recognised    : {len(recognised)}")
    lines.append(f"  Relevant CVEs found  : {len(ranked)}")
    lines.append(f"  Actively exploited   : {len(kev_hits)} (in CISA KEV)")
    lines.append(f"  Ransomware-linked    : {len(ransomware_hits)}")
    lines.append("")

    lines.append(f"TOP {min(top_n, len(ranked))} ACTIONS (highest urgency first)")
    lines.append("")
    if not ranked:
        lines.append("  No relevant CVEs were found for the supplied assets.")
    for i, r in enumerate(ranked[:top_n], start=1):
        lines.append(f"{i:>2}. {r.cve_id}  [{r.kev_display}]  "
                     f"CVSS {r.cvss_display}  EPSS {r.epss_display}")
        lines.append(f"    {risk_sentence(r)}")
        lines.append(f"    Action: {recommended_action(r)}")
        lines.append("")

    if unrecognised:
        lines.append("UNRECOGNISED ASSETS (no confident CPE mapping)")
        lines.append("")
        lines.append("  These were not matched and may hide real vulnerabilities.")
        lines.append("  Review the spelling or extend the normalisation catalogue:")
        for a in unrecognised:
            lines.append(f"    * {a.raw_name}")
        lines.append("")

    lines.append("METHOD AND CAVEATS")
    lines.append("")
    lines.append("  Urgency blends CISA KEV (actively exploited), EPSS")
    lines.append("  (probability of exploitation in the next 30 days), and CVSS")
    lines.append("  (technical severity). KEV entries are always surfaced first.")
    lines.append("  A low score is not a guarantee of safety: EPSS is predictive,")
    lines.append("  and a CVE absent from KEV may simply be unconfirmed.")
    lines.append("=" * 72)

    text = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path
