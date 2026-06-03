"""End-to-end integration test against the bundled real data subset.

This runs the complete pipeline on the project sample asset list using the real
CVE, KEV, and EPSS records that ship in data/bundled/, so it verifies genuine
behaviour rather than mocks.
"""

import csv

from cve_translator import config
from cve_translator.data_loader import parse_asset_list
from cve_translator.pipeline import run_pipeline
from cve_translator.report import write_brief, write_csv


def _sample_text():
    return config.SAMPLE_ASSET_LIST.read_text(encoding="utf-8")


def test_asset_list_parsing_handles_pipe_format():
    assets = parse_asset_list("Google Chrome | Latest\nOpenSSL | 3.0.7\n# comment\n")
    assert assets == [("Google Chrome", "Latest"), ("OpenSSL", "3.0.7")]


def test_full_pipeline_recognises_every_sample_asset():
    result = run_pipeline(_sample_text())
    assert result.stats["assets_supplied"] == 12
    assert result.stats["assets_recognised"] == 12


def test_full_pipeline_finds_known_exploited_cves():
    result = run_pipeline(_sample_text())
    assert result.stats["relevant_cves"] > 0
    assert result.stats["kev_matches"] > 0
    # The real VMware ESXi auth bypass used in ransomware must be present.
    ids = {r.cve_id for r in result.ranked}
    assert "CVE-2024-37085" in ids


def test_kev_entries_rank_above_non_kev():
    result = run_pipeline(_sample_text())
    ranked = result.ranked
    last_kev = max((i for i, r in enumerate(ranked) if r.in_kev), default=-1)
    first_non_kev = next((i for i, r in enumerate(ranked) if not r.in_kev), len(ranked))
    assert last_kev < first_non_kev


def test_kev_only_filter_returns_only_kev():
    result = run_pipeline(_sample_text(), kev_only=True)
    assert result.ranked
    assert all(r.in_kev for r in result.ranked)


def test_top_n_filter_limits_results():
    result = run_pipeline(_sample_text(), top_n=5)
    assert len(result.ranked) == 5


def test_outputs_write_successfully(tmp_path):
    result = run_pipeline(_sample_text(), top_n=10)
    csv_path = write_csv(result.ranked, tmp_path / "report.csv")
    brief_path = write_brief(result.ranked, result.assets, tmp_path / "brief.txt")

    assert csv_path.exists() and brief_path.exists()
    with open(csv_path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 10
    assert rows[0]["cve_id"].startswith("CVE-")
    assert "risk_summary" in rows[0]
