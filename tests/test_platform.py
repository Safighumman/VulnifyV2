"""Tests for the platform layer: confidence, analytics, feeds, export, parsing."""

from cve_translator import analytics, config
from cve_translator.data_loader import parse_asset_list
from cve_translator.export import result_to_dict
from cve_translator.feeds import build_import_jobs
from cve_translator.pipeline import run_pipeline
from cve_translator.ranking import compute_confidence


def _sample():
    return config.SAMPLE_ASSET_LIST.read_text(encoding="utf-8")


# confidence scoring
def test_confidence_rewards_complete_records():
    rich = compute_confidence("Analyzed", True, True, ["CWE-79"], ["http://x"], True)
    poor = compute_confidence("Awaiting Analysis", False, False, [], [], False)
    assert rich > poor
    assert 0 <= poor <= 100 and 0 <= rich <= 100


def test_confidence_is_capped_at_100():
    assert compute_confidence("Analyzed", True, True, ["CWE-1"], ["u"], True) <= 100


# analytics
def test_dashboard_has_expected_sections():
    result = run_pipeline(_sample())
    d = analytics.build_dashboard(result.ranked, result.assets)
    for key in ("kpis", "severity", "epss_bands", "status_split",
                "by_category", "by_vendor", "by_cwe", "pub_timeline",
                "kev_timeline", "top_assets", "confidence_bands"):
        assert key in d
    k = d["kpis"]
    assert k["confirmed"] + k["unconfirmed"] == k["relevant_cves"]
    assert k["confirmed"] == k["kev"]


def test_status_split_matches_kev_count():
    result = run_pipeline(_sample())
    d = analytics.build_dashboard(result.ranked, result.assets)
    confirmed = next(s["value"] for s in d["status_split"] if s["label"] == "Confirmed")
    assert confirmed == sum(1 for r in result.ranked if r.in_kev)


def test_cwe_name_lookup():
    assert analytics.cwe_name("CWE-79") == "Cross-site Scripting"
    assert analytics.cwe_name("CWE-99999") == "CWE-99999"


# import jobs / feeds
def test_import_jobs_compute_speed():
    jobs = build_import_jobs({"nvd": 1000, "kev": 50, "epss": 1000},
                             {"nvd": 0.5, "kev": 0.01, "epss": 0.1})
    nvd = next(j for j in jobs if j["key"] == "nvd")
    assert nvd["records"] == 1000
    assert nvd["speed"] == 2000          # 1000 records / 0.5 s
    assert nvd["status"] == "completed"
    assert all(j["category"] for j in jobs)


# asset parsing
def test_parse_skips_spreadsheet_header():
    assets = parse_asset_list("Product,Version,Owner\nGoogle Chrome,Latest,IT\nOpenSSL,3.0.7,Core\n")
    assert ("Google Chrome", "Latest") in assets
    assert all("product" != n.lower() for n, _ in assets)


def test_parse_multicolumn_csv_takes_first_two_fields():
    assets = parse_asset_list("Windows 10 Pro,22H2,Lab,2024\n")
    assert assets == [("Windows 10 Pro", "22H2")]


# structured export
def test_result_to_dict_shape():
    result = run_pipeline(_sample(), top_n=10)
    payload = result_to_dict(result)
    assert payload["results_total"] >= len(payload["results"])
    assert payload["dashboard"]["kpis"]["relevant_cves"] >= 0
    row = payload["results"][0]
    for field in ("cve_id", "status", "confidence", "urgency", "summary",
                  "cvss_severity", "cwes", "references"):
        assert field in row
    assert isinstance(payload["assets"], list)
