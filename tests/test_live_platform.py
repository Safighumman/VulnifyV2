"""Tests for the live platform layer: sectors, mitigation, geo, connectors,
the live ingestion engine, and the enriched export payload."""

import json

from cve_translator import (analytics, config, connectors, geo, mitigation,
                            sectors)
from cve_translator.export import result_to_dict
from cve_translator.live_feed import FeedHealth, LiveEngine
from cve_translator.normalization import normalise_name
from cve_translator.pipeline import run_pipeline


def _sample():
    return config.SAMPLE_ASSET_LIST.read_text(encoding="utf-8")


# ---------- sectors ----------
def test_sector_classification_specialised_vs_common():
    moodle = normalise_name("Moodle 4.3")
    mysql = normalise_name("MySQL 8.0")
    win = normalise_name("Windows 10 Pro")
    assert sectors.sector_for_asset(moodle) == "education"
    assert sectors.sector_for_asset(mysql) == "technology"
    assert sectors.sector_for_asset(win) == "common"


def test_sector_keyword_override_finance():
    sage = normalise_name("Sage Payroll 22")
    # Even though unrecognised by the CPE catalogue, the keyword pins finance.
    assert sectors.sector_for_asset(sage) == "finance"


def test_sector_meta_and_taxonomy():
    keys = {s["key"] for s in sectors.all_sector_meta()}
    for expected in ("common", "education", "finance", "healthcare"):
        assert expected in keys
    meta = sectors.sector_meta("education")
    assert meta["name"] == "Education" and meta["color"].startswith("#")


def test_build_asset_sector_map():
    result = run_pipeline(_sample())
    amap = sectors.build_asset_sector_map(result.assets)
    assert all(isinstance(v, str) for v in amap.values())
    assert "Moodle" in amap and amap["Moodle"] == "education"


# ---------- mitigation ----------
def test_mitigation_structure_and_doc_links():
    result = run_pipeline(_sample(), top_n=5)
    r = result.ranked[0]
    m = mitigation.mitigation_for(r)
    assert m["priority"] in ("Immediate", "Urgent", "Scheduled", "Routine")
    assert len(m["steps"]) >= 2
    urls = [l["url"] for l in m["doc_links"]]
    assert any(u.endswith("nvd.nist.gov/vuln/detail/" + r.cve_id) for u in urls)
    assert any("cve.org" in u for u in urls)


def test_kev_cve_gets_immediate_priority():
    result = run_pipeline(_sample())
    kev = next((r for r in result.ranked if r.in_kev), None)
    assert kev is not None
    assert mitigation.mitigation_for(kev)["priority"] == "Immediate"


def test_zero_day_detection_and_official_name():
    result = run_pipeline(_sample())
    zds = [r for r in result.ranked if mitigation.is_zero_day(r)]
    assert zds, "expected at least one zero-day-class CVE in the sample run"
    det = mitigation.zero_day_details(zds[0])
    assert det["official_name"]            # the official KEV name, not a nickname
    assert "added_to_kev" in det


def test_feed_mitigation_present_for_each_source():
    for key in ("nvd", "kev", "epss"):
        m = mitigation.feed_mitigation(key)
        assert m["summary"] and m["action"]


# ---------- geo / threat map ----------
def test_threat_map_nodes_have_coordinates():
    result = run_pipeline(_sample())
    nodes = geo.build_threat_map(result.ranked)
    assert nodes
    n = nodes[0]
    for f in ("vendor", "x", "y", "cves", "kev"):
        assert f in n
    assert 0 <= n["x"] <= 1 and 0 <= n["y"] <= 1


def test_region_rollup_shape():
    result = run_pipeline(_sample())
    regions = geo.region_rollup(result.ranked)
    assert all("country" in r and "cves" in r for r in regions)


# ---------- connectors ----------
def _isolate_connectors(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONNECTORS_FILE", tmp_path / "connectors.json")


def test_builtin_connectors_present(monkeypatch, tmp_path):
    _isolate_connectors(monkeypatch, tmp_path)
    ids = {c["id"] for c in connectors.list_connectors()}
    assert {"nvd", "kev", "epss"} <= ids


def test_add_update_remove_user_connector(monkeypatch, tmp_path):
    _isolate_connectors(monkeypatch, tmp_path)
    rec = connectors.add_connector({"name": "Internal mirror",
                                    "url": "https://example.org/feed.json"})
    cid = rec["id"]
    assert connectors.get_connector(cid)["enabled"] is True
    connectors.update_connector(cid, {"enabled": False, "interval": 60})
    updated = connectors.get_connector(cid)
    assert updated["enabled"] is False and updated["interval"] == 60
    assert connectors.remove_connector(cid) is True
    assert connectors.get_connector(cid) is None


def test_builtin_cannot_be_removed_but_can_be_toggled(monkeypatch, tmp_path):
    _isolate_connectors(monkeypatch, tmp_path)
    assert connectors.remove_connector("kev") is False
    connectors.update_connector("kev", {"enabled": False})
    assert connectors.get_connector("kev")["enabled"] is False
    # The override persists to disk.
    assert (tmp_path / "connectors.json").exists()


def test_add_connector_requires_name_and_url(monkeypatch, tmp_path):
    _isolate_connectors(monkeypatch, tmp_path)
    try:
        connectors.add_connector({"name": "no url"})
        assert False, "expected ValueError"
    except ValueError:
        pass


# ---------- enriched export ----------
def test_export_includes_sector_mitigation_zeroday():
    result = run_pipeline(_sample(), top_n=20)
    payload = result_to_dict(result)
    row = payload["results"][0]
    for field in ("sector", "sector_name", "mitigation", "zero_day",
                  "is_zero_day", "doc_url"):
        assert field in row
    assert row["mitigation"]["steps"]
    assert "sectors" in payload and payload["generated_by"].startswith("Vulnify")


def test_dashboard_has_soc_widgets():
    result = run_pipeline(_sample())
    d = analytics.build_dashboard(result.ranked, result.assets)
    for key in ("gauges", "heatmap", "by_sector", "threat_map", "regions"):
        assert key in d
    g = d["gauges"]
    for gk in ("overall", "exploitation", "coverage"):
        assert 0 <= g[gk]["value"] <= 100 and g[gk]["label"]
    # Heatmap rows sum to their sector CVE totals.
    for row in d["heatmap"]:
        assert sum(c["value"] for c in row["cells"]) == row["total"]


def test_payload_is_json_serialisable():
    result = run_pipeline(_sample(), top_n=10)
    json.dumps(result_to_dict(result))     # must not raise


# ---------- live ingestion engine (offline) ----------
def test_live_engine_bootstraps_and_seeds_events_offline():
    eng = LiveEngine()
    eng._live_enabled = False              # never spawn a network thread in tests
    eng.start()
    snap = eng.snapshot()
    assert snap["live_enabled"] is False
    assert len(snap["feeds"]) >= 3
    assert snap["events"], "live stream should be seeded from bundled data"
    assert snap["counts"]["confirmed"] + snap["counts"]["unconfirmed"] == len(snap["events"])


def test_live_event_has_status_and_sector():
    eng = LiveEngine()
    eng._live_enabled = False
    eng.start()
    ev = eng.snapshot()["events"][0]
    assert ev["status"] in ("Confirmed", "Unconfirmed")
    assert ev["cve_id"] and "sector" in ev


def test_feed_health_serialises():
    fh = FeedHealth(key="kev", name="CISA KEV", provider="CISA",
                    category="Confirmed exploitation", fmt="json")
    d = fh.to_dict()
    assert d["key"] == "kev" and d["status"] == "idle"
