"""Tests for the urgency ranking logic."""

from cve_translator.data_loader import CpeMatch, CveRecord
from cve_translator.matcher import AssetMatch
from cve_translator.ranking import compute_urgency, rank_matches


def _match(cve_id, score=7.0):
    rec = CveRecord(cve_id=cve_id, description="d", cvss_score=score,
                    cvss_severity="HIGH", cvss_vector="", cvss_version="3.1",
                    published="2024-01-01", cpe_matches=[])
    am = AssetMatch(cve=rec)
    return am


def test_kev_always_outranks_non_kev():
    kev = compute_urgency(epss=0.01, cvss=4.0, in_kev=True, ransomware=False)
    hot = compute_urgency(epss=0.99, cvss=10.0, in_kev=False, ransomware=False)
    assert kev > hot


def test_ransomware_outranks_plain_kev():
    plain = compute_urgency(epss=0.5, cvss=8.0, in_kev=True, ransomware=False)
    ransom = compute_urgency(epss=0.5, cvss=8.0, in_kev=True, ransomware=True)
    assert ransom > plain


def test_epss_orders_within_band():
    low = compute_urgency(epss=0.1, cvss=5.0, in_kev=False, ransomware=False)
    high = compute_urgency(epss=0.8, cvss=5.0, in_kev=False, ransomware=False)
    assert high > low


def test_rank_matches_sorts_kev_to_top():
    matches = [_match("CVE-A"), _match("CVE-B"), _match("CVE-C")]
    epss = {"CVE-A": {"epss": 0.95, "percentile": 0.99},
            "CVE-B": {"epss": 0.02, "percentile": 0.30},
            "CVE-C": {"epss": 0.10, "percentile": 0.60}}
    kev_ids = {"CVE-B"}
    kev_detail = {"CVE-B": {"ransomware": False, "dateAdded": "2024-05-01"}}

    ranked = rank_matches(matches, epss, kev_ids, kev_detail)
    assert ranked[0].cve_id == "CVE-B"          # KEV first despite low EPSS
    assert ranked[1].cve_id == "CVE-A"          # then highest EPSS
    assert ranked[2].cve_id == "CVE-C"
