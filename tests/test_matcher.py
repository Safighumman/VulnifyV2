"""Tests for CVE matching and version-range logic."""

from cve_translator.data_loader import CpeMatch, CveRecord
from cve_translator.matcher import match_assets, version_is_compatible
from cve_translator.normalization import normalise_name


def _cpe(vp: str, version="*", **bounds) -> CpeMatch:
    vendor, product = vp.split(":")
    return CpeMatch(
        criteria=f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        vendor=vendor, product=product, version=version, vuln=True, **bounds,
    )


def _cve(cve_id: str, *cpes: CpeMatch, score=7.5) -> CveRecord:
    return CveRecord(
        cve_id=cve_id, description=f"desc {cve_id}", cvss_score=score,
        cvss_severity="HIGH", cvss_vector="", cvss_version="3.1",
        published="2024-01-01", cpe_matches=list(cpes),
    )


# version logic
def test_informal_version_always_matches():
    ok, refined = version_is_compatible("Current", _cpe("openssl:openssl"))
    assert ok and not refined


def test_version_range_excludes_patched_version():
    # CVE fixed in 3.0.7; an asset on 3.0.7 is no longer vulnerable.
    m = _cpe("openssl:openssl", version="*",
             start_inc="3.0.0", end_exc="3.0.7")
    ok, refined = version_is_compatible("3.0.7", m)
    assert not ok and refined


def test_version_range_includes_affected_version():
    m = _cpe("openssl:openssl", version="*",
             start_inc="3.0.0", end_exc="3.0.8")
    ok, refined = version_is_compatible("3.0.7", m)
    assert ok and refined


def test_windows_release_matches_same_tag():
    m = _cpe("microsoft:windows_10_22h2", version="10.0.19045.0")
    ok, _ = version_is_compatible("22H2", m)
    assert ok


def test_windows_release_excludes_different_tag():
    m = _cpe("microsoft:windows_10_21h2", version="10.0.19044.0")
    ok, _ = version_is_compatible("22H2", m)
    assert not ok


def test_windows_base_product_matches_any_release():
    m = _cpe("microsoft:windows_server_2022", version="10.0.20348.0")
    ok, _ = version_is_compatible("21H2", m)
    assert ok


# end to end matching on synthetic records
def test_match_assets_finds_relevant_cve_only():
    chrome = normalise_name("Google Chrome", "Latest")
    openssl = normalise_name("OpenSSL", "3.0.7")

    relevant = _cve("CVE-2024-0001", _cpe("google:chrome", version="120.0"))
    irrelevant = _cve("CVE-2024-9999", _cpe("acme:widget", version="1.0"))

    matches = match_assets([relevant, irrelevant], [chrome, openssl])
    ids = {m.cve.cve_id for m in matches}
    assert "CVE-2024-0001" in ids
    assert "CVE-2024-9999" not in ids


def test_prefix_target_matches_versioned_windows_product():
    win = normalise_name("Windows 10 Pro", "22H2")
    cve = _cve("CVE-2024-1000", _cpe("microsoft:windows_10_22h2", "10.0.19045.1"))
    matches = match_assets([cve], [win])
    assert len(matches) == 1
    assert matches[0].cve.cve_id == "CVE-2024-1000"
