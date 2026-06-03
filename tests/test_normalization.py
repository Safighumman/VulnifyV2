"""Tests for the normalisation engine: messy names to canonical CPEs."""

from cve_translator.normalization import normalise_name


def test_informal_office_name_maps_to_365_apps():
    result = normalise_name("Microsoft 365 Apps for Business", "Current")
    assert result.recognised
    assert "microsoft:365_apps" in result.cpe_targets


def test_windows_10_pro_maps_to_prefix_target():
    result = normalise_name("Windows 10 Pro", "22H2")
    assert result.recognised
    assert result.cpe_targets == ["microsoft:windows_10*"]


def test_vsphere_maps_to_multiple_real_cpes():
    # vSphere is a suite with no single CPE; it resolves to its components.
    result = normalise_name("VMware vSphere", "8.0")
    assert result.recognised
    assert "vmware:vcenter_server" in result.cpe_targets
    assert "vmware:esxi" in result.cpe_targets


def test_zoom_maps_to_workplace_not_legacy_name():
    result = normalise_name("Zoom", "5.17")
    assert result.recognised
    assert "zoom:workplace" in result.cpe_targets


def test_nginx_maps_to_f5_vendor_namespace():
    result = normalise_name("nginx", "1.25")
    assert result.recognised
    assert any(t.startswith("f5:nginx") for t in result.cpe_targets)


def test_fuzzy_match_tolerates_spelling_noise():
    result = normalise_name("google chrome browser")
    assert result.recognised
    assert result.cpe_targets == ["google:chrome"]


def test_unknown_product_is_reported_not_silently_dropped():
    result = normalise_name("Totally Made Up Product 9000")
    assert not result.recognised
    assert result.cpe_targets == []


def test_canonical_name_is_exact_full_confidence():
    result = normalise_name("OpenSSL", "3.0.7")
    assert result.recognised
    assert result.score == 100.0
