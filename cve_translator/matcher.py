"""Match the CVE corpus against a normalised asset list.

A CVE is considered relevant to an asset when the CVE's configuration block
references a CPE whose ``vendor:product`` matches one of the asset's catalogue
targets (exact, or prefix when the target ends in ``*``), and the asset's
version is compatible with that CPE entry.

Version handling embodies the central lesson of the brief: matching fails
silently. When a version cannot be confidently parsed or the asset version is
informal ("Current", "Latest", or blank), the match is kept rather than
dropped, so a genuinely relevant CVE is never lost on a version technicality.
When versions can be compared, range matching (a stretch goal) narrows the
result to avoid obvious false positives.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .data_loader import CpeMatch, CveRecord
from .normalization import NormalisationResult

_INFORMAL_VERSIONS = {"", "current", "latest", "n/a", "any", "unspecified"}

# Windows client release tags that appear inside CPE product names, for example
# "windows_10_22h2" or "windows_10_1809". Server release tags such as "23h2"
# match the \d{2}h\d pattern generically. Underscores in product names are not
# regex word boundaries, so explicit non-alphanumeric lookarounds are used to
# isolate the tag (and to avoid matching build numbers like 10.0.19045).
_WIN_RELEASE_RE = re.compile(
    r"(?<![a-z0-9])(\d{2}h\d|150[57]|160[37]|170[39]|180[39]|190[39]|200[49])(?![a-z0-9])"
)


# Windows release handling
def _release_tag(text: str) -> Optional[str]:
    """Extract a Windows release tag (22h2, 21h2, 1809, ...) or None."""
    if not text:
        return None
    match = _WIN_RELEASE_RE.search(text.lower())
    return match.group(1) if match else None


def _windows_decision(asset_version: str, product: str) -> Tuple[bool, bool]:
    """Resolve a Windows match by release tag rather than build number.

    Windows encodes its release (22H2, 23H2, ...) in the CPE product name, while
    the CPE version field holds an unrelated build number such as
    10.0.19045.x. Comparing the asset's release against that build number is
    meaningless, so we match on the release tag in the product name instead.
    """
    asset_release = _release_tag(asset_version)
    product_release = _release_tag(product)

    if asset_release is None:
        # No release supplied: match every release of the product (recall).
        return True, False
    if product_release is None:
        # Product has no release granularity (e.g. windows_server_2022 base).
        return True, True
    # Both carry a release tag: match only when they are the same release.
    return asset_release == product_release, True


# Version comparison (dependency free, predictable)
def _parse_version(value: Optional[str]) -> Optional[Tuple[int, ...]]:
    """Turn a version string into a tuple of ints, or None if not numeric.

    Examples: "3.0.7" -> (3, 0, 7); "2.4.57" -> (2, 4, 57); "17.9" -> (17, 9).
    Non-numeric schemes (for example "current") return None so the caller can
    decide to keep the match rather than guess.
    """
    if value is None:
        return None
    nums = re.findall(r"\d+", value)
    if not nums:
        return None
    return tuple(int(n) for n in nums)


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    """Compare two version tuples, padding the shorter with zeros."""
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return (a > b) - (a < b)


def version_is_compatible(asset_version: str, m: CpeMatch) -> Tuple[bool, bool]:
    """Decide whether an asset version is in scope for a CPE match.

    Returns (compatible, refined) where ``refined`` is True only when an actual
    version comparison was performed (as opposed to an informal pass-through).
    """
    # Windows uses release tags in the product name, not comparable build
    # numbers in the version field, so it gets a dedicated decision path.
    if m.product.startswith("windows"):
        return _windows_decision(asset_version, m.product)

    av = (asset_version or "").strip().lower()
    if av in _INFORMAL_VERSIONS:
        return True, False

    asset = _parse_version(av)
    if asset is None:
        # We could not parse the asset version, so do not risk a silent miss.
        return True, False

    has_bounds = any([m.start_inc, m.start_exc, m.end_inc, m.end_exc])

    if has_bounds:
        start_inc = _parse_version(m.start_inc)
        start_exc = _parse_version(m.start_exc)
        end_inc = _parse_version(m.end_inc)
        end_exc = _parse_version(m.end_exc)
        if start_inc is not None and _cmp(asset, start_inc) < 0:
            return False, True
        if start_exc is not None and _cmp(asset, start_exc) <= 0:
            return False, True
        if end_inc is not None and _cmp(asset, end_inc) > 0:
            return False, True
        if end_exc is not None and _cmp(asset, end_exc) >= 0:
            return False, True
        return True, True

    # No range bounds: fall back to the exact version inside the CPE string.
    if m.version not in {"*", "-", ""}:
        cpe_ver = _parse_version(m.version)
        if cpe_ver is None:
            return True, False
        # Match when the asset version equals the CPE version, or shares its
        # release line (e.g. asset 3.0.7 against CPE 3.0 family).
        return _cmp(asset, cpe_ver) == 0 or _shares_prefix(asset, cpe_ver), True

    # CPE covers every version of the product (version == "*" and no bounds).
    return True, False


def _shares_prefix(a: Tuple[int, ...], b: Tuple[int, ...]) -> bool:
    n = min(len(a), len(b))
    return n > 0 and a[:n] == b[:n]


# CPE index and matching
@dataclass
class AssetMatch:
    """One CVE that is relevant to one or more assets in the user's list."""

    cve: CveRecord
    matched_assets: List[NormalisationResult] = field(default_factory=list)
    matched_cpes: List[str] = field(default_factory=list)
    version_refined: bool = False

    @property
    def asset_display(self) -> str:
        names = []
        for a in self.matched_assets:
            label = a.display_name
            if label not in names:
                names.append(label)
        return "; ".join(names)

    @property
    def asset_raw(self) -> str:
        names = []
        for a in self.matched_assets:
            raw = a.raw_name.strip()
            if raw not in names:
                names.append(raw)
        return "; ".join(names)


class CveIndex:
    """An index of CVE records keyed by ``vendor:product`` for fast lookup."""

    def __init__(self, records: List[CveRecord]):
        self._by_vp: Dict[str, List[Tuple[CveRecord, CpeMatch]]] = defaultdict(list)
        for rec in records:
            seen_vp = set()
            for m in rec.cpe_matches:
                if not m.vuln:
                    continue
                self._by_vp[m.vendor_product].append((rec, m))
                seen_vp.add(m.vendor_product)
        self._vps = list(self._by_vp.keys())

    def candidates_for_target(self, target: str) -> List[Tuple[CveRecord, CpeMatch]]:
        """Return (CVE, CpeMatch) pairs for an exact or prefix CPE target."""
        if target.endswith("*"):
            prefix = target[:-1]
            out: List[Tuple[CveRecord, CpeMatch]] = []
            for vp in self._vps:
                if vp.startswith(prefix):
                    out.extend(self._by_vp[vp])
            return out
        return self._by_vp.get(target, [])


def match_assets(
    records: List[CveRecord],
    assets: List[NormalisationResult],
) -> List[AssetMatch]:
    """Return the de-duplicated set of CVEs relevant to the recognised assets.

    Each result aggregates every asset and CPE that mapped to it, so the same
    CVE is reported once even when it affects several items in the asset list.
    """
    index = CveIndex(records)
    by_cve: Dict[str, AssetMatch] = {}

    for asset in assets:
        if not asset.recognised:
            continue
        for target in asset.cpe_targets:
            for rec, m in index.candidates_for_target(target):
                compatible, refined = version_is_compatible(asset.raw_version, m)
                if not compatible:
                    continue
                entry = by_cve.get(rec.cve_id)
                if entry is None:
                    entry = AssetMatch(cve=rec)
                    by_cve[rec.cve_id] = entry
                if asset not in entry.matched_assets:
                    entry.matched_assets.append(asset)
                if m.vendor_product not in entry.matched_cpes:
                    entry.matched_cpes.append(m.vendor_product)
                entry.version_refined = entry.version_refined or refined

    return list(by_cve.values())
