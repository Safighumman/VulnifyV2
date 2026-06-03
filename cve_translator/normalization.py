"""Normalisation: map a messy, user-supplied product name to a canonical CPE.

The design philosophy is to take inconsistent, human-entered input and resolve
it to a canonical, machine-usable identity, then be honest about confidence.

The flow is:

  1. Clean the raw string (strip edition words, version numbers, punctuation).
  2. Try a direct alias hit on the catalogue (fast path, full confidence).
  3. Fall back to rapidfuzz fuzzy matching against every alias.
  4. Accept the best match only if it clears the configured score cutoff,
     otherwise report the asset as unrecognised so it is never silently lost.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from rapidfuzz import fuzz, process

from . import config
from .cpe_catalog import Product, alias_index

# Words that describe an edition or packaging but not the product identity.
# Removing them improves matching ("Windows 10 Pro" -> "windows 10").
_EDITION_NOISE = {
    "pro", "professional", "home", "enterprise", "business", "standard",
    "edition", "for", "the", "x64", "x86", "64-bit", "32-bit", "bit",
    "lts", "ltsc", "community", "server", "desktop", "client", "suite",
}

# Pre-built once at import time. List of (alias, Product).
_ALIAS_INDEX = alias_index()
_ALIASES = [alias for alias, _ in _ALIAS_INDEX]


@dataclass
class NormalisationResult:
    """Outcome of normalising one raw asset name."""

    raw_name: str
    raw_version: str
    product: Optional[Product]
    score: float
    matched_alias: str = ""

    @property
    def recognised(self) -> bool:
        return self.product is not None

    @property
    def cpe_targets(self) -> List[str]:
        return list(self.product.cpe) if self.product else []

    @property
    def display_name(self) -> str:
        return self.product.name if self.product else self.raw_name


def _clean(name: str) -> str:
    """Lower-case, strip punctuation, and drop edition and version noise."""
    text = name.lower().strip()
    # Drop anything that looks like a version token (1.2.3, 22h2, 2024.001, v3).
    text = re.sub(r"\bv?\d[\w.\-]*\b", " ", text)
    # Replace separators with spaces.
    text = re.sub(r"[._/\\()+,]", " ", text)
    tokens = [t for t in text.split() if t and t not in _EDITION_NOISE]
    cleaned = " ".join(tokens).strip()
    # If we stripped everything (e.g. the name was only edition words), fall
    # back to the lightly cleaned original so fuzzy matching still has input.
    return cleaned or re.sub(r"[._/\\()+,]", " ", name.lower()).strip()


def normalise_name(raw_name: str, raw_version: str = "") -> NormalisationResult:
    """Resolve one raw product name to a catalogue product (or None)."""
    cleaned = _clean(raw_name)

    # Fast path: exact alias hit on either the cleaned or the raw lowercase.
    raw_lower = raw_name.strip().lower()
    for candidate in (cleaned, raw_lower):
        for alias, product in _ALIAS_INDEX:
            if alias == candidate:
                return NormalisationResult(
                    raw_name=raw_name, raw_version=raw_version,
                    product=product, score=100.0, matched_alias=alias,
                )

    # Fuzzy path: token_set_ratio handles word re-ordering and extra words
    # such as "for Business" gracefully.
    match = process.extractOne(
        cleaned, _ALIASES, scorer=fuzz.token_set_ratio,
    )
    if match is None:
        return NormalisationResult(raw_name, raw_version, None, 0.0)

    alias, score, idx = match
    if score < config.FUZZY_SCORE_CUTOFF:
        return NormalisationResult(raw_name, raw_version, None, float(score))

    product = _ALIAS_INDEX[idx][1]
    return NormalisationResult(
        raw_name=raw_name, raw_version=raw_version,
        product=product, score=float(score), matched_alias=alias,
    )


def normalise_assets(assets: List[tuple[str, str]]) -> List[NormalisationResult]:
    """Normalise a list of (name, version) asset tuples."""
    return [normalise_name(name, version) for name, version in assets]
