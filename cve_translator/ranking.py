"""Rank matched CVEs by real-world urgency, and score data confidence.

The ordering rule from the brief is: sort by EPSS descending, with KEV entries
promoted to the top. We implement that with a single combined urgency score so
the result is one clean, explainable number using a transparent weighted-scoring
approach.

    urgency = WEIGHT_EPSS * epss
            + WEIGHT_CVSS * (cvss / 10)
            + KEV_BOOST            (if the CVE is in the CISA KEV catalogue)
            + RANSOMWARE_BOOST     (if KEV flags known ransomware use)

Alongside urgency we compute two intelligence-platform style signals:

  * status     "Confirmed" when CISA KEV records active exploitation in the
               wild, otherwise "Unconfirmed" (exploitation is predicted by EPSS
               but not yet observed at scale).
  * confidence a 0 to 100 data-confidence score reflecting how complete and
               authoritative the record is (NVD analysis status, presence of
               CVSS, CWE, references, and CPE applicability data).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from . import config
from .matcher import AssetMatch

# NVD vulnerability status to a base data-confidence contribution.
_STATUS_CONFIDENCE = {
    "Analyzed": 45,
    "Modified": 40,
    "Deferred": 30,
    "Undergoing Analysis": 20,
    "Awaiting Analysis": 12,
    "Received": 10,
    "Rejected": 0,
}


@dataclass
class RankedCve:
    """A matched CVE enriched with EPSS, KEV, confidence, and urgency."""

    cve_id: str
    asset_display: str
    asset_raw: str
    matched_cpes: List[str]
    description: str
    cvss_score: Optional[float]
    cvss_severity: str
    cvss_vector: str
    cvss_version: str
    epss: Optional[float]
    epss_percentile: Optional[float]
    in_kev: bool
    kev_ransomware: bool
    kev_date_added: str
    kev_short_desc: str
    kev_vuln_name: str
    kev_vendor_project: str
    kev_product: str
    kev_required_action: str
    kev_due_date: str
    urgency: float
    confidence: int
    version_refined: bool
    vuln_status: str
    cwes: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    published: str = ""
    last_modified: str = ""

    @property
    def status(self) -> str:
        return "Confirmed" if self.in_kev else "Unconfirmed"

    @property
    def epss_display(self) -> str:
        return f"{self.epss:.4f}" if self.epss is not None else "n/a"

    @property
    def cvss_display(self) -> str:
        return f"{self.cvss_score:.1f}" if self.cvss_score is not None else "n/a"

    @property
    def severity_band(self) -> str:
        score = self.cvss_score
        if score is None:
            return "UNRATED"
        if score >= config.CVSS_CRITICAL:
            return "CRITICAL"
        if score >= config.CVSS_HIGH:
            return "HIGH"
        if score >= config.CVSS_MEDIUM:
            return "MEDIUM"
        return "LOW"

    @property
    def confidence_band(self) -> str:
        if self.confidence >= 75:
            return "High"
        if self.confidence >= 50:
            return "Medium"
        return "Low"

    @property
    def kev_display(self) -> str:
        if not self.in_kev:
            return "No"
        return "Yes (ransomware)" if self.kev_ransomware else "Yes"


def _scale_cvss(score: Optional[float]) -> float:
    return (score or 0.0) / 10.0


def compute_urgency(
    epss: Optional[float],
    cvss: Optional[float],
    in_kev: bool,
    ransomware: bool,
) -> float:
    base = (
        config.WEIGHT_EPSS * (epss or 0.0)
        + config.WEIGHT_CVSS * _scale_cvss(cvss)
    )
    boost = 0.0
    if in_kev:
        boost += config.KEV_BOOST
        if ransomware:
            boost += config.RANSOMWARE_BOOST
    return round(base + boost, 6)


def compute_confidence(
    vuln_status: str,
    has_cvss: bool,
    has_epss: bool,
    cwes: List[str],
    references: List[str],
    in_kev: bool,
) -> int:
    """Score how complete and authoritative a record is, from 0 to 100."""
    score = _STATUS_CONFIDENCE.get(vuln_status, 15)
    if has_cvss:
        score += 18
    if has_epss:
        score += 10
    if cwes:
        score += 10
    if references:
        score += 7
    if in_kev:
        score += 10          # corroborated by an independent CISA source
    return max(0, min(100, score))


def rank_matches(
    matches: List[AssetMatch],
    epss_map: Dict[str, dict],
    kev_ids: Set[str],
    kev_detail: Dict[str, dict],
) -> List[RankedCve]:
    """Enrich every match with EPSS, KEV, and confidence, then sort by urgency."""
    ranked: List[RankedCve] = []
    for match in matches:
        cve = match.cve
        epss_entry = epss_map.get(cve.cve_id, {})
        epss = epss_entry.get("epss")
        percentile = epss_entry.get("percentile")

        in_kev = cve.cve_id in kev_ids
        detail = kev_detail.get(cve.cve_id, {})
        ransomware = bool(detail.get("ransomware"))

        ranked.append(
            RankedCve(
                cve_id=cve.cve_id,
                asset_display=match.asset_display,
                asset_raw=match.asset_raw,
                matched_cpes=match.matched_cpes,
                description=cve.description,
                cvss_score=cve.cvss_score,
                cvss_severity=cve.cvss_severity,
                cvss_vector=cve.cvss_vector,
                cvss_version=cve.cvss_version,
                epss=epss,
                epss_percentile=percentile,
                in_kev=in_kev,
                kev_ransomware=ransomware,
                kev_date_added=detail.get("dateAdded", ""),
                kev_short_desc=detail.get("shortDescription", ""),
                kev_vuln_name=detail.get("vulnerabilityName", ""),
                kev_vendor_project=detail.get("vendorProject", ""),
                kev_product=detail.get("product", ""),
                kev_required_action=detail.get("requiredAction", ""),
                kev_due_date=detail.get("dueDate", ""),
                urgency=compute_urgency(epss, cve.cvss_score, in_kev, ransomware),
                confidence=compute_confidence(
                    cve.vuln_status, cve.cvss_score is not None,
                    epss is not None, cve.cwes, cve.references, in_kev,
                ),
                version_refined=match.version_refined,
                vuln_status=cve.vuln_status,
                cwes=cve.cwes,
                references=cve.references,
                published=cve.published,
                last_modified=cve.last_modified,
            )
        )

    # Primary sort by urgency, then EPSS, then CVSS, then CVE id for stability.
    ranked.sort(
        key=lambda r: (
            r.urgency,
            r.epss or 0.0,
            r.cvss_score or 0.0,
            r.cve_id,
        ),
        reverse=True,
    )
    return ranked
