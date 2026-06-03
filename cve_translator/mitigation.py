"""Risk mitigation guidance for vulnerabilities, feeds, and zero-days.

The brief asks for plain-English risk summaries; this module adds the matching
"what to do about it" layer that the dashboard surfaces on hover and in the
detail drawer:

  * Per-CVE mitigation: a prioritised set of concrete remediation steps derived
    from the strongest signal available (CISA KEV due dates first, then the CWE
    weakness class, then severity and EPSS), plus links to official
    documentation for that specific vulnerability.
  * Per-feed mitigation: how an analyst should act on each intelligence source.
  * Zero-day detection: when a CVE was added to CISA KEV at or before its public
    documentation caught up, it was very likely exploited as a zero-day. We
    surface the official vulnerability name (from the KEV catalogue) and all the
    available detail rather than inventing a nickname.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .ranking import RankedCve

# Concrete, weakness-specific mitigations keyed by CWE. Each is phrased so a
# non-specialist administrator can act on it. The vendor patch is always the
# first-line action; these add the defence-in-depth context an analyst expects.
_CWE_MITIGATION: Dict[str, List[str]] = {
    "CWE-79": ["Apply the vendor patch, then enforce output encoding and a strict Content-Security-Policy.",
               "Validate and sanitise all user-supplied input on the server side."],
    "CWE-89": ["Apply the vendor patch and convert dynamic SQL to parameterised queries or an ORM.",
               "Apply least-privilege to the database account the application uses."],
    "CWE-20": ["Apply the vendor patch and add strict server-side input validation (allow-lists, not block-lists)."],
    "CWE-22": ["Apply the vendor patch and canonicalise then validate every file path against an allow-list.",
               "Run the service as a low-privilege account confined to its intended directory."],
    "CWE-78": ["Apply the vendor patch and avoid shelling out; use safe APIs and strict argument allow-lists."],
    "CWE-77": ["Apply the vendor patch and remove command construction from untrusted input."],
    "CWE-119": ["Apply the vendor patch; enable OS memory protections (ASLR, DEP) and restrict exposure.",
                "Where exposed to the network, place the service behind a filtering proxy until patched."],
    "CWE-125": ["Apply the vendor patch; this is a memory-safety flaw with no reliable configuration workaround."],
    "CWE-787": ["Apply the vendor patch immediately; out-of-bounds writes are commonly weaponised for code execution."],
    "CWE-416": ["Apply the vendor patch; use-after-free flaws are a leading driver of in-the-wild exploitation."],
    "CWE-476": ["Apply the vendor patch; restrict untrusted input that can reach the affected code path."],
    "CWE-190": ["Apply the vendor patch and validate size and length fields on all untrusted input."],
    "CWE-200": ["Apply the vendor patch and review what data the affected component exposes; tighten access controls."],
    "CWE-269": ["Apply the vendor patch and audit privileged accounts and role assignments for over-provisioning."],
    "CWE-287": ["Apply the vendor patch, enforce multi-factor authentication, and rotate any exposed credentials."],
    "CWE-306": ["Apply the vendor patch and require authentication on every sensitive endpoint; never expose admin interfaces."],
    "CWE-862": ["Apply the vendor patch and add server-side authorisation checks on every object and action."],
    "CWE-863": ["Apply the vendor patch and verify authorisation logic against a least-privilege model."],
    "CWE-284": ["Apply the vendor patch and review network and application access controls around the component."],
    "CWE-94": ["Apply the vendor patch urgently; code-injection flaws typically allow full compromise."],
    "CWE-352": ["Apply the vendor patch and enforce anti-CSRF tokens and SameSite cookies."],
    "CWE-362": ["Apply the vendor patch; race conditions rarely have a safe configuration workaround."],
    "CWE-400": ["Apply the vendor patch and add rate limiting and resource quotas in front of the service."],
    "CWE-770": ["Apply the vendor patch and impose allocation limits and quotas."],
    "CWE-434": ["Apply the vendor patch, validate upload type and content, and store uploads outside the web root."],
    "CWE-502": ["Apply the vendor patch and never deserialise untrusted data; use a safe data format."],
    "CWE-918": ["Apply the vendor patch and restrict outbound requests with an egress allow-list."],
    "CWE-798": ["Apply the vendor patch and rotate the affected credentials immediately; move secrets to a vault."],
    "CWE-732": ["Apply the vendor patch and correct file and resource permissions to least privilege."],
    "CWE-59": ["Apply the vendor patch and restrict the service account's ability to follow links."],
    "CWE-1333": ["Apply the vendor patch and add input-length limits in front of the affected parser."],
}


def _doc_links(r: RankedCve) -> List[dict]:
    """Official documentation links for a specific vulnerability."""
    cve = r.cve_id
    links: List[dict] = [
        {"label": "NVD detail", "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
         "kind": "primary"},
        {"label": "MITRE CVE record",
         "url": f"https://www.cve.org/CVERecord?id={cve}", "kind": "primary"},
    ]
    if r.in_kev:
        links.append({"label": "CISA KEV catalogue",
                      "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                      "kind": "confirmed"})
    for c in r.cwes:
        num = c.replace("CWE-", "").strip()
        if num.isdigit():
            links.append({"label": f"{c} weakness",
                          "url": f"https://cwe.mitre.org/data/definitions/{num}.html",
                          "kind": "weakness"})
    # A vendor advisory, if one is present in the reference set.
    vendor_ref = _first_vendor_ref(r.references)
    if vendor_ref:
        links.append({"label": "Vendor advisory", "url": vendor_ref,
                      "kind": "vendor"})
    return links


_VENDOR_HINTS = ("msrc.microsoft", "support.microsoft", "helpx.adobe",
                 "tools.cisco", "sec.cloudapps.cisco", "security.apache",
                 "chromereleases", "mozilla.org/security", "fortiguard",
                 "vmware.com/security", "oracle.com/security", "github.com")


def _first_vendor_ref(references: List[str]) -> Optional[str]:
    for url in references or []:
        low = url.lower()
        if any(h in low for h in _VENDOR_HINTS):
            return url
    return None


def is_zero_day(r: RankedCve) -> bool:
    """Heuristic: confirmed-exploited at or before public enrichment caught up.

    A CVE that appears in CISA KEV within a short window of its publication was
    almost certainly exploited in the wild as a zero-day. We stay conservative
    and only flag KEV entries, where exploitation is confirmed rather than
    predicted.
    """
    if not r.in_kev or not r.kev_date_added or not r.published:
        return False
    added = (r.kev_date_added or "")[:10]
    published = (r.published or "")[:10]
    if not (added and published):
        return False
    # KEV-listed on the same day as, or before, NVD publication -> zero-day-like.
    return added <= published or _within_days(published, added, 21)


def _within_days(a: str, b: str, days: int) -> bool:
    from datetime import date
    try:
        da = date.fromisoformat(a)
        db = date.fromisoformat(b)
    except ValueError:
        return False
    return abs((db - da).days) <= days


def mitigation_for(r: RankedCve) -> dict:
    """Build the structured risk-mitigation block for one ranked CVE."""
    steps: List[str] = []

    # 1. Urgency framing from the strongest signal.
    if r.in_kev and r.kev_ransomware:
        steps.append("PATCH NOW: actively exploited in ransomware campaigns (CISA KEV). "
                     "Treat as an active incident risk.")
    elif r.in_kev:
        steps.append("PATCH NOW: confirmed exploited in the wild (CISA KEV). "
                     "Prioritise above all unconfirmed items.")
    elif (r.epss or 0.0) >= 0.5:
        steps.append("Patch urgently: EPSS puts exploitation probability above 50% in the next 30 days.")
    elif (r.epss or 0.0) >= 0.1:
        steps.append("Schedule a patch soon: moderate exploitation probability.")
    else:
        steps.append("Patch during routine maintenance: low immediate exploitation risk today.")

    # 2. KEV required action / due date, verbatim where available.
    if r.kev_required_action:
        steps.append(f"CISA required action: {r.kev_required_action}")
    if r.kev_due_date:
        steps.append(f"Federal remediation due by {r.kev_due_date} (a useful target date for any organisation).")

    # 3. Weakness-specific, concrete mitigation.
    added = set()
    for c in r.cwes:
        for tip in _CWE_MITIGATION.get(c, []):
            if tip not in added:
                steps.append(tip)
                added.add(tip)
    if not added:
        steps.append("Apply the latest vendor update for the affected product and version.")

    # 4. Always-on hygiene closer.
    steps.append("Confirm the fix by re-scanning the asset, and record the version you patched to.")

    summary = _mitigation_summary(r)
    return {
        "summary": summary,
        "steps": steps,
        "doc_links": _doc_links(r),
        "priority": _priority(r),
    }


def _priority(r: RankedCve) -> str:
    if r.in_kev:
        return "Immediate"
    if (r.epss or 0.0) >= 0.5 or (r.cvss_score or 0) >= 9.0:
        return "Urgent"
    if (r.epss or 0.0) >= 0.1 or (r.cvss_score or 0) >= 7.0:
        return "Scheduled"
    return "Routine"


def _mitigation_summary(r: RankedCve) -> str:
    product = r.asset_display or "the affected product"
    if r.in_kev:
        return (f"Update {product} to the fixed release immediately; this CVE is on the "
                f"CISA Known Exploited Vulnerabilities list and is being used in real attacks.")
    if (r.epss or 0.0) >= 0.5:
        return (f"Update {product} as a priority; exploitation is forecast as highly likely "
                f"within 30 days even though it is not yet confirmed in the wild.")
    return (f"Update {product} on your normal patch cycle and keep monitoring; "
            f"exploitation has not been observed at scale.")


def zero_day_details(r: RankedCve) -> Optional[dict]:
    """Official name and all available detail when a CVE is zero-day-like."""
    if not is_zero_day(r):
        return None
    return {
        "official_name": r.kev_vuln_name or r.cve_id,
        "vendor": r.kev_vendor_project,
        "product": r.kev_product,
        "added_to_kev": r.kev_date_added,
        "published": (r.published or "")[:10],
        "ransomware": r.kev_ransomware,
        "summary": r.kev_short_desc,
        "note": ("Listed by CISA as exploited at or near disclosure, consistent with "
                 "zero-day exploitation. The official identifier and CISA's recorded "
                 "details are shown rather than any informal nickname."),
    }


# Per-feed mitigation guidance: how to act on each intelligence source.
FEED_MITIGATION: Dict[str, dict] = {
    "nvd": {
        "summary": "Use NVD as the authoritative system of record for what a CVE is and which versions it affects.",
        "action": "Confirm the affected version range against your real inventory before patching to avoid wasted effort.",
    },
    "kev": {
        "summary": "Treat every CISA KEV entry that matches your stack as a patch-now item; exploitation is confirmed.",
        "action": "Patch KEV matches ahead of all other work and meet (or beat) the CISA due date.",
    },
    "epss": {
        "summary": "Use EPSS to triage the long tail: a rising score is an early warning before KEV confirmation.",
        "action": "Re-prioritise weekly. Promote anything crossing 0.5 EPSS into your urgent queue.",
    },
}


def feed_mitigation(key: str) -> dict:
    return FEED_MITIGATION.get(key, {
        "summary": "Correlate this source with your asset inventory.",
        "action": "Review new entries on each ingest cycle.",
    })
