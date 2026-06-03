"""Connector registry: the configurable feeds and APIs the platform ingests.

The dashboard's "Connectors & APIs" view lets a user see the built-in
intelligence sources and add their own (an internal CVE mirror, a commercial
feed, a custom JSON or CSV endpoint). Built-in connectors map to the brief's
named sources; user connectors are persisted to ``data/config/connectors.json``
so the configuration survives restarts.

This module is pure state management. The live ingestion engine reads the
enabled connectors to decide what to fetch; it never trusts a user connector to
do anything beyond fetch-and-parse, and a failing connector degrades to an
"error" status rather than taking the platform down.
"""

from __future__ import annotations

import json
import time
from typing import Dict, List, Optional

from . import config

# The built-in connectors correspond to the three brief-named feeds. They cannot
# be deleted, only enabled or disabled, and their URLs come from config so the
# offline/GitHub-mirror policy lives in one place.
BUILTIN: List[dict] = [
    {
        "id": "nvd",
        "name": "NVD CVE (Fraunhofer FKIE)",
        "provider": "NIST NVD via Fraunhofer FKIE reconstruction",
        "kind": "nvd",
        "format": "json.xz",
        "category": "Vulnerabilities",
        "url": config.LIVE_NVD_URL,
        "interval": config.LIVE_INTERVAL_NVD,
        "builtin": True,
        "enabled": True,
        "confidence": "Authoritative",
    },
    {
        "id": "kev",
        "name": "CISA KEV catalogue",
        "provider": "Cybersecurity and Infrastructure Security Agency",
        "kind": "kev",
        "format": "json",
        "category": "Confirmed exploitation",
        "url": config.LIVE_KEV_URL,
        "interval": config.LIVE_INTERVAL_KEV,
        "builtin": True,
        "enabled": True,
        "confidence": "Confirmed",
    },
    {
        "id": "epss",
        "name": "EPSS scores (FIRST.org)",
        "provider": "FIRST.org via empiricalsecurity",
        "kind": "epss",
        "format": "csv.gz",
        "category": "Exploitation forecast",
        "url": config.LIVE_EPSS_URL,
        "interval": config.LIVE_INTERVAL_EPSS,
        "builtin": True,
        "enabled": True,
        "confidence": "Predictive",
    },
]

_BUILTIN_IDS = {c["id"] for c in BUILTIN}


def _load_user() -> List[dict]:
    if not config.CONNECTORS_FILE.exists():
        return []
    try:
        data = json.loads(config.CONNECTORS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_user(items: List[dict]) -> None:
    config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config.CONNECTORS_FILE.write_text(
        json.dumps(items, indent=2), encoding="utf-8")


def _builtin_overrides() -> Dict[str, dict]:
    """Persisted enabled/interval overrides for the built-in connectors."""
    user = _load_user()
    return {c["id"]: c for c in user if c.get("id") in _BUILTIN_IDS}


def list_connectors() -> List[dict]:
    """All connectors: built-ins (with any saved overrides) plus user feeds."""
    overrides = _builtin_overrides()
    out: List[dict] = []
    for c in BUILTIN:
        merged = dict(c)
        ov = overrides.get(c["id"], {})
        if "enabled" in ov:
            merged["enabled"] = bool(ov["enabled"])
        if "interval" in ov:
            merged["interval"] = int(ov["interval"])
        out.append(merged)
    for c in _load_user():
        if c.get("id") in _BUILTIN_IDS:
            continue
        out.append(c)
    return out


def enabled_connectors() -> List[dict]:
    return [c for c in list_connectors() if c.get("enabled", True)]


def get_connector(cid: str) -> Optional[dict]:
    for c in list_connectors():
        if c["id"] == cid:
            return c
    return None


def add_connector(payload: dict) -> dict:
    """Add a user connector. Returns the stored record."""
    name = (payload.get("name") or "").strip()
    url = (payload.get("url") or "").strip()
    if not name or not url:
        raise ValueError("A connector needs at least a name and a URL.")
    cid = "user_" + str(int(time.time() * 1000))
    record = {
        "id": cid,
        "name": name,
        "provider": (payload.get("provider") or "Custom source").strip(),
        "kind": payload.get("kind", "custom"),
        "format": payload.get("format", "json"),
        "category": payload.get("category", "Custom intelligence"),
        "url": url,
        "interval": int(payload.get("interval") or 900),
        "auth_header": (payload.get("auth_header") or "").strip(),
        "builtin": False,
        "enabled": bool(payload.get("enabled", True)),
        "confidence": payload.get("confidence", "User-defined"),
    }
    items = [c for c in _load_user() if c.get("id") not in _BUILTIN_IDS]
    items.append(record)
    # Preserve built-in overrides alongside user connectors.
    items += list(_builtin_overrides().values())
    _save_user(items)
    return record


def update_connector(cid: str, changes: dict) -> Optional[dict]:
    """Update a connector. Built-ins accept only enabled/interval overrides."""
    if cid in _BUILTIN_IDS:
        overrides = _builtin_overrides()
        ov = overrides.get(cid, {"id": cid})
        if "enabled" in changes:
            ov["enabled"] = bool(changes["enabled"])
        if "interval" in changes:
            ov["interval"] = int(changes["interval"])
        overrides[cid] = ov
        users = [c for c in _load_user() if c.get("id") not in _BUILTIN_IDS]
        _save_user(users + list(overrides.values()))
        return get_connector(cid)

    users = _load_user()
    found = None
    for c in users:
        if c.get("id") == cid:
            allowed = ("name", "provider", "kind", "format", "category",
                       "url", "interval", "auth_header", "enabled", "confidence")
            for k in allowed:
                if k in changes:
                    c[k] = changes[k]
            found = c
    if found is not None:
        _save_user(users)
    return found


def remove_connector(cid: str) -> bool:
    """Delete a user connector (built-ins cannot be removed)."""
    if cid in _BUILTIN_IDS:
        return False
    users = _load_user()
    remaining = [c for c in users if c.get("id") != cid]
    if len(remaining) == len(users):
        return False
    _save_user(remaining)
    return True
