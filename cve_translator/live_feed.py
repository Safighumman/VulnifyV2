"""Offline ingestion engine for the pre-downloaded feeds named in the brief.

The project brief is strict: no external vulnerability-data APIs may be called
at run time. All data must come from the pre-downloaded local files. This engine
honours that. A daemon thread watches the local feed files (``data/feeds/`` when
a facilitator has staged them, otherwise the bundled real subset) and, whenever a
file changes, re-ingests it:

  * diffs it against the previous snapshot,
  * emits events for what changed (new CISA KEV entries are *confirmed*
    exploitation; rising EPSS scores and newly seen CVEs are *unconfirmed*
    signals), and
  * hot-swaps the pipeline's cached corpus so analysis reflects the new data.

Only the brief's feeds are used: NVD CVE (Fraunhofer FKIE reconstruction), the
CISA KEV catalogue, and EPSS. No network is ever touched here; the one-off
download of those files is the facilitator's pre-event step in
``scripts/fetch_data.py``. Subscribers (the dashboard's SSE stream) receive every
event and feed-status change in real time.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from . import config, connectors, data_loader, pipeline
from .sectors import get_sector


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Coarse vendor -> sector guess, just for colouring the live stream. The
# asset-driven Sectors view is the authoritative sector breakdown.
_VENDOR_SECTOR = {
    "moodle": "education", "wordpress": "technology", "apache": "technology",
    "nginx": "technology", "f5": "technology", "oracle": "technology",
    "postgresql": "technology", "php": "technology", "nodejs": "technology",
    "cisco": "technology", "fortinet": "technology", "vmware": "technology",
}


@dataclass
class FeedHealth:
    key: str
    name: str
    provider: str
    category: str
    fmt: str
    status: str = "idle"           # idle|syncing|live|offline|error|disabled
    source: str = "bundled"        # bundled|live
    records: int = 0
    new_since_last: int = 0
    duration_s: float = 0.0
    speed: int = 0
    last_run: str = ""
    next_run: str = ""
    message: str = "Awaiting first sync"
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "key": self.key, "name": self.name, "provider": self.provider,
            "category": self.category, "format": self.fmt,
            "status": self.status, "source": self.source,
            "records": self.records, "new_since_last": self.new_since_last,
            "duration_s": round(self.duration_s, 3), "speed": self.speed,
            "last_run": self.last_run, "next_run": self.next_run,
            "message": self.message, "enabled": self.enabled,
        }


class LiveEngine:
    """Singleton background ingestion engine."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: deque = deque(maxlen=config.LIVE_EVENT_BUFFER)
        self._subscribers: List["queue.Queue"] = []
        self._feeds: Dict[str, FeedHealth] = {}
        self._next_due: Dict[str, float] = {}
        self._prev_kev_ids: set = set()
        self._prev_cve_ids: set = set()
        self._prev_epss: Dict[str, float] = {}
        self._data_version = 0
        self._online = False
        self._live_enabled = config.LIVE_ENABLED_DEFAULT
        self._started = False
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._last_sync = ""
        self._sig: Dict[str, str] = {}        # local-file signatures per feed

    # Lifecycle
    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
        self._bootstrap_from_cache()
        if self._live_enabled:
            self._thread = threading.Thread(
                target=self._run_loop, name="vulnify-live", daemon=True)
            self._thread.start()

    def _bootstrap_from_cache(self) -> None:
        """Load whatever data is available now (bundled or feeds) and seed events."""
        data = pipeline.load_data()
        with self._lock:
            self._prev_kev_ids = set(data.kev_ids)
            self._prev_cve_ids = {r.cve_id for r in data.records}
            self._prev_epss = {k: v["epss"] for k, v in data.epss_map.items()}
            for c in connectors.list_connectors():
                enabled = c.get("enabled", True)
                loaded = enabled and c["id"] in data.counts
                self._feeds[c["id"]] = FeedHealth(
                    key=c["id"], name=c["name"], provider=c.get("provider", ""),
                    category=c.get("category", ""), fmt=c.get("format", ""),
                    enabled=enabled,
                    status="loaded" if loaded else ("disabled" if not enabled else "idle"),
                    records=data.counts.get(c["id"], 0),
                    source="local",
                    last_run=_now_iso() if loaded else "",
                    message=("Loaded from pre-downloaded feed files" if enabled
                             else "Disabled"),
                )
            self._online = any(v > 0 for v in data.counts.values())
            for key in ("kev", "epss", "nvd"):
                self._sig[key] = self._signature(key)
        self._seed_events(data)

    def _seed_events(self, data) -> None:
        """Populate the live stream from current data so it is never empty."""
        # Confirmed: most recently added KEV entries present in the corpus.
        recs = {r.cve_id: r for r in data.records}
        kev_sorted = sorted(
            data.kev_detail.items(),
            key=lambda kv: kv[1].get("dateAdded", ""), reverse=True)
        seeded: List[dict] = []
        for cid, det in kev_sorted[:24]:
            rec = recs.get(cid)
            seeded.append(self._make_event(
                etype="kev_added", cve_id=cid, status="Confirmed",
                title=det.get("vulnerabilityName") or (rec.description if rec else cid),
                severity=(rec.cvss_severity if rec else ""),
                epss=(data.epss_map.get(cid, {}) or {}).get("epss"),
                vendor=det.get("vendorProject", ""), product=det.get("product", ""),
                ransomware=det.get("ransomware", False),
                ts=self._kev_ts(det.get("dateAdded", "")), source="kev"))
        # Unconfirmed: highest-EPSS corpus CVEs not yet confirmed by KEV.
        non_kev = [r for r in data.records if r.cve_id not in data.kev_ids]
        non_kev.sort(key=lambda r: (data.epss_map.get(r.cve_id, {}) or {}).get("epss", 0.0),
                     reverse=True)
        for r in non_kev[:16]:
            epss = (data.epss_map.get(r.cve_id, {}) or {}).get("epss")
            seeded.append(self._make_event(
                etype="cve_high", cve_id=r.cve_id, status="Unconfirmed",
                title=r.description, severity=r.cvss_severity, epss=epss,
                vendor=(r.cpe_matches[0].vendor if r.cpe_matches else ""),
                product="", ts=self._pub_ts(r.published), source="epss"))
        # Interleave by timestamp, newest first.
        seeded.sort(key=lambda e: e["ts"], reverse=True)
        with self._lock:
            for e in reversed(seeded):     # keep newest at the right end
                self._events.append(e)

    # Event helpers
    def _make_event(self, etype: str, cve_id: str, status: str, title: str,
                    severity: str, epss, vendor: str, product: str,
                    ts: str, source: str, ransomware: bool = False) -> dict:
        sector_key = _VENDOR_SECTOR.get((vendor or "").lower(), "common")
        sec = get_sector(sector_key)
        return {
            "id": f"{cve_id}:{etype}:{ts}",
            "ts": ts or _now_iso(),
            "type": etype,
            "cve_id": cve_id,
            "status": status,
            "title": (title or cve_id)[:160],
            "severity": severity or "UNRATED",
            "epss": round(epss, 4) if isinstance(epss, (int, float)) else None,
            "vendor": vendor or "",
            "product": product or "",
            "ransomware": bool(ransomware),
            "sector": sector_key,
            "sector_name": sec.name if sec else "Cross-sector",
            "sector_color": sec.color if sec else "#8aa0c6",
            "source": source,
        }

    @staticmethod
    def _kev_ts(date_added: str) -> str:
        if not date_added:
            return _now_iso()
        return f"{date_added[:10]}T12:00:00+00:00"

    @staticmethod
    def _pub_ts(published: str) -> str:
        return published or _now_iso()

    def _emit(self, event: dict) -> None:
        with self._lock:
            self._events.append(event)
            subs = list(self._subscribers)
        self._push(subs, {"kind": "event", "event": event})

    def _push(self, subs: List["queue.Queue"], message: dict) -> None:
        for q in subs:
            try:
                q.put_nowait(message)
            except queue.Full:
                pass

    def _broadcast_state(self) -> None:
        with self._lock:
            subs = list(self._subscribers)
            snap = self._snapshot_locked()
        self._push(subs, {"kind": "state", "state": snap})

    # Subscriptions (SSE)
    def subscribe(self) -> "queue.Queue":
        q: "queue.Queue" = queue.Queue(maxsize=64)
        with self._lock:
            self._subscribers.append(q)
            snap = self._snapshot_locked()
        q.put_nowait({"kind": "state", "state": snap})
        return q

    def unsubscribe(self, q: "queue.Queue") -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    # Public snapshot
    def snapshot(self) -> dict:
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict:
        return {
            "live_enabled": self._live_enabled,
            "online": self._online,
            "mode": "offline",
            "data_version": self._data_version,
            "last_sync": self._last_sync,
            "server_time": _now_iso(),
            "feeds": [self._feeds[k].to_dict() for k in self._feeds],
            "events": list(self._events)[-80:][::-1],
            "counts": self._counts_locked(),
        }

    def _counts_locked(self) -> dict:
        confirmed = sum(1 for e in self._events if e["status"] == "Confirmed")
        return {
            "events": len(self._events),
            "confirmed": confirmed,
            "unconfirmed": len(self._events) - confirmed,
        }

    def recent_events(self, limit: int = 80) -> List[dict]:
        with self._lock:
            return list(self._events)[-limit:][::-1]

    def set_live(self, enabled: bool) -> None:
        with self._lock:
            self._live_enabled = enabled
        if enabled and (self._thread is None or not self._thread.is_alive()):
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run_loop, name="vulnify-live", daemon=True)
            self._thread.start()
        self._broadcast_state()

    def trigger(self, feed_key: Optional[str] = None) -> None:
        """Re-read one feed (or all enabled) from local files now, in the background."""
        keys = [feed_key] if feed_key else [c["id"] for c in connectors.enabled_connectors()]
        threading.Thread(target=lambda: [self._sync_feed(k, force=True) for k in keys],
                         daemon=True).start()

    # The background loop
    def _run_loop(self) -> None:
        # Stagger first runs so KEV (small, fast) lands before NVD (large).
        order = ["kev", "epss", "nvd"]
        with self._lock:
            now = time.monotonic()
            for i, k in enumerate(order):
                self._next_due[k] = now + i * 2
        while not self._stop.is_set():
            enabled = {c["id"]: c for c in connectors.enabled_connectors()}
            for key, conn in enabled.items():
                due = self._next_due.get(key, 0)
                if time.monotonic() >= due:
                    self._sync_feed(key)
                    interval = max(30, int(conn.get("interval", 900)))
                    with self._lock:
                        self._next_due[key] = time.monotonic() + interval
                        if key in self._feeds:
                            self._feeds[key].next_run = (
                                datetime.now(timezone.utc) + timedelta(seconds=interval)
                            ).isoformat(timespec="seconds")
            self._broadcast_state()
            self._stop.wait(5)

    def _sync_feed(self, key: str, force: bool = False) -> None:
        """Ingest one feed strictly from the local pre-downloaded files.

        No network is touched: data is read from ``data/feeds/`` when present,
        else from the bundled real subset. A feed is only re-read when its local
        file has changed since the last ingest (or when forced), so a facilitator
        dropping updated files mid-session is picked up without needless reloads.
        """
        conn = connectors.get_connector(key)
        if conn is None or not conn.get("enabled", True):
            return
        handler = {"kev": self._ingest_kev, "epss": self._ingest_epss,
                   "nvd": self._ingest_nvd}.get(conn.get("kind", key))
        if handler is None:
            self._ingest_custom(conn)
            return

        sig = self._signature(key)
        if not force and sig and self._sig.get(key) == sig:
            return                     # local files unchanged, nothing to ingest

        self._set_status(key, "scanning", message="Reading local feed files")
        t0 = time.perf_counter()
        try:
            handler(conn)
        except FileNotFoundError:
            self._set_status(key, "error", source="none",
                             message="No local feed file (run the facilitator pre-event prep)")
            return
        except Exception as exc:  # noqa: BLE001 - degrade, never crash
            self._set_status(key, "error", message=f"Ingest failed: {type(exc).__name__}")
            return
        dur = time.perf_counter() - t0
        with self._lock:
            self._sig[key] = sig
            self._online = True
            fh = self._feeds.get(key)
            if fh:
                fh.duration_s = dur
                fh.last_run = _now_iso()
                fh.speed = int(fh.records / dur) if dur > 0 else fh.records
            self._last_sync = _now_iso()

    # Local file resolution (feeds-first, bundled-fallback, mirroring data_loader)
    def _feed_paths(self, key: str) -> List[Path]:
        try:
            if key == "kev":
                p = config.FEEDS_DIR / "known_exploited_vulnerabilities.json"
                if p.exists():
                    return [p]
                return [config.BUNDLED_KEV] if config.BUNDLED_KEV.exists() else []
            if key == "epss":
                p = data_loader._resolve_epss_path()
                return [p] if p else []
            if key == "nvd":
                return data_loader._resolve_nvd_paths()
        except Exception:  # noqa: BLE001
            return []
        return []

    def _signature(self, key: str) -> str:
        """A change-signature of a feed's local files (path + mtime)."""
        parts = []
        for p in self._feed_paths(key):
            try:
                parts.append(f"{p}:{p.stat().st_mtime_ns}")
            except OSError:
                pass
        return "|".join(parts)

    # Per-source offline ingest handlers (read local files only)
    def _ingest_kev(self, conn: dict) -> None:
        kev_ids, kev_detail = data_loader.load_kev_set()
        with self._lock:
            new_ids = kev_ids - self._prev_kev_ids
            self._prev_kev_ids = set(kev_ids)
        self._update_cache(kev_ids=kev_ids, kev_detail=kev_detail)
        data = pipeline.current_data()
        recs = {r.cve_id: r for r in data.records} if data else {}
        for cid in sorted(new_ids,
                          key=lambda c: kev_detail.get(c, {}).get("dateAdded", ""),
                          reverse=True)[:30]:
            det = kev_detail.get(cid, {})
            rec = recs.get(cid)
            self._emit(self._make_event(
                etype="kev_added", cve_id=cid, status="Confirmed",
                title=det.get("vulnerabilityName") or (rec.description if rec else cid),
                severity=(rec.cvss_severity if rec else ""),
                epss=(data.epss_map.get(cid, {}) or {}).get("epss") if data else None,
                vendor=det.get("vendorProject", ""), product=det.get("product", ""),
                ransomware=det.get("ransomware", False), source="kev",
                ts=_now_iso()))
        self._set_status("kev", "loaded", source="local", new=len(new_ids),
                         records=len(kev_ids),
                         message=(f"{len(new_ids)} new confirmed-exploited CVE(s) in local file"
                                  if new_ids else "Loaded from local feed file"))

    def _ingest_epss(self, conn: dict) -> None:
        epss_map = data_loader.load_epss_map()
        risers: List[tuple] = []
        with self._lock:
            for cve, entry in epss_map.items():
                prev = self._prev_epss.get(cve)
                cur = entry["epss"]
                if (prev is None and cur >= 0.5) or (prev is not None and cur - prev >= 0.10):
                    risers.append((cve, cur, prev))
            self._prev_epss = {k: v["epss"] for k, v in epss_map.items()}
        self._update_cache(epss_map=epss_map)
        data = pipeline.current_data()
        recs = {r.cve_id: r for r in data.records} if data else {}
        kev = data.kev_ids if data else set()
        risers.sort(key=lambda x: x[1], reverse=True)
        for cve, cur, prev in risers[:20]:
            if cve in kev:
                continue
            rec = recs.get(cve)
            self._emit(self._make_event(
                etype="epss_rise", cve_id=cve, status="Unconfirmed",
                title=(rec.description if rec else f"{cve} exploitation forecast rising"),
                severity=(rec.cvss_severity if rec else ""), epss=cur,
                vendor=(rec.cpe_matches[0].vendor if rec and rec.cpe_matches else ""),
                product="", source="epss", ts=_now_iso()))
        self._set_status("epss", "loaded", source="local", new=len(risers),
                         records=len(epss_map),
                         message=(f"{len(risers)} CVE(s) with rising exploitation odds"
                                  if risers else "Loaded from local feed file"))

    def _ingest_nvd(self, conn: dict) -> None:
        records = data_loader.load_cve_records()
        with self._lock:
            cur_ids = {r.cve_id for r in records}
            new_ids = cur_ids - self._prev_cve_ids
            self._prev_cve_ids = cur_ids
        self._update_cache(records=records)
        data = pipeline.current_data()
        kev = data.kev_ids if data else set()
        new_recs = sorted((r for r in records if r.cve_id in new_ids),
                          key=lambda r: r.published, reverse=True)[:25]
        for rec in new_recs:
            in_kev = rec.cve_id in kev
            self._emit(self._make_event(
                etype="cve_new", cve_id=rec.cve_id,
                status="Confirmed" if in_kev else "Unconfirmed",
                title=rec.description, severity=rec.cvss_severity,
                epss=(data.epss_map.get(rec.cve_id, {}) or {}).get("epss") if data else None,
                vendor=(rec.cpe_matches[0].vendor if rec.cpe_matches else ""),
                product="", source="nvd", ts=_now_iso()))
        self._set_status("nvd", "loaded", source="local", new=len(new_ids),
                         records=len(records),
                         message=(f"{len(new_ids)} newly seen CVE(s) in local corpus"
                                  if new_ids else "Loaded from local feed file(s)"))

    def _ingest_custom(self, conn: dict) -> None:
        """Custom connectors are offline: read a local file path, never the network."""
        key = conn["id"]
        path = Path(conn.get("url", ""))
        if path.is_file():
            size = path.stat().st_size
            self._set_status(key, "loaded", source="local", records=size,
                             message=f"Local file read, {size:,} bytes")
        else:
            self._set_status(key, "idle", source="local",
                             message="Configured (offline). Point it at a local file path to ingest.")

    # Cache hot-swap
    def _update_cache(self, **parts) -> None:
        """Atomically replace the pipeline's cached corpus with updated feeds."""
        cur = pipeline.current_data()
        if cur is None:
            return
        records = parts.get("records", cur.records)
        kev_ids = parts.get("kev_ids", cur.kev_ids)
        kev_detail = parts.get("kev_detail", cur.kev_detail)
        epss_map = parts.get("epss_map", cur.epss_map)
        new = pipeline.LoadedData(
            records=records, kev_ids=kev_ids, kev_detail=kev_detail,
            epss_map=epss_map,
            counts={"nvd": len(records), "kev": len(kev_ids), "epss": len(epss_map)},
            timings=cur.timings,
        )
        pipeline.set_cache(new)
        with self._lock:
            self._data_version += 1

    def _set_status(self, key: str, status: str, source: Optional[str] = None,
                    records: Optional[int] = None, new: Optional[int] = None,
                    message: str = "") -> None:
        with self._lock:
            fh = self._feeds.get(key)
            if fh is None:
                return
            fh.status = status
            if source is not None:
                fh.source = source
            if records is not None:
                fh.records = records
            if new is not None:
                fh.new_since_last = new
            if message:
                fh.message = message
            if status in ("loaded", "offline", "error"):
                fh.last_run = _now_iso()
        self._broadcast_state()


# Module-level singleton.
engine = LiveEngine()
