"""Live ingestion engine: constant, background import of the brief's feeds.

This is what turns the platform from a static page into a live one. A daemon
thread polls the enabled connectors on their own cadences, fetching fresh data
from the sources named in the project brief (reached through their maintained
GitHub mirrors so they work behind strict outbound allow-lists). Each cycle:

  * downloads the source into ``data/feeds/`` (atomically),
  * diffs it against the previous snapshot,
  * emits live events for what changed (new CISA KEV entries are *confirmed*
    exploitation; rising EPSS scores and freshly published CVEs are
    *unconfirmed* signals), and
  * hot-swaps the pipeline's cached corpus so analysis reflects the new data.

If the network is unavailable the feed degrades to an ``offline`` status and the
platform keeps serving the bundled real subset, then upgrades itself the moment
connectivity returns. Subscribers (the dashboard's SSE stream) receive every
event and feed-status change in real time.
"""

from __future__ import annotations

import json
import queue
import shutil
import threading
import time
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
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
                self._feeds[c["id"]] = FeedHealth(
                    key=c["id"], name=c["name"], provider=c.get("provider", ""),
                    category=c.get("category", ""), fmt=c.get("format", ""),
                    enabled=c.get("enabled", True),
                    status="idle" if c.get("enabled", True) else "disabled",
                    records=data.counts.get(c["id"], 0),
                    source="bundled",
                    message=("Bundled snapshot loaded; awaiting live sync"
                             if c.get("enabled", True) else "Disabled"),
                )
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
        """Force an immediate sync of one feed (or all enabled) in the background."""
        keys = [feed_key] if feed_key else [c["id"] for c in connectors.enabled_connectors()]
        threading.Thread(target=lambda: [self._sync_feed(k) for k in keys],
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

    def _sync_feed(self, key: str) -> None:
        conn = connectors.get_connector(key)
        if conn is None or not conn.get("enabled", True):
            return
        handler = {"kev": self._sync_kev, "epss": self._sync_epss,
                   "nvd": self._sync_nvd}.get(conn.get("kind", key))
        if handler is None:
            self._sync_custom(conn)
            return
        self._set_status(key, "syncing", message="Fetching from live source")
        t0 = time.perf_counter()
        try:
            handler(conn)
            self._online = True
        except Exception as exc:  # noqa: BLE001 - degrade, never crash
            self._set_status(key, "offline", source="bundled",
                             message=f"Offline, serving bundled data ({type(exc).__name__})")
            return
        dur = time.perf_counter() - t0
        with self._lock:
            fh = self._feeds.get(key)
            if fh:
                fh.duration_s = dur
                fh.last_run = _now_iso()
                fh.speed = int(fh.records / dur) if dur > 0 else fh.records
            self._last_sync = _now_iso()

    @staticmethod
    def _file_fresh(path: Path, max_age_s: float) -> bool:
        if not path.exists():
            return False
        return (time.time() - path.stat().st_mtime) < max(60.0, float(max_age_s))

    # Per-source sync handlers
    def _download(self, url: str, dest: Path, auth_header: str = "") -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        headers = {"User-Agent": "vulnify/3.0 (+live-ingest)"}
        if auth_header and ":" in auth_header:
            name, _, value = auth_header.partition(":")
            headers[name.strip()] = value.strip()
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=config.LIVE_HTTP_TIMEOUT) as resp, \
                open(tmp, "wb") as fh:
            shutil.copyfileobj(resp, fh)
        tmp.replace(dest)

    def _sync_kev(self, conn: dict) -> None:
        dest = config.FEEDS_DIR / "known_exploited_vulnerabilities.json"
        self._download(conn["url"], dest, conn.get("auth_header", ""))
        kev_ids, kev_detail = data_loader.load_kev_set()
        with self._lock:
            new_ids = kev_ids - self._prev_kev_ids
            self._prev_kev_ids = set(kev_ids)
        self._update_cache(kev_ids=kev_ids, kev_detail=kev_detail)
        data = pipeline.current_data()
        recs = {r.cve_id: r for r in data.records} if data else {}
        # Emit newest first; cap the burst so the stream stays readable.
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
        self._set_status("kev", "live", source="live", new=len(new_ids),
                         records=len(kev_ids),
                         message=(f"{len(new_ids)} new confirmed-exploited CVE(s)"
                                  if new_ids else "Up to date, no new entries"))

    def _sync_epss(self, conn: dict) -> None:
        dest = None
        last_err: Optional[Exception] = None
        # Today's file may not be posted yet; walk back a few days.
        for back in range(0, 4):
            day = (date.today() - timedelta(days=back)).isoformat()
            url = conn["url"].format(year=day[:4], date=day)
            target = config.FEEDS_DIR / f"epss_scores-{day}.csv.gz"
            try:
                self._download(url, target, conn.get("auth_header", ""))
                dest = target
                break
            except Exception as exc:  # noqa: BLE001
                last_err = exc
        if dest is None:
            raise last_err or RuntimeError("No EPSS file available")
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
        self._set_status("epss", "live", source="live", new=len(risers),
                         records=len(epss_map),
                         message=(f"{len(risers)} CVE(s) with rising exploitation odds"
                                  if risers else "Up to date"))

    def _sync_nvd(self, conn: dict) -> None:
        years = config.env_year_list()
        # The full NVD corpus is hundreds of MB. Skip the download when the
        # per-year files already exist and are newer than the sync interval, so
        # restarts reuse the cached feeds instead of re-pulling every time.
        fresh = all(self._file_fresh(config.FEEDS_DIR / f"CVE-{year}.json",
                                     conn.get("interval", config.LIVE_INTERVAL_NVD))
                    for year in years)
        if not fresh:
            for year in years:
                xz = config.FEEDS_DIR / f"CVE-{year}.json.xz"
                self._download(conn["url"].format(year=year), xz)
                import lzma
                out = config.FEEDS_DIR / f"CVE-{year}.json"
                with lzma.open(xz, "rb") as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                xz.unlink(missing_ok=True)
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
        self._set_status("nvd", "live", source="live", new=len(new_ids),
                         records=len(records),
                         message=(f"{len(new_ids)} newly published CVE(s)"
                                  if new_ids else "Corpus current"))

    def _sync_custom(self, conn: dict) -> None:
        """Best-effort fetch of a user connector: validate it returns data."""
        key = conn["id"]
        self._set_status(key, "syncing", message="Fetching custom source")
        try:
            dest = config.FEEDS_DIR / f"custom_{key}.dat"
            self._download(conn["url"], dest, conn.get("auth_header", ""))
            size = dest.stat().st_size
            self._set_status(key, "live", source="live", records=size,
                             message=f"Reachable, {size:,} bytes fetched")
            self._emit(self._make_event(
                etype="connector", cve_id=conn["name"], status="Unconfirmed",
                title=f"Custom connector '{conn['name']}' returned {size:,} bytes",
                severity="", epss=None, vendor=conn.get("provider", ""),
                product="", source="custom", ts=_now_iso()))
        except Exception as exc:  # noqa: BLE001
            self._set_status(key, "error", message=f"Unreachable: {type(exc).__name__}")

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
            if status in ("live", "offline", "error"):
                fh.last_run = _now_iso()
        self._broadcast_state()


# Module-level singleton.
engine = LiveEngine()
