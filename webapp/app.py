"""Vulnify web platform: a live CVE intelligence dashboard.

A Flask application that wraps the same pipeline the CLI uses and presents it as
a categorised, SOC-style intelligence platform: an overview dashboard with risk
gauges and a sector heatmap, a live confirmed/unconfirmed feed, a stylised
threat map, a filterable vulnerability table with hover detail and a full drawer
(risk summary, mitigation, official documentation, zero-day treatment), a sector
view, an asset view, a configurable connectors/APIs view, and the normalisation
knowledge base.

Ingestion is live: a background engine polls the brief's sources (NVD via the
Fraunhofer FKIE GitHub mirror, the CISA KEV catalogue, and EPSS) and streams
new confirmed and unconfirmed activity to the dashboard over Server-Sent Events,
falling back to the bundled real subset whenever the network is unavailable.

Run:
    python webapp/app.py
    # then open http://127.0.0.1:5000
"""

from __future__ import annotations

import json
import queue
import sys
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cve_translator import config  # noqa: E402
from cve_translator import connectors as conn_mod  # noqa: E402
from cve_translator.cpe_catalog import CATALOG  # noqa: E402
from cve_translator.export import result_to_dict  # noqa: E402
from cve_translator.feeds import FEED_CATALOG  # noqa: E402
from cve_translator.live_feed import engine  # noqa: E402
from cve_translator.pipeline import load_data, run_pipeline  # noqa: E402
from cve_translator.sectors import all_sector_meta  # noqa: E402

app = Flask(__name__)

# A sensible cap on rows serialised to the browser. The dashboard aggregates
# always reflect the full result set; only the table is capped for rendering.
MAX_ROWS = 600

_DEFAULT_PREFS = {
    "theme": "emerald",
    "sectors": [],                 # empty means "all sectors"
    "widgets": {
        "gauges": True, "heatmap": True, "threat_map": True,
        "severity": True, "status": True, "epss": True, "cwe": True,
        "category": True, "vendor": True, "timelines": True, "assets": True,
    },
    "default_filter": "all",
    "live": True,
}


@app.get("/")
def index():
    sample = ""
    if config.SAMPLE_ASSET_LIST.exists():
        sample = config.SAMPLE_ASSET_LIST.read_text(encoding="utf-8")
    return render_template("index.html", sample_assets=sample)


@app.post("/api/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}
    asset_text = (payload.get("asset_text") or "").strip()
    if not asset_text:
        return jsonify({"error": "No asset list provided."}), 400

    min_epss = float(payload.get("min_epss") or 0.0)
    kev_only = bool(payload.get("kev_only"))

    # top_n is intentionally not applied server side: the dashboard reflects the
    # whole result set and the table is capped at MAX_ROWS for rendering.
    result = run_pipeline(asset_text, top_n=None, min_epss=min_epss,
                          kev_only=kev_only)
    return jsonify(result_to_dict(result, max_rows=MAX_ROWS))


@app.get("/api/catalog")
def catalog():
    """The normalisation knowledge base: products, aliases, and CPE targets."""
    items = [{
        "name": p.name,
        "category": p.category,
        "aliases": p.aliases,
        "cpe": p.cpe,
    } for p in CATALOG]
    return jsonify({"products": items, "feeds": FEED_CATALOG})


@app.get("/api/sectors")
def sectors_api():
    return jsonify({"sectors": all_sector_meta()})


# Live ingestion
@app.get("/api/live")
def live_state():
    return jsonify(engine.snapshot())


@app.get("/api/stream")
def stream():
    """Server-Sent Events: pushes live ingest events and feed-status changes."""
    def gen():
        q = engine.subscribe()
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    msg = q.get(timeout=15)
                    yield f"data: {json.dumps(msg)}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"     # keep the connection alive
        finally:
            engine.unsubscribe(q)

    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",
                             "Connection": "keep-alive"})


@app.post("/api/live/toggle")
def live_toggle():
    payload = request.get_json(silent=True) or {}
    engine.set_live(bool(payload.get("enabled", True)))
    return jsonify(engine.snapshot())


@app.post("/api/refresh")
def refresh():
    payload = request.get_json(silent=True) or {}
    engine.trigger(payload.get("feed"))
    return jsonify({"status": "refresh triggered", "feed": payload.get("feed")})


# Connectors and APIs
@app.get("/api/connectors")
def connectors_list():
    return jsonify({"connectors": conn_mod.list_connectors()})


@app.post("/api/connectors")
def connectors_add():
    payload = request.get_json(silent=True) or {}
    try:
        record = conn_mod.add_connector(payload)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    engine.start()  # ensure the loop is running to pick up the new connector
    return jsonify(record), 201


@app.patch("/api/connectors/<cid>")
def connectors_update(cid):
    payload = request.get_json(silent=True) or {}
    record = conn_mod.update_connector(cid, payload)
    if record is None:
        return jsonify({"error": "Connector not found."}), 404
    return jsonify(record)


@app.delete("/api/connectors/<cid>")
def connectors_delete(cid):
    ok = conn_mod.remove_connector(cid)
    if not ok:
        return jsonify({"error": "Built-in connectors cannot be removed."}), 400
    return jsonify({"status": "removed", "id": cid})


# Preferences (the configurable dashboard)
def _load_prefs() -> dict:
    if config.PREFERENCES_FILE.exists():
        try:
            saved = json.loads(config.PREFERENCES_FILE.read_text(encoding="utf-8"))
            merged = {**_DEFAULT_PREFS, **saved}
            merged["widgets"] = {**_DEFAULT_PREFS["widgets"],
                                 **(saved.get("widgets") or {})}
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    return dict(_DEFAULT_PREFS)


@app.get("/api/preferences")
def get_prefs():
    return jsonify(_load_prefs())


@app.post("/api/preferences")
def save_prefs():
    payload = request.get_json(silent=True) or {}
    prefs = _load_prefs()
    for key in ("theme", "sectors", "default_filter", "live"):
        if key in payload:
            prefs[key] = payload[key]
    if "widgets" in payload and isinstance(payload["widgets"], dict):
        prefs["widgets"].update(payload["widgets"])
    config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config.PREFERENCES_FILE.write_text(json.dumps(prefs, indent=2),
                                       encoding="utf-8")
    return jsonify(prefs)


@app.get("/health")
def health():
    data = load_data()
    snap = engine.snapshot()
    return jsonify({
        "status": "ok",
        "version": "3.0.0",
        "name": "Vulnify",
        "live_enabled": snap["live_enabled"],
        "online": snap["online"],
        "cve_records": data.counts["nvd"],
        "kev_entries": data.counts["kev"],
        "epss_scores": data.counts["epss"],
    })


# Warm the cache and start the live engine at import time so it runs under any
# WSGI server, not only the development server below. Guarded so a feed problem
# degrades gracefully (the server still binds; data loads lazily per request)
# rather than preventing startup.
def _startup() -> None:
    try:
        load_data()
        engine.start()
    except Exception as exc:  # noqa: BLE001
        print(f"[vulnify] startup warm-up deferred: {type(exc).__name__}: {exc}")


_startup()


if __name__ == "__main__":
    # threaded=True so the SSE stream and the background poller coexist with
    # request handling on the development server.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
