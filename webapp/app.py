"""Lodestar web platform: an offline CVE intelligence dashboard.

A Flask application that wraps the same pipeline the CLI uses and presents it as
a categorised, OpenCTI style intelligence platform: an overview dashboard, an
import and feed view, a filterable vulnerability table with a detail drawer, an
asset view, and a knowledge base of the normalisation catalogue.

All processing is offline. The feed data is loaded once and cached, so queries
answer in milliseconds.

Run:
    python webapp/app.py
    # then open http://127.0.0.1:5000
"""

from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cve_translator import config  # noqa: E402
from cve_translator.cpe_catalog import CATALOG  # noqa: E402
from cve_translator.export import result_to_dict  # noqa: E402
from cve_translator.feeds import FEED_CATALOG  # noqa: E402
from cve_translator.pipeline import load_data, run_pipeline  # noqa: E402

app = Flask(__name__)

# A sensible cap on rows serialised to the browser. The dashboard aggregates
# always reflect the full result set; only the table is capped for rendering.
MAX_ROWS = 600


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


@app.get("/health")
def health():
    data = load_data()
    return jsonify({
        "status": "ok",
        "version": "2.0.0",
        "cve_records": data.counts["nvd"],
        "kev_entries": data.counts["kev"],
        "epss_scores": data.counts["epss"],
    })


if __name__ == "__main__":
    # Warm the cache before serving so the first request is fast.
    load_data()
    app.run(host="127.0.0.1", port=5000, debug=False)
