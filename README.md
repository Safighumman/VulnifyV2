<div align="center">

# Vulnify

### Live CVE-to-Stack Intelligence Platform

Turn a list of the software you actually run into a **live**, prioritised,
plain-English action list of the vulnerabilities that matter, ranked by
real-world exploitability, with risk mitigation, sector context, and official
documentation for every finding.

</div>

> A small IT administrator cannot filter hundreds of daily CVEs to the handful
> that actually affect their systems. Vulnify does that for them, live, and
> presents it as a clean, SOC-style intelligence platform.

Built for the CyberHack 2026 "CVE-to-My-Stack Translator" brief, then taken well
beyond it into a full, **continuously ingesting** intelligence platform. A real
bundled dataset ships in the repository so it works the moment you clone it, and
a background engine upgrades it to live data the moment it can reach the
network.

## What makes it stand out

* **Live ingestion, not a static page.** A background engine constantly polls
  the brief's sources (NVD via the Fraunhofer FKIE mirror, the CISA KEV
  catalogue, and EPSS) and streams new activity to the dashboard over
  Server-Sent Events. New CISA KEV entries arrive as **Confirmed** exploitation;
  rising EPSS scores and freshly published CVEs arrive as **Unconfirmed**
  signals. If the network is unavailable it falls back to the bundled real
  subset and upgrades itself the moment connectivity returns.
* **A SOC console, not a script.** Risk gauges, a sector × severity heatmap, a
  stylised threat map, a live confirmed/unconfirmed feed, confidence scoring,
  CWE weakness categorisation, and breakdowns by severity, sector, vendor,
  category, and time.
* **Risk mitigation on every finding.** Each CVE carries a prioritised,
  weakness-specific remediation plan, and each feed carries guidance on how to
  act on it. Hover any vulnerability for its description, risk summary, risk
  mitigation, and a link to official documentation.
* **Zero-day treatment.** CVEs exploited at or near disclosure are flagged and
  shown with their **official CISA name** and all available detail, not a
  made-up nickname.
* **Organisation sectors.** Education, banking & finance, healthcare,
  government, technology, retail, manufacturing, energy, and charity, with a
  heatmap and per-sector exposure, all configurable to the sectors you run.
* **Configurable and extensible.** A Connectors & APIs view to enable, tune, or
  add your own feed/API, and a Settings view to choose your sectors, the widgets
  you see, and the live cadence.
* **The hard part done right.** Normalisation maps messy product names to CPE
  identifiers verified against the real NVD feeds, including the traps that
  silently break naive matching.

## The platform

The web dashboard (`python webapp/app.py`) is organised the way an analyst
expects:

* **Overview.** Risk gauges (composite exposure, exploitation, asset coverage),
  KPI cards (relevant CVEs, confirmed exploited, zero-day class, ransomware,
  critical, mean CVSS, mean confidence, peak EPSS), a sector × severity heatmap,
  the threat map, and a wall of charts.
* **Live feed.** Per-source ingestion health (live/offline, records,
  new-since-last) and a streaming list of confirmed and unconfirmed activity as
  it is ingested.
* **Threat map.** Exposure plotted by affected-technology vendor headquarters on
  a stylised world canvas, with region and vendor rollups. Clearly labelled as a
  vendor-HQ heuristic, not attack telemetry.
* **Vulnerabilities.** A sortable, filterable, searchable table. Hover any row
  for description, risk summary, risk mitigation, and the official-documentation
  link; click for the full drawer with the parsed CVSS vector, EPSS percentile,
  confidence gauge, affected assets and CPEs, weaknesses, the step-by-step
  mitigation plan, official documentation links, zero-day detail, and references.
* **Sectors.** Sector exposure cards and the heatmap; click a sector to filter
  the whole vulnerability table to it.
* **Assets.** Your inventory normalised to CPEs and tagged by sector, with per
  asset CVE and exploited counts, and unrecognised assets clearly flagged.
* **Connectors & APIs.** Every source as a connector you can enable, disable,
  re-tune, sync on demand, or extend with your own feed/API.
* **Imports & feeds.** Live ingestion health for every source, with how to act
  on each one.
* **Settings.** Choose your sectors, the visible widgets, the default filter,
  and toggle live ingestion. Saved to the workspace.
* **Normalisation catalogue.** The verified product-to-CPE knowledge base.

## How it works

A small, auditable pipeline. Each stage is its own module.

```
  Asset list (pasted text, file upload, or CSV export)
        |
        v
  Normalisation   map messy names to verified CPE identifiers (the hard part)
        |
        v
  CVE matching    filter the NVD corpus by CPE, with version range awareness
        |
        v
  Enrichment      attach EPSS probability, CISA KEV flags, CWE, confidence,
        |         sector, mitigation, zero-day treatment
        v
  Ranking         one urgency score: KEV first, then EPSS, then CVSS
        |
        v
  Output          dashboard, console table, CSV, one page brief, JSON
```

Alongside the request pipeline, a **live ingestion engine** runs in the
background, polls the enabled connectors on their own cadences, diffs each feed
against the previous snapshot, emits live events, and hot-swaps the cached corpus
so analysis always reflects the freshest data.

### Why normalisation is the whole game

CVE matching fails silently. If a product name maps to the wrong CPE, the
relevant CVE simply does not appear, with no error. Every trap below is handled
by a hand-verified catalogue:

* Windows 10 and 11 have no bare CPE. They exist only as release-tagged products
  such as `microsoft:windows_10_22h2`. A "Windows 10 Pro, 22H2" asset matches the
  `22h2` release specifically, not `21h2`.
* VMware vSphere is a suite with no `vmware:vsphere` CPE. It resolves to its real
  components, `vmware:vcenter_server` and `vmware:esxi`.
* Zoom the classic client is now published as `zoom:workplace`.
* nginx moved under the `f5` vendor namespace after the F5 acquisition.

### Scoring

```
urgency    = 0.70 * EPSS + 0.30 * (CVSS / 10)
           + 100  if the CVE is in the CISA KEV catalogue
           + 10   if KEV flags known ransomware use

confidence = NVD analysis status
           + bonuses for CVSS, EPSS, CWE, references, and KEV corroboration
```

Urgency guarantees confirmed-exploited CVEs always sort to the top. Confidence
expresses how complete and trustworthy each record is.

## Data sources, live with offline fallback

Vulnify uses **only the sources named in the project brief**. The direct
official hosts for two of them are reached through their maintained GitHub
mirrors, which is the same data on a host that works behind strict outbound
allow-lists. The brief itself names the Fraunhofer FKIE GitHub repository as the
recommended NVD source.

| Feed | Live source | Bundled subset |
|------|-------------|----------------|
| NVD CVE | Fraunhofer FKIE reconstruction (GitHub releases) | 3,369 real CVEs touching catalogue vendors |
| CISA KEV | CISA catalogue (CISAgov GitHub mirror) | All current entries, verbatim |
| EPSS | FIRST.org EPSS (empiricalsec GitHub mirror) | Scores for every bundled CVE |

Resolution is tiered and automatic:

1. Full live feeds in `data/feeds/` (fetched on demand by the live engine, or by
   `scripts/fetch_data.py`).
2. The real bundled subset in `data/bundled/` that ships with the repository.

So the tool produces real results immediately after a clone, scales up to the
complete live feeds with no code change, and never breaks when offline.

## Quick start

```bash
pip install -r requirements.txt

# Web platform (live ingestion starts automatically).
python webapp/app.py        # then open http://127.0.0.1:5000

# Command line, against the bundled real data.
python cli.py data/sample_asset_list.txt --top 15
python cli.py examples/enterprise_datacenter.txt --kev-only
python cli.py examples/smb_accountancy.txt --csv out.csv --brief brief.txt --json out.json
```

## Configuration

* **Live ingestion** is on by default. Disable it with `VULNIFY_LIVE=0`, or from
  the Settings view in the dashboard.
* **Poll cadences** (seconds) are tunable: `VULNIFY_INTERVAL_KEV` (default 180),
  `VULNIFY_INTERVAL_EPSS` (900), `VULNIFY_INTERVAL_NVD` (86400).
* **Connectors** you add in the dashboard are persisted to
  `data/config/connectors.json`; preferences to `data/config/preferences.json`.
* **CVE years** are controlled by `CVE_YEARS` (default `2024,2025`).

## Project structure

```
Vulnify/
  cli.py                       command line entry point
  requirements.txt

  cve_translator/              the core engine package
    config.py                  paths, thresholds, ranking weights, live settings
    cpe_catalog.py             verified normalisation catalogue
    normalization.py           fuzzy match messy names to canonical CPEs
    data_loader.py             read NVD, KEV (with official names), EPSS, assets
    matcher.py                 CPE matching and version range logic
    ranking.py                 urgency and confidence scoring
    sectors.py                 organisation-sector classification
    mitigation.py              per-CVE/per-feed risk mitigation, zero-day, docs
    geo.py                     vendor-HQ geography for the threat map
    connectors.py              configurable feed/API registry (persisted)
    live_feed.py               background live ingestion engine + event stream
    analytics.py               dashboard aggregations (gauges, heatmap, sectors)
    feeds.py                   import and feed metadata
    risk_summary.py            plain-English summaries and actions
    report.py                  CSV, console table, one page brief
    export.py                  structured JSON payload
    pipeline.py                cached end to end orchestration

  webapp/                      the web platform (Flask)
    app.py                     JSON API + SSE stream over the engine
    templates/index.html       single page dashboard shell
    static/                    app.css, app.js, charts.js, icons.js, logo.svg

  scripts/
    fetch_data.py              download the full real feeds
    build_sample_dataset.py    distil full feeds into the bundled subset

  data/
    sample_asset_list.txt      the brief sample list
    bundled/                   real data subset, tracked, works offline
    feeds/                     full live feeds, fetched on demand, not tracked
    config/                    connectors and preferences, not tracked

  examples/                    ready-made asset lists and sample outputs
  tests/                       unit and integration tests
```

## Requirements coverage

Every objective in the brief is met, plus all four stretch goals and a great deal
more.

| Requirement | Status | Where |
|-------------|--------|-------|
| Load and parse a data feed | All three (NVD, KEV, EPSS) | `data_loader.py` |
| Normalisation dictionary, 15 to 20 products | 49 verified products | `cpe_catalog.py` |
| Matching filters CVEs to the asset list | Done | `matcher.py` |
| Apply EPSS and KEV to rank by urgency | Done | `ranking.py` |
| Structured output (CSV or table) | CSV, console table | `report.py` |
| Plain-English risk summary | Done | `risk_summary.py` |
| Stretch: one page brief | Done | `report.py` |
| Stretch: combined CVSS and EPSS score | Done | `ranking.py` |
| Stretch: version range matching | Done, plus Windows release logic | `matcher.py` |
| Stretch: command line interface | Done | `cli.py` |
| Extra: live ingestion + SSE, offline fallback | Done | `live_feed.py`, `app.py` |
| Extra: live confirmed vs unconfirmed feed | Done | `live_feed.py` |
| Extra: per-CVE and per-feed risk mitigation | Done | `mitigation.py` |
| Extra: zero-day official name and detail | Done | `mitigation.py` |
| Extra: organisation-sector categorisation | Done | `sectors.py` |
| Extra: configurable connectors/APIs | Done | `connectors.py` |
| Extra: SOC dashboard (gauges, heatmap, threat map) | Done | `analytics.py`, `webapp/` |
| Extra: real bundled data, offline on clone | Done | `data/bundled/` |
| Extra: automated test suite | Done | `tests/` |

## Testing

```bash
python -m pytest tests/ -q
```

The suite covers normalisation (including the Windows release and vSphere suite
cases), version range logic, ranking order, confidence scoring, dashboard
aggregation (gauges, heatmap, sectors, threat map), sector classification, risk
mitigation and zero-day detection, the connector registry, the live ingestion
engine (offline), feed metadata, asset parsing, and a full end-to-end run against
the bundled real data.

## Known limitations

* Matching depends on the normalisation catalogue. A product not in it, or
  mapped to the wrong CPE, silently produces no results. Unrecognised assets are
  always reported so they are never hidden.
* EPSS is predictive, not deterministic. A low score means exploitation has not
  been observed at scale yet, not that the CVE is safe.
* CISA KEV records confirmed exploitation. A CVE absent from KEV may simply be
  unconfirmed rather than unexploited.
* The threat map's geography is a vendor-headquarters heuristic for the SOC
  aesthetic, not attack-origin telemetry; the CVE feeds carry no such geography.
* Product-level matching is broad by design. Running Windows and Chrome genuinely
  exposes you to many CVEs; the value is in the ranking, the confidence signal,
  the sector context, and the filters.
