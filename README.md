<div align="center">

# Lodestar

### CVE to Stack Intelligence Platform

Turn a list of the software you actually run into a prioritised, plain-English
action list of the vulnerabilities that matter, ranked by real-world
exploitability. Lodestar is the guiding star that cuts the daily CVE firehose
down to the few that threaten your stack today.

</div>

> A small IT administrator cannot filter hundreds of daily CVEs to the handful
> that actually affect their systems. Lodestar does that for them, and presents
> it as a clean, categorised intelligence platform.

Built for the CyberHack 2026 "CVE-to-My-Stack Translator" brief, then taken well
beyond it into a full offline intelligence platform. Everything runs against
pre-downloaded data with no live API calls, and a real bundled dataset ships in
the repository so it works the moment you clone it.

## Why this stands out

* A real working engine on real data. 83,000 real CVEs are scannable from the
  full feeds, and a verified 3,369 CVE real subset ships in the repo so results
  are genuine out of the box (the famous VMware ESXi and Windows SmartScreen
  exploited CVEs really do rank to the top).
* A platform, not a script. An OpenCTI style dashboard with import jobs and
  ingest speed, confirmed versus unconfirmed exploitation, a per CVE data
  confidence score, CWE weakness categorisation, and breakdowns by severity,
  vendor, category, and time.
* The hard part done right. Normalisation maps messy product names to CPE
  identifiers that were each verified against the real NVD feeds, including the
  traps that silently break naive matching (see below).
* Four ways to consume it. A console table, a CSV export, a one page management
  brief, and a structured JSON payload, all from one engine.
* Polished and fast. A dark, animated dashboard with charts, a constellation
  background, subtle 3D card motion, and a detail drawer, all dependency free
  and built to respect reduced motion.

## The platform

The web dashboard (`python webapp/app.py`) has five categorised views:

* Overview. KPI cards (relevant CVEs, confirmed exploited, ransomware linked,
  critical count, mean CVSS, mean confidence, assets covered, peak EPSS) and a
  wall of charts: severity donut, exploitation status, EPSS probability bands,
  top weakness types, breakdowns by category and vendor, and publication and
  KEV timelines.
* Vulnerabilities. A sortable, filterable, searchable table. Every row carries
  severity, EPSS, confirmed or unconfirmed status, and a confidence meter.
  Click any row for a full detail drawer with the parsed CVSS vector, EPSS
  percentile, confidence gauge, affected assets and CPEs, weaknesses,
  references, and the recommended action.
* Imports and feeds. Each offline source rendered as an import job with record
  count, ingest speed, format, and contribution, exactly how an analyst expects
  to see connector runs.
* Assets. Your inventory normalised to CPEs, with per asset CVE and exploited
  counts, and unrecognised assets clearly flagged so nothing hides.
* Normalisation catalogue. The verified knowledge base of products, their
  aliases, and the real CPE targets they resolve to.

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
  Enrichment      attach EPSS probability, CISA KEV flags, CWE, confidence
        |
        v
  Ranking         one urgency score: KEV first, then EPSS, then CVSS
        |
        v
  Output          dashboard, console table, CSV, one page brief, JSON
```

### Why normalisation is the whole game

CVE matching fails silently. If a product name maps to the wrong CPE, the
relevant CVE simply does not appear, with no error. Every trap below is handled
by a hand verified catalogue:

* Windows 10 and 11 have no bare CPE. They exist only as release tagged products
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

Urgency guarantees confirmed exploited CVEs always sort to the top. Confidence
expresses how complete and trustworthy each record is, shown as a 0 to 100 score
and a High, Medium, or Low band.

## Requirements coverage

Every objective in the brief is met, plus all four stretch goals and a great deal
more.

| Requirement | Status | Where |
|-------------|--------|-------|
| Load and parse a data feed | All three (NVD, KEV, EPSS) | `data_loader.py` |
| Normalisation dictionary, 15 to 20 products | 25 verified products | `cpe_catalog.py` |
| Matching filters CVEs to the asset list | Done | `matcher.py` |
| Apply EPSS and KEV to rank by urgency | Done | `ranking.py` |
| Structured output (CSV or table) | CSV, console table | `report.py` |
| Plain-English risk summary | Done | `risk_summary.py` |
| Stretch: one page brief | Done | `report.py` |
| Stretch: combined CVSS and EPSS score | Done | `ranking.py` |
| Stretch: version range matching | Done, plus Windows release logic | `matcher.py` |
| Stretch: command line interface | Done | `cli.py` |
| Extra: OpenCTI style web platform | Done | `webapp/` |
| Extra: confidence scoring, confirmed vs unconfirmed | Done | `ranking.py`, `analytics.py` |
| Extra: import and feed metadata with ingest speed | Done | `feeds.py` |
| Extra: CWE categorisation and dashboards | Done | `analytics.py` |
| Extra: JSON export for automation | Done | `export.py`, `cli.py` |
| Extra: real bundled data, offline on clone | Done | `data/bundled/` |
| Extra: 36 test automated suite | Done | `tests/` |

## Quick start

```bash
pip install -r requirements.txt

# Command line, against the bundled real data.
python cli.py data/sample_asset_list.txt --top 15
python cli.py examples/enterprise_datacenter.txt --kev-only
python cli.py examples/smb_accountancy.txt --csv out.csv --brief brief.txt --json out.json

# Web platform.
python webapp/app.py        # then open http://127.0.0.1:5000
```

See `examples/` for ready-made asset lists covering each target user, plus sample
generated outputs in `examples/outputs/`.

## Data, offline by design

No live data APIs are ever called. The tool resolves data in two tiers:

1. Full feeds in `data/feeds/` if present (fetched on demand).
2. A real bundled subset in `data/bundled/` that ships with the repository.

| Feed | Source | Bundled subset |
|------|--------|----------------|
| NVD CVE | Fraunhofer FKIE reconstruction | 3,369 real CVEs touching catalogue vendors |
| CISA KEV | The official catalogue | All 1,610 entries, verbatim |
| EPSS | The official empiricalsecurity scores | Scores for every bundled CVE |

To pull the complete current feeds (hundreds of thousands of CVEs) and rebuild
the subset:

```bash
python scripts/fetch_data.py
python scripts/build_sample_dataset.py \
  --nvd-dir data/feeds \
  --kev data/feeds/known_exploited_vulnerabilities.json \
  --epss data/feeds/epss_scores-YYYY-MM-DD.csv.gz
```

## Project structure

```
Lodestar/
  cli.py                       command line entry point
  requirements.txt

  cve_translator/              the core engine package
    config.py                  paths, thresholds, ranking weights
    cpe_catalog.py             verified normalisation catalogue (25 products)
    normalization.py           fuzzy match messy names to canonical CPEs
    data_loader.py             read NVD, KEV, EPSS, and asset lists
    matcher.py                 CPE matching and version range logic
    ranking.py                 urgency and confidence scoring
    analytics.py               dashboard aggregations and CWE naming
    feeds.py                   import and feed metadata
    risk_summary.py            plain-English summaries and actions
    report.py                  CSV, console table, one page brief
    export.py                  structured JSON payload
    pipeline.py                cached end to end orchestration

  webapp/                      the web platform (Flask)
    app.py                     JSON API over the engine
    templates/index.html       single page dashboard shell
    static/                    app.css, app.js, charts.js, logo.svg

  scripts/
    fetch_data.py              download the full real feeds
    build_sample_dataset.py    distil full feeds into the bundled subset

  data/
    sample_asset_list.txt      the brief sample list
    bundled/                   real data subset, tracked, works offline
    feeds/                     full feeds, fetched on demand, not tracked

  examples/                    ready-made asset lists and sample outputs
  tests/                       36 unit and integration tests
```

## Output formats

* Dashboard. The categorised web platform described above.
* Console table. A ranked table for the terminal demo.
* CSV. The full structured table: CVE, asset, status, CVSS, EPSS, KEV flags,
  confidence, urgency, weakness, matched CPE, action, and plain-English summary.
* One page brief. A plain text management briefing.
* JSON. The complete structured payload for automation and integration.

## Known limitations

* Matching depends on the normalisation catalogue. A product not in it, or
  mapped to the wrong CPE, silently produces no results. Unrecognised assets are
  always reported so they are never hidden.
* EPSS is predictive, not deterministic. A low score means exploitation has not
  been observed at scale yet, not that the CVE is safe.
* CISA KEV records confirmed exploitation. A CVE absent from KEV may simply be
  unconfirmed rather than unexploited.
* NVD enrichment is selective, so lower profile CVEs may have incomplete data.
* Product level matching is broad by design. Running Windows and Chrome genuinely
  exposes you to many CVEs. The value is in the ranking, the confidence signal,
  and the filters, which surface the few that matter now.

## Testing

```bash
python -m pytest tests/ -q
```

Thirty six tests cover normalisation (including the Windows release and vSphere
suite cases), version range logic, ranking order, confidence scoring, dashboard
aggregation, feed metadata, asset parsing (including spreadsheet headers), and a
full end to end run against the bundled real data.

## Relationship to ThreatOrbit

Lodestar reuses the design philosophy of the author's ThreatOrbit platform. The
normalisation approach (resolve messy input to a canonical identity, then be
honest about confidence) mirrors ThreatOrbit's `normalization.py`, the weighted
scoring follows its `trust_scoring.py`, and the categorised dashboard and
confirmed versus unconfirmed framing echo its intelligence platform model.
