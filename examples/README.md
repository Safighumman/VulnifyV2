# Example asset lists

Drop-in inputs for Lodestar, one per target user in the brief, plus a deliberately
messy file that shows the normalisation engine at work. Feed any of them to the
CLI or paste them into the web dashboard.

```bash
python cli.py examples/smb_accountancy.txt --top 15
python cli.py examples/university_estate.csv --kev-only
python cli.py examples/enterprise_datacenter.txt --json examples/outputs/enterprise.json
```

| File | Scenario | Shows off |
|------|----------|-----------|
| `smb_accountancy.txt` | Solo sysadmin at a 40 person firm (Use Case 1) | Pipe format, one unrecognised app (Sage Payroll) surfaced rather than hidden |
| `university_estate.csv` | University IT estate (Use Case 2) | A real spreadsheet export with a header row, parsed automatically |
| `charity_nonprofit.txt` | Volunteer run charity (Use Case 3) | Informal names (Office 365, Chrome, Adobe Reader) resolved to CPEs |
| `enterprise_datacenter.txt` | Large mixed datacenter and endpoint estate | 23 products across operating systems, network, databases, runtimes |
| `messy_inventory.txt` | Stress test for normalisation | Misspellings, odd casing, renamed products (vSphere, Zoom Workplace, nginx) |

## How Lodestar presents the data (the OpenCTI cues)

The web dashboard categorises everything the way an analyst expects:

* Imports and feeds. Each offline source (NVD, CISA KEV, EPSS) is shown as an
  import job with its record count, ingest speed (records per second), format,
  and the category of intelligence it contributes.
* Confirmed versus unconfirmed. Every CVE is tagged Confirmed when CISA KEV
  records active exploitation in the wild, or Unconfirmed when exploitation is
  only predicted by EPSS. Ransomware linked entries are highlighted.
* Trust and confidence. A 0 to 100 data confidence score per CVE reflects the
  NVD analysis status and the presence of CVSS, CWE, references, and CPE data.
* CVSS and EPSS. Severity bands and exploitation probability are shown on every
  row and aggregated into distributions.
* Categorised views. Breakdowns by product category, vendor, and weakness type
  (CWE), plus publication and exploitation timelines.

## Sample outputs

The `outputs/` folder holds real generated artefacts so you can see the shape of
the results without running anything:

* `smb_accountancy_report.csv` the full prioritised table.
* `smb_accountancy_brief.txt` the one page management brief.
* `enterprise_dashboard.json` the complete structured payload (KPIs, dashboard
  aggregates, sample rows, per asset rollup, and import metadata).
