"""CVE-to-My-Stack Translator.

A tool that takes a list of software assets and returns a prioritised,
plain-English list of the published CVEs that actually affect them, ranked
by real-world exploitability (EPSS), known exploitation (CISA KEV), and
severity (CVSS).

The package is organised as a small, auditable data pipeline:

    asset list  ->  normalisation  ->  CVE matching  ->  ranking  ->  output

Each stage lives in its own module so the logic is easy to follow and test.
"""

__version__ = "1.0.0"
__all__ = [
    "config",
    "cpe_catalog",
    "normalization",
    "data_loader",
    "matcher",
    "ranking",
    "risk_summary",
    "report",
    "pipeline",
]
