"""Collector for NVD enrichment-gap tracking.

Measures how much of the CVE corpus NVD has actually enriched since the
risk-based triage policy took effect on 15 April 2026, and records a
field-level change log so post-publication edits can be diffed later.
"""

__version__ = "0.1.0"
