"""Configuration for the NVD enrichment-gap collector.

Paths resolve relative to the nvd_gap/ package root, so the collector behaves
identically whether it is run from a scheduler, a container, or the repo root.
Override the data location with NVD_GAP_DATA_DIR.
"""
from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent

_data_override = os.environ.get("NVD_GAP_DATA_DIR")
DATA_DIR = Path(_data_override) if _data_override else PACKAGE_ROOT / "data"

STATE_DIR = DATA_DIR / "state"
CHANGES_DIR = DATA_DIR / "changes"
ROLLUP_DIR = DATA_DIR / "rollups"

SYNC_STATE_PATH = STATE_DIR / "sync_state.json"
ROLLUP_PATH = ROLLUP_DIR / "coverage_daily.parquet"

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY") or None

# NVD permits 5 requests per rolling 30s window without an API key and 50 with
# one. These delays stay comfortably inside both limits; the API returns 403
# rather than 429 when you exceed them, which is easy to misdiagnose.
REQUEST_DELAY_SECONDS = 0.8 if NVD_API_KEY else 6.5

RESULTS_PER_PAGE = 2000  # API maximum
MAX_RETRIES = 5
RETRY_BACKOFF_SECONDS = 15
REQUEST_TIMEOUT_SECONDS = 60

# NVD rejects lastModStartDate/lastModEndDate ranges wider than 120 days.
MAX_WINDOW = timedelta(days=110)

# NVD publishes its own enrichment under this source identifier. Any other
# source in `metrics` is a CNA or other third party. Distinguishing the two is
# the whole point of this collector: after April 2026 NVD stops scoring a CVE
# at all when the CNA has already scored it.
NVD_SOURCE_ID = "nvd@nist.gov"

# vulnStatus values, split by what they actually mean to a consumer:
#
#   terminal - NVD has decided not to enrich. Durable; this is the real gap.
#   queued   - still in the backlog, and may yet clear.
#
# Keeping these apart is essential. In a 30-day window most unenriched records
# are merely recent, so collapsing the two inflates every headline number.
# "Deferred" is the status the April 2026 triage policy pushes new records
# into; "Not Scheduled" holds the pre-March-2026 backlog it abandoned.
#
# There is deliberately no combined "unenriched" constant. Reporting the two
# as one number collapses a durable NVD decision (~40%, stable across
# windows) into a clearing backlog (48.9% at 3 days, 37.2% at 30), producing a
# headline figure that swings with the sampling window and is trivially
# discredited. Any caller that wants the union must spell it out at the call
# site and own that choice.
TERMINAL_UNENRICHED_STATUSES = frozenset({"Not Scheduled", "Deferred"})
QUEUED_STATUSES = frozenset({"Awaiting Analysis", "Received", "Undergoing Analysis"})
