"""NVD API 2.0 client.

Two access patterns:

  crawl_all()        - full corpus walk, used once to establish the baseline.
  crawl_modified()   - records changed in a lastModified window, used by `sync`.

The API is noticeably flaky under load and signals rate-limit violations with
403 rather than 429, so every request goes through the same retry path.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import requests

from ..config import (
    MAX_RETRIES,
    MAX_WINDOW,
    NVD_API_BASE,
    NVD_API_KEY,
    REQUEST_DELAY_SECONDS,
    REQUEST_TIMEOUT_SECONDS,
    RESULTS_PER_PAGE,
    RETRY_BACKOFF_SECONDS,
)

log = logging.getLogger(__name__)

# NVD expects ISO-8601 with millisecond precision and no timezone suffix.
_NVD_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000"


class NvdError(RuntimeError):
    """Raised when the NVD API cannot be read after exhausting retries."""


def _format_time(moment: datetime) -> str:
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment.strftime(_NVD_TIME_FORMAT)


def _session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": "nvd-gap-collector/0.1 (+research)"})
    if NVD_API_KEY:
        session.headers["apiKey"] = NVD_API_KEY
    return session


def _get_page(session: requests.Session, params: dict[str, Any]) -> dict[str, Any]:
    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(
                NVD_API_BASE, params=params, timeout=REQUEST_TIMEOUT_SECONDS
            )
            # 403 here almost always means the rate limit was tripped, not that
            # the key is wrong - back off rather than failing fast.
            if response.status_code in (403, 429, 503, 502, 504):
                raise requests.HTTPError(
                    f"HTTP {response.status_code} from NVD", response=response
                )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            last_error = exc
            if attempt == MAX_RETRIES:
                break
            wait = RETRY_BACKOFF_SECONDS * attempt
            log.warning(
                "NVD request failed (attempt %d/%d): %s - retrying in %ds",
                attempt,
                MAX_RETRIES,
                exc,
                wait,
            )
            time.sleep(wait)
    raise NvdError(f"NVD API unreadable after {MAX_RETRIES} attempts: {last_error}")


def _paginate(base_params: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield raw CVE dicts for one parameter set, following startIndex."""
    session = _session()
    start_index = 0
    total = None

    while True:
        params = dict(base_params, resultsPerPage=RESULTS_PER_PAGE, startIndex=start_index)
        payload = _get_page(session, params)

        if total is None:
            total = payload.get("totalResults", 0)
            log.info("NVD reports %s matching records", f"{total:,}")

        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            cve = item.get("cve")
            if cve and cve.get("id"):
                yield cve

        start_index += len(vulnerabilities)
        log.info("Fetched %s / %s", f"{start_index:,}", f"{total:,}")

        if start_index >= total:
            break
        time.sleep(REQUEST_DELAY_SECONDS)


def crawl_all() -> Iterator[dict[str, Any]]:
    """Walk the entire CVE corpus. ~150 requests at 2000 per page."""
    log.info("Starting full NVD corpus crawl")
    yield from _paginate({})


def _crawl_windowed(
    start: datetime,
    end: datetime,
    start_param: str,
    end_param: str,
    label: str,
) -> Iterator[dict[str, Any]]:
    """Paginate a date-filtered query, split into API-legal windows.

    NVD rejects date ranges wider than 120 days on both the lastModified and
    published filters, so the span is walked in chunks of at most 110.
    """
    if end < start:
        raise ValueError("end must not precede start")

    window_start = start
    while window_start < end:
        window_end = min(window_start + MAX_WINDOW, end)
        log.info(
            "Fetching %s %s to %s",
            label,
            _format_time(window_start),
            _format_time(window_end),
        )
        yield from _paginate(
            {
                start_param: _format_time(window_start),
                end_param: _format_time(window_end),
            }
        )
        window_start = window_end + timedelta(milliseconds=1)


def crawl_modified(start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
    """Yield records whose lastModified falls in [start, end]."""
    return _crawl_windowed(
        start, end, "lastModStartDate", "lastModEndDate", "modifications"
    )


def crawl_published(start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
    """Yield records whose publication date falls in [start, end].

    This is the cohort that matters for gap reporting. An unfiltered crawl
    returns the oldest CVEs first, which are all fully enriched and therefore
    say nothing at all about how NVD behaves today.
    """
    return _crawl_windowed(start, end, "pubStartDate", "pubEndDate", "publications")
