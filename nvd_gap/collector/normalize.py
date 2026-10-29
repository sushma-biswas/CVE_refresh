"""Flatten an NVD API 2.0 CVE record into the columns the gap metrics need.

The flattened row is deliberately small so a daily observation of the whole
corpus is cheap. The full record is kept only when its content hash changes,
which is what makes the change log affordable.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterator

from .config import (
    NVD_SOURCE_ID,
    QUEUED_STATUSES,
    TERMINAL_UNENRICHED_STATUSES,
)

# Ordered strongest-first: we report the highest CVSS version present.
METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

_CVSS_VERSION_LABEL = {
    "cvssMetricV40": "4.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV30": "3.0",
    "cvssMetricV2": "2.0",
}


def content_hash(cve: dict[str, Any]) -> str:
    """Stable SHA-256 of the whole record, so any field change is detectable.

    Canonical JSON (sorted keys, no whitespace) keeps the hash stable across
    responses that differ only in key ordering, which NVD does not guarantee.
    """
    canonical = json.dumps(cve, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _iter_metrics(cve: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    metrics = cve.get("metrics") or {}
    for key in METRIC_KEYS:
        for entry in metrics.get(key) or []:
            yield key, entry


def _metric_rank(item: tuple[str, dict[str, Any]]) -> tuple[int, int, int, str]:
    """Total ordering over CVSS entries, best first.

    A CVE is routinely scored by both its CNA and NVD at the same CVSS
    version, so both entries sit in the same metric list. NVD does not
    contract the order of that list, which means picking "the first one" makes
    base_score depend on serialisation order and lets the same record
    normalise differently on separate observations. Since content_hash is
    computed over the raw record, such a flip would not even register as a
    change - current.parquet would just quietly disagree with itself.

    So the choice is made explicit and total: strongest CVSS version, then
    NVD's own Primary score, then any Primary, then NVD as a source, and
    finally the source identifier as an alphabetical tie-break so that no two
    distinct entries can ever compare equal.
    """
    key, entry = item
    is_primary = (entry.get("type") or "") == "Primary"
    source = entry.get("source") or ""
    is_nvd = source == NVD_SOURCE_ID
    return (
        METRIC_KEYS.index(key),
        0 if (is_primary and is_nvd) else 1 if is_primary else 2,
        0 if is_nvd else 1,
        source,
    )


def _cpe_count(cve: dict[str, Any]) -> int:
    """Count cpeMatch entries across all configuration nodes.

    A record with configurations but zero cpeMatch entries is still
    unenriched for matching purposes, so count the matches, not the nodes.
    """
    total = 0
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            total += len(node.get("cpeMatch") or [])
    return total


def _english_description(cve: dict[str, Any]) -> str:
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en":
            return entry.get("value") or ""
    return ""


def normalize_cve(cve: dict[str, Any], observed_at: str) -> dict[str, Any]:
    """Return one flat observation row for a single CVE record."""
    candidates = list(_iter_metrics(cve))

    nvd_scored = any(
        (entry.get("source") or "") == NVD_SOURCE_ID for _, entry in candidates
    )
    cna_scored = any(
        (entry.get("source") or "") != NVD_SOURCE_ID for _, entry in candidates
    )

    best_key, best_entry = (
        min(candidates, key=_metric_rank) if candidates else (None, None)
    )
    cvss_data = (best_entry or {}).get("cvssData") or {}

    cpe_count = _cpe_count(cve)
    vuln_status = cve.get("vulnStatus") or ""
    description = _english_description(cve)

    return {
        "cve_id": cve.get("id") or "",
        "source_identifier": cve.get("sourceIdentifier") or "",
        "published": cve.get("published") or None,
        "last_modified": cve.get("lastModified") or None,
        "vuln_status": vuln_status,
        # Derived gap flags - the metrics Route 1 reports on. Kept distinct
        # from the verbatim API fields above, because NVD's terms forbid
        # attributing modified content to them.
        "nvd_scored": nvd_scored,
        "cna_scored": cna_scored,
        "unscored": not (nvd_scored or cna_scored),
        "has_cpe": cpe_count > 0,
        "cpe_count": cpe_count,
        "nvd_declined": vuln_status in TERMINAL_UNENRICHED_STATUSES,
        "in_queue": vuln_status in QUEUED_STATUSES,
        "is_rejected": vuln_status == "Rejected",
        # Strongest CVSS present, chosen deterministically - see _metric_rank.
        "cvss_version": _CVSS_VERSION_LABEL.get(best_key or "", None),
        "cvss_source": (best_entry or {}).get("source") or None,
        "base_score": cvss_data.get("baseScore"),
        "base_severity": cvss_data.get("baseSeverity")
        or (best_entry or {}).get("baseSeverity"),
        "cwe_count": len(cve.get("weaknesses") or []),
        "reference_count": len(cve.get("references") or []),
        "description_length": len(description),
        "content_hash": content_hash(cve),
        "observed_at": observed_at,
    }
