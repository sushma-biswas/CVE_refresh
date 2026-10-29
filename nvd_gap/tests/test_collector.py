"""Tests for the parts that are easy to get wrong and costly when wrong.

Scoped deliberately at the review findings rather than at coverage: the
deterministic CVSS choice, the schema guard on state, and the idempotency of
the change log. Those three are the ones whose failure modes are either silent
or unrecoverable.
"""
from __future__ import annotations

import argparse
import json
from datetime import date, datetime, timedelta, timezone

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from collector import cli, storage
from collector.config import MIN_AGE_HOURS
from collector.normalize import normalize_cve
from collector.storage import SchemaMismatchError

OBSERVED_AT = "2026-10-29T00:00:00.000"


def _redirect_storage(monkeypatch, tmp_path):
    """Point every storage path at a temp directory."""
    monkeypatch.setattr(storage, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(storage, "CHANGES_DIR", tmp_path / "changes")
    monkeypatch.setattr(storage, "ROLLUP_PATH", tmp_path / "rollups" / "r.parquet")
    monkeypatch.setattr(storage, "CURRENT_PATH", tmp_path / "state" / "current.parquet")
    storage.ensure_dirs()


def _change_row(cve: dict, run_id: str) -> dict:
    row = normalize_cve(cve, OBSERVED_AT)
    return dict(
        row,
        change_type="new",
        prev_content_hash=None,
        prev_observed_at=None,
        run_id=run_id,
        raw_json=json.dumps(cve, sort_keys=True, separators=(",", ":")),
    )


# --------------------------------------------------------- CVSS selection


def _cve_with_two_v31_scores(nvd_first: bool) -> dict:
    cna = {
        "source": "cna@example.com",
        "type": "Primary",
        "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
    }
    nvd = {
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"},
    }
    entries = [nvd, cna] if nvd_first else [cna, nvd]
    return {
        "id": "CVE-2026-0001",
        "vulnStatus": "Analyzed",
        "metrics": {"cvssMetricV31": entries},
    }


@pytest.mark.parametrize("nvd_first", [True, False])
def test_cvss_choice_is_independent_of_response_order(nvd_first):
    """The same record must normalise identically whatever the entry order.

    This is the regression that matters most: NVD does not contract the order
    of entries within a metric list, so picking "the first one" let base_score
    flip between observations - and because content_hash covers the raw
    record, the flip would not even be logged as a change.
    """
    row = normalize_cve(_cve_with_two_v31_scores(nvd_first), OBSERVED_AT)
    assert row["cvss_source"] == "nvd@nist.gov"
    assert row["base_score"] == 7.5
    assert row["base_severity"] == "HIGH"
    assert row["nvd_scored"] is True
    assert row["cna_scored"] is True


def test_stronger_cvss_version_wins_over_nvd_preference():
    """Version precedence outranks source precedence."""
    cve = {
        "id": "CVE-2026-0002",
        "vulnStatus": "Analyzed",
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"},
                }
            ],
            "cvssMetricV40": [
                {
                    "source": "cna@example.com",
                    "type": "Primary",
                    "cvssData": {"baseScore": 6.1, "baseSeverity": "MEDIUM"},
                }
            ],
        },
    }
    row = normalize_cve(cve, OBSERVED_AT)
    assert row["cvss_version"] == "4.0"
    assert row["base_score"] == 6.1


def test_primary_outranks_secondary_from_same_source():
    cve = {
        "id": "CVE-2026-0003",
        "vulnStatus": "Analyzed",
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "other@example.com",
                    "type": "Secondary",
                    "cvssData": {"baseScore": 2.0, "baseSeverity": "LOW"},
                },
                {
                    "source": "cna@example.com",
                    "type": "Primary",
                    "cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"},
                },
            ]
        },
    }
    row = normalize_cve(cve, OBSERVED_AT)
    assert row["base_score"] == 9.1
    assert row["nvd_scored"] is False


def test_unscored_record_has_no_cvss_fields():
    row = normalize_cve(
        {"id": "CVE-2026-0004", "vulnStatus": "Deferred"}, OBSERVED_AT
    )
    assert row["unscored"] is True
    assert row["base_score"] is None
    assert row["cvss_version"] is None
    assert row["nvd_declined"] is True
    assert row["in_queue"] is False


def test_declined_and_queued_are_mutually_exclusive():
    """The distinction the whole headline metric rests on."""
    declined = normalize_cve({"id": "A", "vulnStatus": "Deferred"}, OBSERVED_AT)
    queued = normalize_cve(
        {"id": "B", "vulnStatus": "Awaiting Analysis"}, OBSERVED_AT
    )
    assert (declined["nvd_declined"], declined["in_queue"]) == (True, False)
    assert (queued["nvd_declined"], queued["in_queue"]) == (False, True)


def test_cpe_count_counts_matches_not_nodes():
    cve = {
        "id": "CVE-2026-0005",
        "vulnStatus": "Analyzed",
        "configurations": [{"nodes": [{"cpeMatch": []}, {"cpeMatch": [{}, {}]}]}],
    }
    row = normalize_cve(cve, OBSERVED_AT)
    assert row["cpe_count"] == 2
    assert row["has_cpe"] is True


def test_configurations_with_no_matches_is_not_enriched():
    cve = {
        "id": "CVE-2026-0006",
        "vulnStatus": "Analyzed",
        "configurations": [{"nodes": [{"cpeMatch": []}]}],
    }
    assert normalize_cve(cve, OBSERVED_AT)["has_cpe"] is False


# ------------------------------------------------------------ state schema


def test_upsert_refuses_state_written_by_another_schema(monkeypatch, tmp_path):
    """A positional INSERT would corrupt or crash; this must fail loudly.

    Reproduces the real incident: the Actions cache holds a current.parquet
    written before a column was added, so every later sync would otherwise
    break obscurely until someone evicted the cache by hand.
    """
    _redirect_storage(monkeypatch, tmp_path)
    rows = [normalize_cve({"id": "CVE-2026-0007", "vulnStatus": "Deferred"}, OBSERVED_AT)]

    # State missing one column, as an older build would have written it.
    stale_schema = pa.schema(
        [f for f in storage.OBSERVATION_SCHEMA if f.name != "in_queue"]
    )
    pq.write_table(
        storage.to_table(rows, stale_schema), storage.CURRENT_PATH
    )

    with pytest.raises(SchemaMismatchError) as excinfo:
        storage.upsert_current(rows)
    assert "baseline" in str(excinfo.value)


def test_upsert_creates_then_merges_state(monkeypatch, tmp_path):
    _redirect_storage(monkeypatch, tmp_path)
    first = normalize_cve({"id": "CVE-2026-0008", "vulnStatus": "Received"}, OBSERVED_AT)
    assert storage.upsert_current([first]) == 1

    # Same CVE, new status: replaced, not duplicated.
    second = normalize_cve({"id": "CVE-2026-0008", "vulnStatus": "Deferred"}, OBSERVED_AT)
    assert storage.upsert_current([second]) == 1
    assert storage.load_current_hashes()["CVE-2026-0008"][0] == second["content_hash"]

    # A different CVE is added alongside.
    third = normalize_cve({"id": "CVE-2026-0009", "vulnStatus": "Analyzed"}, OBSERVED_AT)
    assert storage.upsert_current([third]) == 2


# -------------------------------------------------------------- change log


def test_append_changes_is_idempotent(monkeypatch, tmp_path):
    """Re-running after a crash must converge, not double-count.

    The change log is unrebuildable, so sync writes it before updating state.
    That ordering risks a duplicate rather than a loss - which is only the
    right trade if the duplicate is actually suppressed.
    """
    _redirect_storage(monkeypatch, tmp_path)
    cve = {"id": "CVE-2026-0010", "vulnStatus": "Deferred"}

    first = storage.append_changes([_change_row(cve, "run1")], date(2026, 10, 29))
    assert first is not None

    # Identical content observed again under a fresh run_id: same event.
    assert storage.append_changes([_change_row(cve, "run2")], date(2026, 10, 30)) is None

    # A genuine change to the record is logged.
    changed = dict(cve, vulnStatus="Analyzed")
    assert storage.append_changes([_change_row(changed, "run3")], date(2026, 10, 30))

    parts = sorted(storage.CHANGES_DIR.glob("dt=*/part-*.parquet"))
    assert len(parts) == 2


def test_append_changes_handles_empty_input(monkeypatch, tmp_path):
    _redirect_storage(monkeypatch, tmp_path)
    assert storage.append_changes([], date(2026, 10, 29)) is None


# ---------------------------------------------------------------- rollup

ALL_COHORTS = {
    "all",
    "settled_30d",
    "settled_90d",
    "fresh",
    "published_30d",
    "published_90d",
    "post_policy",
    "pre_policy",
}


def _redirect_rollup(monkeypatch, tmp_path):
    _redirect_storage(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "CURRENT_PATH", storage.CURRENT_PATH)
    monkeypatch.setattr(cli, "ROLLUP_PATH", tmp_path / "rollups" / "coverage.parquet")


def _rollup_by_cohort():
    con = duckdb.connect()
    try:
        rows = con.execute(
            "SELECT cohort, records, pct_no_cpe FROM read_parquet(?)",
            [str(cli.ROLLUP_PATH)],
        ).fetchall()
    finally:
        con.close()
    return {row[0]: (row[1], row[2]) for row in rows}


def _published(cve_id, status, published):
    return normalize_cve(
        {"id": cve_id, "vulnStatus": status, "published": published}, OBSERVED_AT
    )


def test_rollup_emits_every_cohort_even_when_empty(monkeypatch, tmp_path):
    """An empty cohort must still appear, with 0 records and a NULL share.

    GROUP BY on its own drops it, which would silently delete the fresh row
    that the dashboard leans on to justify its own exclusion - and nothing
    would report the row's absence.
    """
    _redirect_rollup(monkeypatch, tmp_path)
    storage.upsert_current(
        [_published("CVE-2024-0001", "Analyzed", "2024-06-01T00:00:00.000")]
    )

    assert cli.cmd_rollup(argparse.Namespace()) == 0

    by_cohort = _rollup_by_cohort()
    assert set(by_cohort) == ALL_COHORTS
    assert by_cohort["all"][0] == 1
    assert by_cohort["pre_policy"][0] == 1
    for empty in ("settled_30d", "settled_90d", "fresh", "published_30d", "post_policy"):
        assert by_cohort[empty] == (0, None), empty


def test_future_published_date_cannot_park_in_fresh(monkeypatch, tmp_path):
    """A future publication date must not sit in fresh indefinitely.

    Without an upper bound it would be excluded from every settled cohort by
    the age floor and counted as fresh forever - invisible in every published
    figure while inflating the row that justifies the floor.
    """
    _redirect_rollup(monkeypatch, tmp_path)
    ahead = datetime.now(timezone.utc) + timedelta(days=30)
    storage.upsert_current(
        [
            _published(
                "CVE-2026-9999", "Deferred", ahead.strftime("%Y-%m-%dT%H:%M:%S.000")
            )
        ]
    )

    assert cli.cmd_rollup(argparse.Namespace()) == 0

    by_cohort = _rollup_by_cohort()
    assert by_cohort["fresh"] == (0, None)
    assert by_cohort["published_30d"] == (0, None)
    assert by_cohort["all"][0] == 1


# ------------------------------------------------------------------- cli


def test_probe_min_age_defaults_to_the_published_floor():
    """The zero-argument probe must reproduce what the dashboard publishes.

    A default of 0 would make the sanity check disagree with the thing it is
    checking, so anyone verifying a published figure would appear to fail.
    """
    args = cli.build_parser().parse_args(["probe"])
    assert args.min_age_hours == MIN_AGE_HOURS


def test_parse_iso_names_the_flag_and_the_bad_value():
    with pytest.raises(ValueError) as excinfo:
        cli._parse_iso("2024/01/01", "--published-from")
    message = str(excinfo.value)
    assert "--published-from" in message
    assert "2024/01/01" in message


def test_parse_iso_accepts_a_plain_date():
    assert cli._parse_iso("2024-01-01", "--published-from").year == 2024
