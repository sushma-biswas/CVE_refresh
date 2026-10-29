"""Parquet storage for observations, the change log, and daily rollups.

Three datasets, each with a distinct job:

  state/current.parquet          One row per CVE: the latest observation.
                                 Rebuildable from a full crawl at any time.

  changes/dt=.../part-*.parquet  Append-only. One row every time a record's
                                 content hash changes, carrying the full JSON.
                                 NOT rebuildable - this only accumulates
                                 going forward, which is precisely why it is
                                 worth something.

  rollups/coverage_daily.parquet One row per run: the enrichment-gap metrics.

DuckDB does the set operations so this stays honest SQL rather than hand-rolled
merge logic in Python.
"""
from __future__ import annotations

import logging
from datetime import date
from pathlib import Path
from typing import Any, Iterable

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from .config import CHANGES_DIR, LAST_SEEN_PATH, ROLLUP_PATH, STATE_DIR

log = logging.getLogger(__name__)

CURRENT_PATH = STATE_DIR / "current.parquet"

# Explicit schema rather than inference: base_score is frequently all-null in a
# batch, and inference would type it as null and then fail to merge.
OBSERVATION_SCHEMA = pa.schema(
    [
        ("cve_id", pa.string()),
        ("source_identifier", pa.string()),
        ("published", pa.string()),
        ("last_modified", pa.string()),
        ("vuln_status", pa.string()),
        ("nvd_scored", pa.bool_()),
        ("cna_scored", pa.bool_()),
        ("unscored", pa.bool_()),
        ("has_cpe", pa.bool_()),
        ("cpe_count", pa.int32()),
        ("nvd_declined", pa.bool_()),
        ("is_rejected", pa.bool_()),
        ("cvss_version", pa.string()),
        ("cvss_source", pa.string()),
        ("base_score", pa.float64()),
        ("base_severity", pa.string()),
        ("cwe_count", pa.int32()),
        ("reference_count", pa.int32()),
        ("description_length", pa.int32()),
        ("content_hash", pa.string()),
        ("in_queue", pa.bool_()),
        ("observed_at", pa.string()),
    ]
)

# The change log carries everything above plus provenance and the full record.
CHANGE_SCHEMA = pa.schema(
    list(OBSERVATION_SCHEMA)
    + [
        ("change_type", pa.string()),       # 'new' | 'modified'
        ("prev_content_hash", pa.string()),
        ("prev_observed_at", pa.string()),
        ("run_id", pa.string()),
        ("raw_json", pa.string()),
    ]
)


def ensure_dirs() -> None:
    for directory in (STATE_DIR, CHANGES_DIR, ROLLUP_PATH.parent):
        directory.mkdir(parents=True, exist_ok=True)


def sql_literal(value: Any) -> str:
    """Quote a path as a SQL string literal.

    DuckDB's COPY ... TO rejects prepared-statement placeholders for the
    target path, so these have to be interpolated. Every value passed here is
    collector-controlled, and doubling embedded quotes keeps it safe anyway.
    """
    return "'" + str(value).replace("'", "''") + "'"


def to_table(rows: Iterable[dict[str, Any]], schema: pa.Schema) -> pa.Table:
    rows = list(rows)
    columns = {
        field.name: [row.get(field.name) for row in rows] for field in schema
    }
    return pa.table(columns, schema=schema)


def load_current_hashes() -> dict[str, tuple[str, str]]:
    """Return {cve_id: (content_hash, observed_at)} for every known record."""
    if not CURRENT_PATH.exists():
        return {}
    con = duckdb.connect()
    try:
        rows = con.execute(
            "SELECT cve_id, content_hash, observed_at FROM read_parquet(?)",
            [str(CURRENT_PATH)],
        ).fetchall()
    finally:
        con.close()
    return {row[0]: (row[1], row[2]) for row in rows}


def append_changes(rows: list[dict[str, Any]], run_date: date) -> Path | None:
    """Append a change-log partition for this run. Returns the path written."""
    if not rows:
        return None
    partition = CHANGES_DIR / f"dt={run_date.isoformat()}"
    partition.mkdir(parents=True, exist_ok=True)
    # Many runs can land on the same date, so name parts by run_id.
    run_id = rows[0]["run_id"]
    target = partition / f"part-{run_id}.parquet"
    pq.write_table(to_table(rows, CHANGE_SCHEMA), target, compression="zstd")
    log.info("Wrote %s change rows to %s", f"{len(rows):,}", target)
    return target


def upsert_current(rows: list[dict[str, Any]]) -> int:
    """Merge observations into state/current.parquet. Returns total row count."""
    if not rows:
        return 0
    incoming = to_table(rows, OBSERVATION_SCHEMA)

    con = duckdb.connect()
    # Write via a temp file so an interrupted run cannot truncate state.
    temp_path = CURRENT_PATH.with_suffix(".parquet.tmp")
    try:
        con.register("incoming", incoming)
        if CURRENT_PATH.exists():
            con.execute(
                "CREATE TABLE merged AS SELECT * FROM read_parquet(?)",
                [str(CURRENT_PATH)],
            )
            # Delete-then-insert rather than UPDATE: the incoming row is the
            # complete new truth for that CVE, so a column-by-column update
            # would just be a longer way of saying the same thing.
            con.execute(
                "DELETE FROM merged WHERE cve_id IN (SELECT cve_id FROM incoming)"
            )
            con.execute("INSERT INTO merged SELECT * FROM incoming")
        else:
            con.execute("CREATE TABLE merged AS SELECT * FROM incoming")

        total = con.execute("SELECT count(*) FROM merged").fetchone()[0]
        con.execute(
            f"COPY merged TO {sql_literal(temp_path)} "
            "(FORMAT PARQUET, COMPRESSION ZSTD)"
        )
    finally:
        con.close()

    temp_path.replace(CURRENT_PATH)
    log.info("state/current.parquet now holds %s records", f"{total:,}")
    return total
