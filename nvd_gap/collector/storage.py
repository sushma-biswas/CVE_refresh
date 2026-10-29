"""Parquet storage for observations, the change log, and daily rollups.

Three datasets, each with a distinct job:

  state/current.parquet          One row per CVE: the latest observation.
                                 Rebuildable from a full crawl at any time.

  changes/dt=.../part-*.parquet  Append-only. One row every time a record's
                                 content hash changes, carrying the full JSON.
                                 NOT rebuildable - this only accumulates
                                 going forward, which is precisely why it is
                                 worth something.

  rollups/coverage_daily.parquet One row per cohort per run: the gap metrics.

DuckDB does the set operations so this stays honest SQL rather than hand-rolled
merge logic in Python.

Ordering note: a sync writes the change log BEFORE updating state, because the
two writes are not one transaction and the asymmetry matters. State is
rebuildable and the change log is not, so a crash between them must risk a
duplicate rather than a loss. `append_changes` is therefore idempotent: it
drops rows whose (cve_id, content_hash) pair is already logged, so re-running
after a partial failure converges instead of double-counting.
"""
from __future__ import annotations

import logging
from datetime import date
from pathlib import Path
from typing import Any, Iterable

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from .config import CHANGES_DIR, ROLLUP_PATH, STATE_DIR

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
        ("in_queue", pa.bool_()),
        ("is_rejected", pa.bool_()),
        ("cvss_version", pa.string()),
        ("cvss_source", pa.string()),
        ("base_score", pa.float64()),
        ("base_severity", pa.string()),
        ("cwe_count", pa.int32()),
        ("reference_count", pa.int32()),
        ("description_length", pa.int32()),
        ("content_hash", pa.string()),
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

OBSERVATION_COLUMNS = [field.name for field in OBSERVATION_SCHEMA]


class SchemaMismatchError(RuntimeError):
    """Existing state on disk was written by a different schema version."""


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


def _parquet_columns(con: duckdb.DuckDBPyConnection, path: Path) -> list[str]:
    return (
        con.execute(f"SELECT * FROM read_parquet({sql_literal(path)}) LIMIT 0")
        .arrow()
        .schema.names
    )


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


def _change_log_glob() -> Path:
    return CHANGES_DIR / "dt=*" / "part-*.parquet"


def _logged_change_keys(con: duckdb.DuckDBPyConnection) -> set[tuple[str, str]]:
    """(cve_id, content_hash) pairs already present in the change log.

    This pair is the identity of an observation: the same record content
    observed twice is the same event, not two events.
    """
    if not any(CHANGES_DIR.glob("dt=*/part-*.parquet")):
        return set()
    rows = con.execute(
        "SELECT DISTINCT cve_id, content_hash FROM read_parquet"
        f"({sql_literal(_change_log_glob())})"
    ).fetchall()
    return {(row[0], row[1]) for row in rows}


def append_changes(rows: list[dict[str, Any]], run_date: date) -> Path | None:
    """Append a change-log partition, skipping events already logged.

    Idempotent by (cve_id, content_hash), so a re-run after a crash between
    the change-log write and the state update converges rather than
    double-counting. Returns the path written, or None if nothing was new.
    """
    if not rows:
        return None
    ensure_dirs()

    con = duckdb.connect()
    try:
        already_logged = _logged_change_keys(con)
    finally:
        con.close()

    fresh = [
        row
        for row in rows
        if (row["cve_id"], row["content_hash"]) not in already_logged
    ]
    skipped = len(rows) - len(fresh)
    if skipped:
        log.info(
            "Skipped %s change rows already in the log (idempotent re-run)",
            f"{skipped:,}",
        )
    if not fresh:
        return None

    partition = CHANGES_DIR / f"dt={run_date.isoformat()}"
    partition.mkdir(parents=True, exist_ok=True)
    # Many runs can land on the same date, so name parts by run_id.
    target = partition / f"part-{fresh[0]['run_id']}.parquet"
    pq.write_table(to_table(fresh, CHANGE_SCHEMA), target, compression="zstd")
    log.info("Wrote %s change rows to %s", f"{len(fresh):,}", target)
    return target


def upsert_current(rows: list[dict[str, Any]]) -> int:
    """Merge observations into state/current.parquet. Returns total row count."""
    if not rows:
        return 0
    incoming = to_table(rows, OBSERVATION_SCHEMA)
    column_list = ", ".join(OBSERVATION_COLUMNS)

    con = duckdb.connect()
    # Write via a temp file so an interrupted run cannot truncate state.
    temp_path = CURRENT_PATH.with_suffix(".parquet.tmp")
    try:
        con.register("incoming", incoming)
        if CURRENT_PATH.exists():
            # Refuse to merge into state written by a different schema. A
            # positional INSERT would otherwise either fail obscurely on an
            # added column or, far worse, silently shift every value into its
            # neighbour when a column is renamed or reordered.
            existing = _parquet_columns(con, CURRENT_PATH)
            if existing != OBSERVATION_COLUMNS:
                raise SchemaMismatchError(
                    f"{CURRENT_PATH} has columns {existing!r} but this build "
                    f"expects {OBSERVATION_COLUMNS!r}. Re-run `baseline "
                    "--force` to rebuild state; the change log is unaffected."
                )
            con.execute(
                "CREATE TABLE merged AS SELECT * FROM read_parquet(?)",
                [str(CURRENT_PATH)],
            )
            # Delete-then-insert rather than UPDATE: the incoming row is the
            # complete new truth for that CVE, so a column-by-column update
            # would just be a longer way of saying the same thing. Columns are
            # named explicitly on both sides so order never matters.
            con.execute(
                "DELETE FROM merged WHERE cve_id IN (SELECT cve_id FROM incoming)"
            )
            con.execute(
                f"INSERT INTO merged ({column_list}) "
                f"SELECT {column_list} FROM incoming"
            )
        else:
            con.execute(
                f"CREATE TABLE merged AS SELECT {column_list} FROM incoming"
            )

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
