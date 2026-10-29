"""Command line entry point for the NVD enrichment-gap collector.

  baseline   Full corpus crawl -> state/current.parquet. Run once.
  sync       Fetch lastModified changes and append to the change log.
  rollup     Recompute enrichment-gap metrics from current state.
  status     Report what is on disk.

Output is deliberately plain ASCII: this runs on a Windows console using the
cp1252 code page, where non-ASCII log output raises UnicodeEncodeError.
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import uuid
from collections import Counter
from datetime import date, datetime, timedelta, timezone

import duckdb
import pyarrow.parquet as pq

from . import __version__
from .config import CHANGES_DIR, MIN_AGE_HOURS, ROLLUP_PATH, SYNC_STATE_PATH
from .normalize import normalize_cve
from .sources import nvd
from .storage import (
    CURRENT_PATH,
    OBSERVATION_SCHEMA,
    append_changes,
    ensure_dirs,
    load_current_hashes,
    sql_literal,
    to_table,
    upsert_current,
)

log = logging.getLogger("collector")

BASELINE_BATCH_SIZE = 20_000

# The date NVD's risk-based triage policy took effect. Cohorts either side of
# it are the headline comparison this whole project exists to make.
POLICY_DATE = "2026-04-15"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _read_sync_state() -> dict:
    if SYNC_STATE_PATH.exists():
        return json.loads(SYNC_STATE_PATH.read_text(encoding="utf-8"))
    return {}


def _write_sync_state(state: dict) -> None:
    SYNC_STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- baseline


def cmd_baseline(args: argparse.Namespace) -> int:
    """Full crawl. Writes current.parquet directly, bypassing the merge path.

    The baseline does not populate the change log. The change log means
    "edits observed since we started watching", and inventing 300k synthetic
    'new' rows on day one would make every later metric lie.
    """
    if CURRENT_PATH.exists() and not args.force:
        log.error(
            "%s already exists. Use 'sync' to update, or --force to re-baseline.",
            CURRENT_PATH,
        )
        return 1

    ensure_dirs()
    observed_at = _now_iso()
    parts_dir = CURRENT_PATH.parent / "_baseline_parts"
    parts_dir.mkdir(parents=True, exist_ok=True)
    for stale in parts_dir.glob("*.parquet"):
        stale.unlink()

    batch: list[dict] = []
    part_index = 0
    total = 0

    def flush() -> None:
        nonlocal batch, part_index
        if not batch:
            return
        target = parts_dir / f"part-{part_index:05d}.parquet"
        pq.write_table(to_table(batch, OBSERVATION_SCHEMA), target, compression="zstd")
        part_index += 1
        batch = []

    for cve in nvd.crawl_all():
        batch.append(normalize_cve(cve, observed_at))
        total += 1
        if len(batch) >= BASELINE_BATCH_SIZE:
            flush()
        if args.limit and total >= args.limit:
            log.info("Stopping early at --limit %s", f"{args.limit:,}")
            break
    flush()

    if total == 0:
        log.error("No records returned - refusing to write an empty baseline")
        return 1

    # Union the parts into one file. Deduplicate defensively: paginating a
    # live dataset can return the same CVE twice if records shift between
    # pages, and current.parquet must hold exactly one row per CVE.
    con = duckdb.connect()
    temp_path = CURRENT_PATH.with_suffix(".parquet.tmp")
    parts_glob = sql_literal(parts_dir / "*.parquet")
    target = sql_literal(temp_path)
    try:
        con.execute(
            f"""
            COPY (
                SELECT * EXCLUDE (rn) FROM (
                    SELECT *, row_number() OVER (
                        PARTITION BY cve_id ORDER BY last_modified DESC
                    ) AS rn
                    FROM read_parquet({parts_glob})
                ) WHERE rn = 1
            ) TO {target} (FORMAT PARQUET, COMPRESSION ZSTD)
            """
        )
    finally:
        con.close()
    temp_path.replace(CURRENT_PATH)

    # Best-effort. State is already committed above, so a leftover file in
    # here must never turn a successful baseline into a failed job - in CI
    # that would discard the cache and force the whole crawl again.
    shutil.rmtree(parts_dir, ignore_errors=True)

    _write_sync_state({"last_sync_utc": observed_at, "baseline_records": total})
    log.info("Baseline complete: %s records fetched", f"{total:,}")
    return 0


# -------------------------------------------------------------------- sync


def cmd_sync(args: argparse.Namespace) -> int:
    """Fetch records modified since the last sync and log what changed."""
    if not CURRENT_PATH.exists():
        log.error("No baseline found. Run 'baseline' first.")
        return 1

    ensure_dirs()
    state = _read_sync_state()

    if args.since:
        start = datetime.fromisoformat(args.since)
    elif args.days:
        start = datetime.now(timezone.utc) - timedelta(days=args.days)
    elif state.get("last_sync_utc"):
        start = datetime.fromisoformat(state["last_sync_utc"])
    else:
        start = datetime.now(timezone.utc) - timedelta(days=1)

    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    # Overlap by an hour: NVD's lastModified ordering is not perfectly
    # reliable at the boundary, and a missed record is unrecoverable while a
    # duplicate is free (the content hash makes re-observation a no-op).
    start -= timedelta(hours=1)
    end = datetime.now(timezone.utc)

    known = load_current_hashes()
    run_id = uuid.uuid4().hex[:12]
    observed_at = _now_iso()

    changes: list[dict] = []
    observations: list[dict] = []
    seen = 0
    unchanged = 0

    for cve in nvd.crawl_modified(start, end):
        seen += 1
        row = normalize_cve(cve, observed_at)
        prev = known.get(row["cve_id"])

        if prev and prev[0] == row["content_hash"]:
            unchanged += 1
            continue

        observations.append(row)
        changes.append(
            dict(
                row,
                change_type="modified" if prev else "new",
                prev_content_hash=prev[0] if prev else None,
                prev_observed_at=prev[1] if prev else None,
                run_id=run_id,
                raw_json=json.dumps(cve, sort_keys=True, separators=(",", ":")),
            )
        )

    log.info(
        "Scanned %s records: %s changed, %s unchanged",
        f"{seen:,}",
        f"{len(changes):,}",
        f"{unchanged:,}",
    )

    append_changes(changes, date.today())
    upsert_current(observations)
    _write_sync_state(
        {
            "last_sync_utc": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "last_run_id": run_id,
            "last_seen": seen,
            "last_changed": len(changes),
        }
    )
    return 0


# ------------------------------------------------------------------ rollup

_ROLLUP_SQL = """
WITH base AS (
    SELECT
        *,
        TRY_CAST(published AS TIMESTAMP) AS published_ts
    FROM read_parquet(?)
),
cohorts AS (
    SELECT 'all' AS cohort, * FROM base
    UNION ALL
    -- The two headline cohorts. A minimum age is applied because deferral is
    -- recorded at intake and partly reclassified afterwards, so a window
    -- holding very fresh records overstates it. See config.MIN_AGE_HOURS.
    SELECT 'settled_30d' AS cohort, * FROM base
      WHERE published_ts >= CAST(now() AS TIMESTAMP) - INTERVAL 30 DAY
        AND published_ts <  CAST(now() AS TIMESTAMP) - INTERVAL {min_age} HOUR
    UNION ALL
    SELECT 'settled_90d' AS cohort, * FROM base
      WHERE published_ts >= CAST(now() AS TIMESTAMP) - INTERVAL 90 DAY
        AND published_ts <  CAST(now() AS TIMESTAMP) - INTERVAL {min_age} HOUR
    UNION ALL
    -- Deliberately kept and published: the excluded cohort is the evidence
    -- that the exclusion is honest rather than convenient. Bounded above by
    -- now, so a record carrying a future publication date cannot park here
    -- permanently, invisible to every settled window.
    SELECT 'fresh' AS cohort, * FROM base
      WHERE published_ts >= CAST(now() AS TIMESTAMP) - INTERVAL {min_age} HOUR
        AND published_ts <= CAST(now() AS TIMESTAMP)
    UNION ALL
    SELECT 'published_30d' AS cohort, * FROM base
      WHERE published_ts >= CAST(now() AS TIMESTAMP) - INTERVAL 30 DAY
        AND published_ts <= CAST(now() AS TIMESTAMP)
    UNION ALL
    SELECT 'published_90d' AS cohort, * FROM base
      WHERE published_ts >= CAST(now() AS TIMESTAMP) - INTERVAL 90 DAY
        AND published_ts <= CAST(now() AS TIMESTAMP)
    UNION ALL
    SELECT 'post_policy' AS cohort, * FROM base
      WHERE published_ts >= TIMESTAMP '{policy} 00:00:00'
    UNION ALL
    SELECT 'pre_policy' AS cohort, * FROM base
      WHERE published_ts < TIMESTAMP '{policy} 00:00:00'
),
agg AS (
    SELECT
        cohort,
        count(*)                                        AS records,
        count_if(NOT has_cpe)                           AS no_cpe,
        count_if(unscored)                              AS unscored,
        count_if(nvd_scored)                            AS nvd_scored,
        count_if(cna_scored AND NOT nvd_scored)         AS cna_only,
        count_if(nvd_declined)                          AS nvd_declined,
        count_if(in_queue)                              AS in_queue,
        count_if(is_rejected)                           AS rejected
    FROM cohorts
    GROUP BY cohort
),
-- Every cohort is emitted even when it matches nothing. GROUP BY on its own
-- drops an empty cohort entirely, so a stale baseline would silently remove
-- the fresh row - the one the dashboard leans on to show what it excluded.
names AS (
    SELECT cohort FROM (VALUES
        ('all'), ('settled_30d'), ('settled_90d'), ('fresh'),
        ('published_30d'), ('published_90d'), ('post_policy'), ('pre_policy')
    ) AS v(cohort)
)
SELECT
    CAST(? AS DATE)                                     AS run_date,
    names.cohort                                        AS cohort,
    COALESCE(agg.records, 0)                            AS records,
    COALESCE(agg.no_cpe, 0)                             AS no_cpe,
    COALESCE(agg.unscored, 0)                           AS unscored,
    COALESCE(agg.nvd_scored, 0)                         AS nvd_scored,
    COALESCE(agg.cna_only, 0)                           AS cna_only,
    COALESCE(agg.nvd_declined, 0)                       AS nvd_declined,
    COALESCE(agg.in_queue, 0)                           AS in_queue,
    COALESCE(agg.rejected, 0)                           AS rejected,
    -- Shares stay NULL for an empty cohort rather than 0: a share of nothing
    -- is not zero, and a zero here would read as "none of them", a claim the
    -- data does not support.
    round(100.0 * agg.no_cpe / agg.records, 2)          AS pct_no_cpe,
    round(100.0 * agg.unscored / agg.records, 2)        AS pct_unscored,
    round(100.0 * agg.nvd_scored / agg.records, 2)      AS pct_nvd_scored
FROM names
LEFT JOIN agg ON agg.cohort = names.cohort
ORDER BY names.cohort
"""


def cmd_rollup(args: argparse.Namespace) -> int:
    if not CURRENT_PATH.exists():
        log.error("No baseline found. Run 'baseline' first.")
        return 1

    ensure_dirs()
    run_date = date.today()
    sql = _ROLLUP_SQL.format(policy=POLICY_DATE, min_age=MIN_AGE_HOURS)

    con = duckdb.connect()
    temp_path = ROLLUP_PATH.with_suffix(".parquet.tmp")
    try:
        fresh = con.execute(sql, [str(CURRENT_PATH), run_date.isoformat()]).arrow()
        con.register("fresh", fresh)
        if ROLLUP_PATH.exists():
            con.execute(
                "CREATE TABLE merged AS SELECT * FROM read_parquet(?)",
                [str(ROLLUP_PATH)],
            )
            con.execute(
                "DELETE FROM merged WHERE run_date = CAST(? AS DATE)",
                [run_date.isoformat()],
            )
            con.execute("INSERT INTO merged SELECT * FROM fresh")
        else:
            con.execute("CREATE TABLE merged AS SELECT * FROM fresh")

        con.execute(
            f"COPY merged TO {sql_literal(temp_path)} "
            "(FORMAT PARQUET, COMPRESSION ZSTD)"
        )
        printable = con.execute(
            "SELECT cohort, records, pct_no_cpe, pct_unscored, pct_nvd_scored"
            " FROM fresh ORDER BY cohort"
        ).fetchall()
    finally:
        con.close()
    temp_path.replace(ROLLUP_PATH)

    header = (
        f"{'cohort':<16}{'records':>10}{'no CPE %':>11}"
        f"{'unscored %':>12}{'NVD scored %':>14}"
    )
    def share(value) -> str:
        """Render a share, or a dash where the cohort matched nothing.

        An empty cohort carries NULL rather than 0, so printing it as a number
        would both crash and, once formatted, claim a 0% that no data supports.
        """
        return "-" if value is None else f"{value:.2f}"

    print()
    print(header)
    print("-" * len(header))
    for cohort, records, no_cpe, unscored, nvd_scored in printable:
        print(
            f"{cohort:<16}{records:>10,}"
            f"{share(no_cpe):>11}{share(unscored):>12}{share(nvd_scored):>14}"
        )
    print()
    return 0


# ------------------------------------------------------------------- probe


def _parse_iso(value: str, flag: str) -> datetime:
    """Parse an ISO date or timestamp, naming the flag and value on failure."""
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(
            f"{flag} expects an ISO date such as 2024-01-01, not {value!r}"
        ) from None


# Reported apart, never summed: "declined" is a decision the NVD has made and
# "in queue" is a backlog that may still clear. Collapsing them overstates the
# permanent gap, badly so in a short window where most records are days old.
_PROBE_MEASURES = (
    ("no CPE match", lambda r: not r["has_cpe"]),
    ("no score at all", lambda r: r["unscored"]),
    ("NVD scored", lambda r: r["nvd_scored"]),
    ("CNA scored only", lambda r: r["cna_scored"] and not r["nvd_scored"]),
    ("NVD declined", lambda r: r["nvd_declined"]),
    ("still in queue", lambda r: r["in_queue"]),
    ("rejected", lambda r: r["is_rejected"]),
)


def cmd_probe(args: argparse.Namespace) -> int:
    """Sample a publication window and report the gap, without touching state.

    This is the sanity check behind every headline number the dashboard shows.
    If the enrichment gap is not visible here, it is not real, and no amount of
    presentation will make it so. Which is why --min-age-hours defaults to the
    floor the dashboard publishes with: reproducing a published figure has to be
    the zero-argument case, or the check disagrees with what it is checking.

    Counts accumulate as the crawl runs rather than collecting into a list. An
    explicit --published-from can reach the whole corpus - over 400,000 records
    - and holding every one of them would cost gigabytes for an answer that is
    only ever a handful of totals.
    """
    now = datetime.now(timezone.utc)
    try:
        if args.published_from:
            # An explicit range, for comparing a historical cohort against a
            # figure someone else published about that same cohort.
            start = _parse_iso(args.published_from, "--published-from")
            end = (
                _parse_iso(args.published_to, "--published-to")
                if args.published_to
                else now - timedelta(hours=args.min_age_hours)
            )
        else:
            end = now - timedelta(hours=args.min_age_hours)
            start = now - timedelta(days=args.days)
    except ValueError as exc:
        log.error("%s", exc)
        return 1

    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)

    if end <= start:
        log.error(
            "Empty window: %s to %s. With --min-age-hours %s, --days must "
            "exceed %.1f.",
            start.isoformat(),
            end.isoformat(),
            args.min_age_hours,
            args.min_age_hours / 24,
        )
        return 1

    observed_at = _now_iso()
    counts: Counter = Counter()
    statuses: Counter = Counter()
    total = 0

    for cve in nvd.crawl_published(start, end):
        row = normalize_cve(cve, observed_at)
        total += 1
        for label, predicate in _PROBE_MEASURES:
            if predicate(row):
                counts[label] += 1
        statuses[row["vuln_status"]] += 1
        if args.limit and total >= args.limit:
            log.info("Stopping early at --limit %s", f"{args.limit:,}")
            break

    if total == 0:
        log.error(
            "No records published between %s and %s",
            start.isoformat(),
            end.isoformat(),
        )
        return 1

    # Resolved timestamps, not dates: a date alone reads as a whole inclusive
    # day, and the end bound is an instant.
    stamp = "%Y-%m-%d %H:%M UTC"
    print()
    print(
        f"Sample: {total:,} CVEs published "
        f"{start.strftime(stamp)} to {end.strftime(stamp)}"
    )
    print("-" * 46)
    for label, _ in _PROBE_MEASURES:
        n = counts[label]
        print(f"  {label:<22}{n:>8,}{100.0 * n / total:>9.1f}%")
    print()
    print("vulnStatus breakdown:")
    for status, n in statuses.most_common():
        print(f"  {(status or '(empty)'):<22}{n:>8,}{100.0 * n / total:>9.1f}%")
    print()
    return 0


# ------------------------------------------------------------------ status


def cmd_status(args: argparse.Namespace) -> int:
    print(f"collector version : {__version__}")
    print(f"current.parquet   : {CURRENT_PATH if CURRENT_PATH.exists() else 'absent'}")
    if CURRENT_PATH.exists():
        con = duckdb.connect()
        try:
            count, newest = con.execute(
                "SELECT count(*), max(last_modified) FROM read_parquet(?)",
                [str(CURRENT_PATH)],
            ).fetchone()
        finally:
            con.close()
        size_mb = CURRENT_PATH.stat().st_size / 1_048_576
        print(f"  records         : {count:,}")
        print(f"  newest lastMod  : {newest}")
        print(f"  size            : {size_mb:.1f} MB")

    parts = sorted(CHANGES_DIR.glob("dt=*/part-*.parquet"))
    print(f"change log parts  : {len(parts)}")
    if parts:
        con = duckdb.connect()
        try:
            rows = con.execute(
                "SELECT count(*) FROM read_parquet(?)",
                [str(CHANGES_DIR / "dt=*" / "part-*.parquet")],
            ).fetchone()[0]
        finally:
            con.close()
        print(f"  change rows     : {rows:,}")
        print(f"  earliest part   : {parts[0].parent.name}")
    print(f"sync state        : {json.dumps(_read_sync_state(), indent=2)}")
    return 0


# -------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="collector", description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p_baseline = sub.add_parser("baseline", help="full corpus crawl")
    p_baseline.add_argument(
        "--limit", type=int, default=0, help="stop after N records (smoke test)"
    )
    p_baseline.add_argument(
        "--force", action="store_true", help="overwrite existing state"
    )
    p_baseline.set_defaults(func=cmd_baseline)

    p_sync = sub.add_parser("sync", help="fetch and log modifications")
    p_sync.add_argument("--since", help="ISO timestamp to sync from")
    p_sync.add_argument("--days", type=int, help="sync the last N days")
    p_sync.set_defaults(func=cmd_sync)

    p_probe = sub.add_parser("probe", help="sample recent publications, no state write")
    p_probe.add_argument("--days", type=int, default=30, help="lookback window")
    p_probe.add_argument(
        "--min-age-hours",
        type=int,
        default=MIN_AGE_HOURS,
        help=(
            "exclude records younger than this; defaults to the floor the "
            f"dashboard publishes with ({MIN_AGE_HOURS}), so reproducing a "
            "published figure needs no flags. Pass 0 for the raw window, "
            "which is biased toward Deferred."
        ),
    )
    p_probe.add_argument(
        "--published-from", help="ISO date; overrides --days for an explicit cohort"
    )
    p_probe.add_argument(
        "--published-to", help="ISO date; defaults to now minus --min-age-hours"
    )
    p_probe.add_argument("--limit", type=int, default=0, help="stop after N records")
    p_probe.set_defaults(func=cmd_probe)

    p_rollup = sub.add_parser("rollup", help="recompute gap metrics")
    p_rollup.set_defaults(func=cmd_rollup)

    p_status = sub.add_parser("status", help="report on-disk state")
    p_status.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
