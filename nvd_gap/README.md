# NVD enrichment-gap collector

Measures how much of the CVE corpus the NVD has actually enriched since its
risk-based triage policy took effect on **15 April 2026**, and keeps an
append-only change log so post-publication edits to CVE records can be diffed
later.

> **This product uses the NVD API but is not endorsed or certified by the NVD.**

## Why this exists

As of 15 April 2026 the NVD enriches only a subset of incoming CVEs — those in
CISA KEV, federal-use software, and EO 14028 critical software, an estimated
15–20% of annual volume. It also stopped issuing its own CVSS score whenever
the assigning CNA had already scored the record, and moved tens of thousands of
older records into a `Not Scheduled` status.

Consumers of vulnerability data therefore face a question that no free tool
currently answers: *for the CVEs published this month, how much usable
enrichment actually exists, and from whom?* This collector measures it.

## Commands

```bash
python -m collector probe --days 30   # sample recent publications, no state write
python -m collector baseline          # one-time full corpus crawl
python -m collector sync              # fetch lastModified changes, append change log
python -m collector rollup            # recompute gap metrics from current state
python -m collector status            # report on-disk state
```

`probe` is the sanity check behind every published number: it hits the API,
aggregates in memory, prints, and writes nothing.

## Storage layout

| Path | Contents | Rebuildable? |
|---|---|---|
| `data/state/current.parquet` | one row per CVE, latest observation | yes, from a full crawl |
| `data/changes/dt=*/part-*.parquet` | append-only change log with full JSON | **no** |
| `data/rollups/coverage_daily.parquet` | one row per cohort per run | yes |

The change log only accumulates going forward and cannot be backfilled from
any upstream source. **Back it up.** It is the one asset here with no
replacement cost of zero.

## Terms-of-use compliance

The NVD API [Terms of Use](https://nvd.nist.gov/developers/terms-of-use) shape
several design decisions:

- **Attribution.** The notice above is reproduced in the README and must appear
  prominently in any application or dashboard built on this data.
- **No implied endorsement.** The NVD name may identify the *source* of the
  data but must not appear in a way that implies endorsement. Consequence:
  the published product must not be *named* after the NVD, and must not use it
  in a domain. "NVD" belongs in the description, never the brand.
- **No false attribution of modified content.** Derived values must never be
  presented as NVD content. Every column in `OBSERVATION_SCHEMA` is therefore
  either verbatim from the API (`vuln_status`, `published`, `base_score`, …) or
  explicitly derived by this collector (`has_cpe`, `unscored`, `nvd_declined`,
  `cna_scored`). Any UI must keep that split visible.
- **Rate limits.** 5 requests per rolling 30s without a key, 50 with one. The
  client's delays (6.5s keyless, 0.8s keyed) stay inside both.
- **Incremental access.** The NVD asks consumers not to repeatedly re-pull the
  whole dataset. `baseline` runs once; `sync` fetches only `lastModified`
  windows thereafter.
- **Shared egress IPs.** The TOU notes rate limits apply per apparent IP, not
  per user. CI runners share egress IPs with many other NVD consumers, so an
  API key — which scopes the limit to the key — is required in practice for any
  scheduled run, not merely a speed optimisation.
- **No warranty.** The API is provided as-is with no continuity guarantee. Any
  commercial offering downstream of this must disclaim upstream availability
  rather than promise an SLA it does not control.

## API key

Request one at <https://nvd.nist.gov/developers/request-an-api-key>. The
activation link expires after 7 days. Keys are tied to a single requestor and
must not be shared.

The collector reads `NVD_API_KEY` from the environment and sends it as an HTTP
header, never as a query parameter, so it does not leak into URLs or logs.

```bash
export NVD_API_KEY=...          # or a GitHub Actions repository secret
```

## Requirements

Python 3.12, `pip install -r requirements.txt`. No warehouse, no credentials,
no cloud account. Override the data location with `NVD_GAP_DATA_DIR`.
