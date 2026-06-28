{{
    config(
        materialized='incremental',
        unique_key='cve_id',
        incremental_strategy='merge',
        merge_update_columns=[
            'state',
            'date_updated',
            'date_reserved',
            'assigner_org_id',
            'raw_json',
            'loaded_at',
            'delta_tag'
        ]
    )
}}

SELECT
    cve_id,
    state,
    date_published,
    date_updated,
    date_reserved,
    assigner_org_id,
    raw_json,
    loaded_at,
    delta_tag
FROM {{ ref('stg_cve_raw') }}

{% if is_incremental() %}
-- On incremental runs, process:
--   1. CVEs updated since the last run (the common case).
--   2. RESERVED CVEs (date_updated IS NULL) whose loaded_at is more recent than
--      the latest RESERVED CVE already in the table — i.e. newly-loaded RESERVED
--      records only. Without this guard the entire RESERVED backlog would be
--      re-merged on every run even when nothing changed.
WHERE
    date_updated > (
        SELECT COALESCE(MAX(date_updated), '1970-01-01'::TIMESTAMP_TZ)
        FROM {{ this }}
    )
    OR (
        date_updated IS NULL
        AND loaded_at > (
            SELECT COALESCE(MAX(loaded_at), '1970-01-01'::TIMESTAMP_TZ)
            FROM {{ this }}
            WHERE date_updated IS NULL
        )
    )
{% endif %}
