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
-- On incremental runs, only process CVEs updated since the last run.
-- date_updated IS NULL guard catches RESERVED records with no update timestamp.
WHERE
    date_updated > (
        SELECT COALESCE(MAX(date_updated), '1970-01-01'::TIMESTAMP_TZ)
        FROM {{ this }}
    )
    OR date_updated IS NULL
{% endif %}
