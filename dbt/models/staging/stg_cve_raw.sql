{{ config(materialized='view') }}

WITH raw AS (
    SELECT
        RAW_JSON:cveMetadata:cveId::VARCHAR                AS cve_id,
        RAW_JSON:cveMetadata:state::VARCHAR                AS state,
        RAW_JSON:cveMetadata:datePublished::TIMESTAMP_TZ   AS date_published,
        RAW_JSON:cveMetadata:dateUpdated::TIMESTAMP_TZ     AS date_updated,
        RAW_JSON:cveMetadata:dateReserved::TIMESTAMP_TZ    AS date_reserved,
        RAW_JSON:cveMetadata:assignerOrgId::VARCHAR        AS assigner_org_id,
        RAW_JSON                                           AS raw_json,
        LOADED_AT,
        DELTA_TAG
    FROM {{ source('cve_schema', 'CVE_RAW') }}
),

deduped AS (
    -- When the same CVE appears multiple times in CVE_RAW (e.g. reruns or
    -- overlapping deltas), keep only the record with the latest dateUpdated.
    SELECT
        *,
        ROW_NUMBER() OVER (
            PARTITION BY cve_id
            ORDER BY date_updated DESC NULLS LAST, LOADED_AT DESC
        ) AS rn
    FROM raw
    WHERE cve_id IS NOT NULL
)

SELECT
    cve_id,
    state,
    date_published,
    date_updated,
    date_reserved,
    assigner_org_id,
    raw_json,
    LOADED_AT AS loaded_at,
    DELTA_TAG AS delta_tag
FROM deduped
WHERE rn = 1
