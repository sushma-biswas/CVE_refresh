-- Singular test: returns rows only if duplicates exist (failure condition).
-- A passing test returns 0 rows.

SELECT
    cve_id,
    COUNT(*) AS cnt
FROM {{ ref('cve_records') }}
GROUP BY cve_id
HAVING cnt > 1
