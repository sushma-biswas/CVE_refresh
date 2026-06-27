-- Singular test: returns rows only if any CVE ID does not match the standard
-- format CVE-YYYY-NNNNN (e.g. CVE-2024-12345). A passing test returns 0 rows.

SELECT cve_id
FROM {{ ref('cve_records') }}
WHERE NOT REGEXP_LIKE(cve_id, '^CVE-[0-9]{4}-[0-9]+$')
