-- Detect potential S3 data exfiltration
-- High request or byte counts grouped by caller and source IP.
-- Thresholds below are laboratory heuristics, not compliance guarantees.

SELECT
    useridentity.arn AS caller_arn,
    sourceipaddress,
    COUNT(*) AS request_count,
    SUM(CAST(json_extract_scalar(additionaleventdata, '$.bytesTransferredOut') AS BIGINT)) AS bytes_out,
    array_agg(DISTINCT requestparameters) AS buckets_accessed,
    MIN(eventtime) AS first_access,
    MAX(eventtime) AS last_access
FROM cloudtrail_logs
WHERE from_iso8601_timestamp(eventtime) > date_add('hour', -24, now())
  AND eventsource = 's3.amazonaws.com'
  AND eventname IN ('GetObject', 'SelectObjectContent')
GROUP BY useridentity.arn, sourceipaddress
HAVING COUNT(*) > 100
   OR SUM(CAST(json_extract_scalar(additionaleventdata, '$.bytesTransferredOut') AS BIGINT)) > 1073741824  -- 1GB
ORDER BY bytes_out DESC;
