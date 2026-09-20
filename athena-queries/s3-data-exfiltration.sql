-- Detect potential S3 data exfiltration
-- Large volume downloads, access from new IPs, or unusual hours
-- GDPR compliance: unauthorized data access must be detected within 72 hours

SELECT
    useridentity.arn AS caller_arn,
    sourceipaddress,
    COUNT(*) AS request_count,
    SUM(CAST(json_extract_scalar(additionaleventdata, '$.bytesTransferredOut') AS BIGINT)) AS bytes_out,
    array_agg(DISTINCT requestparameters) AS buckets_accessed,
    MIN(eventtime) AS first_access,
    MAX(eventtime) AS last_access
FROM cloudtrail_logs
WHERE eventtime > date_add('hour', -24, now())
  AND eventsource = 's3.amazonaws.com'
  AND eventname IN ('GetObject', 'SelectObjectContent')
GROUP BY useridentity.arn, sourceipaddress
HAVING COUNT(*) > 100
   OR SUM(CAST(json_extract_scalar(additionaleventdata, '$.bytesTransferredOut') AS BIGINT)) > 1073741824  -- 1GB
ORDER BY bytes_out DESC;
