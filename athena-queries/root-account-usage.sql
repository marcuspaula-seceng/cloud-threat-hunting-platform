-- Detect ANY root account activity
-- Review root activity against documented, authorised root-only operations.
-- Activity is an investigation signal, not proof of compromise.

SELECT
    eventtime,
    eventname,
    eventsource,
    sourceipaddress,
    useragent,
    awsregion,
    errorcode
FROM cloudtrail_logs
WHERE from_iso8601_timestamp(eventtime) > date_add('day', -30, now())
  AND useridentity.type = 'Root'
ORDER BY eventtime DESC;
