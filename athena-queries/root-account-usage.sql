-- Detect ANY root account activity
-- Root should NEVER be used in production — Marcus enforced this via SCP at the independent lab
-- Same principle as disabling local admin in AD environments

SELECT
    eventtime,
    eventname,
    eventsource,
    sourceipaddress,
    useragent,
    awsregion,
    errorcode
FROM cloudtrail_logs
WHERE eventtime > date_add('day', -30, now())
  AND useridentity.type = 'Root'
ORDER BY eventtime DESC;
