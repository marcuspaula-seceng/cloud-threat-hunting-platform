-- Detect CloudTrail tampering — attacker trying to cover tracks
-- If someone stops logging, that IS the incident
-- Priority: CRITICAL — alert immediately

SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    eventname,
    requestparameters,
    sourceipaddress,
    errorcode
FROM cloudtrail_logs
WHERE eventtime > date_add('day', -7, now())
  AND eventsource = 'cloudtrail.amazonaws.com'
  AND eventname IN (
    'StopLogging',
    'DeleteTrail',
    'UpdateTrail',
    'PutEventSelectors',
    'DeleteEventDataStore'
  )
ORDER BY eventtime DESC;
