-- Find API calls returning selected authorisation errors.
-- This query does not validate source-IP allowlists or business hours.
-- Review the caller, operation and error in context.

SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    useridentity.accountid AS account_id,
    eventsource,
    eventname,
    sourceipaddress,
    awsregion,
    errorcode,
    errormessage
FROM cloudtrail_logs
WHERE from_iso8601_timestamp(eventtime) > date_add('hour', -24, now())
  AND errorcode IN ('AccessDenied', 'UnauthorizedAccess', 'Client.UnauthorizedAccess')
ORDER BY eventtime DESC
LIMIT 500;
