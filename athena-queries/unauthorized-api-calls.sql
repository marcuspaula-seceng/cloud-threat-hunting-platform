-- Detect API calls from unauthorized IPs or outside business hours
-- Same concept as Grafana alert rules Marcus built at the independent lab
-- but applied to CloudTrail instead of infrastructure metrics

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
WHERE eventtime > date_add('hour', -24, now())
  AND errorcode IN ('AccessDenied', 'UnauthorizedAccess', 'Client.UnauthorizedAccess')
ORDER BY eventtime DESC
LIMIT 500;
