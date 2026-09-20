-- Detect console login anomalies
-- Failed logins and logins without MFA; no location baseline is evaluated.
-- Review CloudTrail console-login result and MFA fields.

SELECT
    eventtime,
    useridentity.arn AS user_arn,
    sourceipaddress,
    json_extract_scalar(responseelements, '$.ConsoleLogin') AS login_result,
    json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa_used,
    json_extract_scalar(additionaleventdata, '$.LoginTo') AS login_destination,
    useragent,
    errorcode
FROM cloudtrail_logs
WHERE from_iso8601_timestamp(eventtime) > date_add('day', -7, now())
  AND eventname = 'ConsoleLogin'
  AND (
    errorcode = 'Failed authentication'
    OR json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No'
  )
ORDER BY eventtime DESC;
