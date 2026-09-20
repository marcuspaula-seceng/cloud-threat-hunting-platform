-- Detect console login anomalies
-- Failed logins, logins from new locations, logins without MFA
-- Same audit Marcus ran on AD: last logon, failed attempts, MFA status

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
WHERE eventtime > date_add('day', -7, now())
  AND eventname = 'ConsoleLogin'
  AND (
    errorcode = 'Failed authentication'
    OR json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No'
  )
ORDER BY eventtime DESC;
