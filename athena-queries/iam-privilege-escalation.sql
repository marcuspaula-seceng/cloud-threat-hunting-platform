-- Detect IAM privilege escalation attempts
-- Review identity and policy changes; ARN exclusions are heuristics, not role verification.
-- Investigate whether each change was authorised and expected.

SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    useridentity.principalid AS principal_id,
    eventname,
    requestparameters,
    sourceipaddress,
    useragent
FROM cloudtrail_logs
WHERE from_iso8601_timestamp(eventtime) > date_add('hour', -24, now())
  AND eventname IN (
    'CreateRole',
    'CreateUser',
    'AttachRolePolicy',
    'AttachUserPolicy',
    'PutRolePolicy',
    'PutUserPolicy',
    'AddUserToGroup',
    'CreateAccessKey',
    'CreateLoginProfile',
    'UpdateAssumeRolePolicy',
    'PassRole'
  )
  AND useridentity.arn NOT LIKE '%/iamadmin%'
  AND useridentity.arn NOT LIKE '%:root'
ORDER BY eventtime DESC;
