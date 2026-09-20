-- Detect IAM privilege escalation attempts
-- Flags: non-admin users trying to create roles, attach policies, or modify permissions
-- In Marcus's AD experience: equivalent to a standard user trying to add themselves to Domain Admins

SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    useridentity.principalid AS principal_id,
    eventname,
    requestparameters,
    sourceipaddress,
    useragent
FROM cloudtrail_logs
WHERE eventtime > date_add('hour', -24, now())
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
