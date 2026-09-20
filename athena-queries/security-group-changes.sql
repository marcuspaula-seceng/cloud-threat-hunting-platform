-- Detect security group modifications
-- Especially adding 0.0.0.0/0 rules — the #1 misconfiguration in AWS
-- Same as firewall rule audits Marcus ran quarterly at the independent lab

SELECT
    eventtime,
    useridentity.arn AS who_changed,
    eventname,
    requestparameters,
    sourceipaddress,
    awsregion
FROM cloudtrail_logs
WHERE eventtime > date_add('hour', -24, now())
  AND eventsource = 'ec2.amazonaws.com'
  AND eventname IN (
    'AuthorizeSecurityGroupIngress',
    'AuthorizeSecurityGroupEgress',
    'RevokeSecurityGroupIngress',
    'RevokeSecurityGroupEgress',
    'CreateSecurityGroup',
    'DeleteSecurityGroup'
  )
ORDER BY eventtime DESC;
