-- Detect security group modifications
-- Rules opening 0.0.0.0/0 are the highest-signal case; inspect request parameters
-- to determine which rules changed, and review them against the approved baseline.

SELECT
    eventtime,
    useridentity.arn AS who_changed,
    eventname,
    requestparameters,
    sourceipaddress,
    awsregion
FROM cloudtrail_logs
WHERE from_iso8601_timestamp(eventtime) > date_add('hour', -24, now())
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
