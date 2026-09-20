# Cloud Threat Hunting Platform

AWS threat-hunting lab with seven Athena SQL files, a query runner and Terraform configuration for Athena/Glue, GuardDuty, Security Hub and alerting components. WAF and Macie integrations are design ideas; their resources are not included.

## Intended Architecture

```
  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │CloudTrail│  │ VPC Flow │  │   WAF    │  │  Macie   │
  │  Logs    │  │   Logs   │  │  Logs    │  │ Findings │
  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
       │              │              │              │
       └──────────────┼──────────────┘              │
                      ▼                             │
              ┌───────────────┐                     │
              │  S3 (Central  │                     │
              │  Log Bucket)  │                     │
              └───────┬───────┘                     │
                      ▼                             ▼
              ┌───────────────┐           ┌─────────────────┐
              │    Athena     │           │  Security Hub   │
              │  (SQL Query)  │           │  (Aggregation)  │
              └───────┬───────┘           └────────┬────────┘
                      │                            │
                      └────────────┬───────────────┘
                                   ▼
                           ┌──────────────┐
                           │  Dashboard   │
                           │  + Alerts    │
                           └──────────────┘
```

The diagram includes planned integrations. It is not a record of an end-to-end deployment.

## Threat Hunting Queries

### Detect Unauthorized API Calls
```sql
SELECT eventTime, eventName, sourceIPAddress, userIdentity.arn, errorCode
FROM cloudtrail_logs
WHERE errorCode IN ('AccessDenied', 'UnauthorizedAccess')
AND from_iso8601_timestamp(eventTime) > current_timestamp - interval '24' hour
ORDER BY eventTime DESC
LIMIT 100;
```

### Detect Console Login Without MFA
```sql
SELECT eventTime, userIdentity.arn, sourceIPAddress, responseElements
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
AND additionalEventData LIKE '%MFAUsed%No%'
ORDER BY eventTime DESC;
```

### Summarise Identity Activity by Source IP
```sql
SELECT sourceIPAddress, userIdentity.arn, COUNT(*) as call_count
FROM cloudtrail_logs
WHERE from_iso8601_timestamp(eventTime) > current_timestamp - interval '7' day
GROUP BY sourceIPAddress, userIdentity.arn
HAVING COUNT(*) > 100
ORDER BY call_count DESC;
```

The examples use fields declared by the current Glue schema. A high call count alone does not establish suspicious activity; compare with an expected baseline. The seven standalone queries parse in the Trino dialect and pass translated offline tests against synthetic records with that schema. This is not a recorded Athena query run.

## Structure

- `terraform/main.tf` — declared infrastructure components and input variables
- `scripts/run-hunt.sh` — query runner
- `athena-queries/cloudtrail-tampering.sql`
- `athena-queries/console-login-anomalies.sql`
- `athena-queries/iam-privilege-escalation.sql`
- `athena-queries/root-account-usage.sql`
- `athena-queries/s3-data-exfiltration.sql`
- `athena-queries/security-group-changes.sql`
- `athena-queries/unauthorized-api-calls.sql`

No WAF rules directory, Macie resource file, architecture image or additional `docs/` playbooks are included.

## Key Design Decisions

### Why Athena over Splunk/ELK
Athena queries S3 directly — no data ingestion pipeline, no cluster to manage, pay-per-query pricing. Query cost depends on data volume, partitioning and workload; no comparative cost benchmark is included.

### Why Security Hub as Aggregator
Single pane of glass for GuardDuty, Macie, Config, IAM Access Analyzer, and Firewall Manager. CIS Benchmark and AWS Foundational Security Best Practices run automatically.

### WAF at the Edge — Planned Integration
Block known attack patterns (SQLi, XSS, bot traffic) before they reach application layer. Rate limiting can help reduce abusive request volume. No WAF deployment is included here.

## Deployment and Validation Status

The invalid HCL separators and nested blocks have been corrected. The Glue table now declares `region` and `logdate` partition keys matching its projection settings and S3 location template; `eventtime` remains the CloudTrail data field. The seven SQL time filters convert that field from ISO 8601 text before timestamp comparisons.

Offline checks passed: Terraform syntax/formatting, HCL parsing and partition consistency, Trino-dialect SQL parsing, and translated synthetic SQL tests for expected matches and time-window exclusions. No provider-backed Terraform validation, plan, apply or Athena query run is demonstrated here.

Complete provider-backed validation and test the event delivery and queries in a dedicated lab account before use. AWS credentials, account IDs, log-bucket names and alert recipients must be supplied through an appropriate local configuration; do not commit secrets or real investigation data.

## References

- [AWS Threat Hunting with Athena](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [Security Hub Standards](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html)
- [AWS WAF Rule Groups](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-groups.html)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)

---

*Built with Terraform + Athena SQL | Serverless threat hunting*


---

## Classification

**Hands-on Lab** — part of the [`marcuspaula-security-portfolio`](https://github.com/marcuspaula-seceng/marcuspaula-security-portfolio) hub.

Laboratory and study material. The code here exists to learn a concept, not to run an operation. It is not production tooling.
