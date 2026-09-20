# Cloud Threat Hunting Platform

Centralized threat detection and hunting using AWS-native services. CloudTrail logs analyzed via Athena, WAF protecting edge, Macie scanning for sensitive data exposure, Security Hub aggregating findings — all automated with Terraform.

## Architecture

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

## Threat Hunting Queries

### Detect Unauthorized API Calls
```sql
SELECT eventTime, eventName, sourceIPAddress, userIdentity.arn, errorCode
FROM cloudtrail_logs
WHERE errorCode IN ('AccessDenied', 'UnauthorizedAccess')
AND eventTime > current_timestamp - interval '24' hour
ORDER BY eventTime DESC
LIMIT 100;
```

### Detect Console Login Without MFA
```sql
SELECT eventTime, userIdentity.userName, sourceIPAddress, responseElements
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
AND additionalEventData LIKE '%MFAUsed%No%'
ORDER BY eventTime DESC;
```

### Detect IAM Key Usage from Unusual IP
```sql
SELECT sourceIPAddress, userIdentity.accessKeyId, COUNT(*) as call_count
FROM cloudtrail_logs
WHERE eventTime > current_timestamp - interval '7' day
GROUP BY sourceIPAddress, userIdentity.accessKeyId
HAVING COUNT(*) > 100
ORDER BY call_count DESC;
```

## Structure

```
.
├── README.md
├── architecture.png
├── terraform/
│   ├── main.tf
│   ├── security-hub.tf            # Enable + configure Security Hub
│   ├── macie.tf                   # Macie classification jobs
│   ├── waf.tf                     # WAF WebACL + rule groups
│   ├── athena.tf                  # Workgroup + named queries
│   ├── s3-log-bucket.tf           # Centralized log storage
│   └── variables.tf
├── athena-queries/
│   ├── unauthorized-api-calls.sql
│   ├── console-login-no-mfa.sql
│   ├── unusual-ip-access.sql
│   ├── s3-public-access-changes.sql
│   ├── iam-policy-changes.sql
│   └── root-account-usage.sql
├── waf-rules/
│   ├── rate-limiting.json
│   ├── geo-restriction.json
│   ├── sql-injection-block.json
│   └── known-bad-ips.json
└── docs/
    ├── hunting-playbook.md        # Step-by-step investigation guide
    └── waf-tuning.md              # False positive handling
```

## Key Design Decisions

### Why Athena over Splunk/ELK
Athena queries S3 directly — no data ingestion pipeline, no cluster to manage, pay-per-query pricing. For threat hunting against CloudTrail logs, this is the most cost-effective approach at scale.

### Why Security Hub as Aggregator
Single pane of glass for GuardDuty, Macie, Config, IAM Access Analyzer, and Firewall Manager. CIS Benchmark and AWS Foundational Security Best Practices run automatically.

### Why WAF at Edge
Block known attack patterns (SQLi, XSS, bot traffic) before they reach application layer. Rate limiting prevents DDoS and brute force at the perimeter.

## Deployment

```bash
cd terraform/
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

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
