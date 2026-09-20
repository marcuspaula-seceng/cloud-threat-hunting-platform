#!/bin/bash
# Run all threat hunting queries and generate summary report
# Like the Grafana monitoring dashboards Marcus built — but for CloudTrail
set -euo pipefail

WORKGROUP="${ATHENA_WORKGROUP:-security-hunting}"
OUTPUT_BUCKET="${ATHENA_OUTPUT:-s3://security-athena-results/}"
REPORT_FILE="hunt-report-$(date +%Y%m%d-%H%M).txt"

echo "============================================" | tee "$REPORT_FILE"
echo " AWS Threat Hunting Report" | tee -a "$REPORT_FILE"
echo " $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$REPORT_FILE"
echo "============================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

run_query() {
    local name=$1
    local file=$2
    echo "--- Running: $name ---" | tee -a "$REPORT_FILE"

    QUERY=$(cat "$file")
    EXECUTION_ID=$(aws athena start-query-execution \
        --query-string "$QUERY" \
        --work-group "$WORKGROUP" \
        --result-configuration "OutputLocation=$OUTPUT_BUCKET" \
        --query 'QueryExecutionId' --output text)

    # Wait for completion
    while true; do
        STATE=$(aws athena get-query-execution \
            --query-execution-id "$EXECUTION_ID" \
            --query 'QueryExecution.Status.State' --output text)
        case $STATE in
            SUCCEEDED) break ;;
            FAILED|CANCELLED)
                echo "  FAILED: $STATE" | tee -a "$REPORT_FILE"
                return 1 ;;
            *) sleep 2 ;;
        esac
    done

    # Get results count
    ROWS=$(aws athena get-query-results \
        --query-execution-id "$EXECUTION_ID" \
        --query 'length(ResultSet.Rows)' --output text)
    FINDINGS=$((ROWS - 1))  # minus header

    if [ "$FINDINGS" -gt 0 ]; then
        echo "  FINDINGS: $FINDINGS results" | tee -a "$REPORT_FILE"
    else
        echo "  CLEAN: No findings" | tee -a "$REPORT_FILE"
    fi
    echo "" | tee -a "$REPORT_FILE"
}

run_query "Unauthorized API Calls"     athena-queries/unauthorized-api-calls.sql
run_query "IAM Privilege Escalation"   athena-queries/iam-privilege-escalation.sql
run_query "S3 Data Exfiltration"       athena-queries/s3-data-exfiltration.sql
run_query "Security Group Changes"     athena-queries/security-group-changes.sql
run_query "CloudTrail Tampering"       athena-queries/cloudtrail-tampering.sql
run_query "Root Account Usage"         athena-queries/root-account-usage.sql
run_query "Console Login Anomalies"    athena-queries/console-login-anomalies.sql

echo "============================================" | tee -a "$REPORT_FILE"
echo " Report saved: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "============================================" | tee -a "$REPORT_FILE"
