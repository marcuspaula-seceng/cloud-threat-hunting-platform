terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = { Project = "cloud-threat-hunting", ManagedBy = "terraform" }
  }
}

# Athena workgroup for security hunting
resource "aws_athena_workgroup" "security" {
  name = "security-hunting"
  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"
      encryption_configuration { encryption_option = "SSE_S3" }
    }
  }
}

resource "aws_s3_bucket" "athena_results" {
  bucket_prefix = "security-athena-results-"
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudTrail table for Athena queries
resource "aws_glue_catalog_table" "cloudtrail" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.security.name

  table_type = "EXTERNAL_TABLE"
  parameters = {
    "projection.enabled"               = "true"
    "projection.logdate.type"          = "date"
    "projection.logdate.format"        = "yyyy/MM/dd"
    "projection.logdate.range"         = "2024/01/01,NOW"
    "projection.logdate.interval"      = "1"
    "projection.logdate.interval.unit" = "DAYS"
    "projection.region.type"           = "enum"
    "projection.region.values"         = var.aws_region
    "storage.location.template"        = "s3://${var.cloudtrail_bucket}/AWSLogs/${var.account_id}/CloudTrail/$${region}/$${logdate}/"
  }

  partition_keys {
    name = "region"
    type = "string"
  }

  partition_keys {
    name = "logdate"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${var.cloudtrail_bucket}/AWSLogs/${var.account_id}/CloudTrail/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    ser_de_info {
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"
    }

    columns {
      name = "eventversion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string>"
    }
    columns {
      name = "eventtime"
      type = "string"
    }
    columns {
      name = "eventsource"
      type = "string"
    }
    columns {
      name = "eventname"
      type = "string"
    }
    columns {
      name = "awsregion"
      type = "string"
    }
    columns {
      name = "sourceipaddress"
      type = "string"
    }
    columns {
      name = "useragent"
      type = "string"
    }
    columns {
      name = "errorcode"
      type = "string"
    }
    columns {
      name = "errormessage"
      type = "string"
    }
    columns {
      name = "requestparameters"
      type = "string"
    }
    columns {
      name = "responseelements"
      type = "string"
    }
    columns {
      name = "additionaleventdata"
      type = "string"
    }
  }
}

resource "aws_glue_catalog_database" "security" {
  name = "security_logs"
}

# GuardDuty
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  datasources {
    s3_logs { enable = true }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

# Security Hub with CIS benchmark
resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# SNS alerts by severity
resource "aws_sns_topic" "critical" { name = "security-alerts-critical" }
resource "aws_sns_topic" "high" { name = "security-alerts-high" }

resource "aws_sns_topic_subscription" "critical_email" {
  topic_arn = aws_sns_topic.critical.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge: GuardDuty high severity → SNS
resource "aws_cloudwatch_event_rule" "guardduty_critical" {
  name = "guardduty-critical-findings"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { severity = [{ numeric = [">=", 7] }] }
  })
}

resource "aws_cloudwatch_event_target" "critical_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_critical.name
  target_id = "critical-to-sns"
  arn       = aws_sns_topic.critical.arn
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}
variable "alert_email" { type = string }
variable "cloudtrail_bucket" { type = string }
variable "account_id" { type = string }
