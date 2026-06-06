resource "aws_cloudwatch_log_group" "audit" {
  name              = "/a2a-trust-poc/audit"
  retention_in_days = 30

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "mcp_server" {
  name              = "/a2a-trust-poc/mcp-server"
  retention_in_days = 7

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "admin_bootstrap" {
  name              = "/a2a-trust-poc/admin-bootstrap"
  retention_in_days = 7

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "demo_web" {
  name              = "/a2a-trust-poc/demo-web"
  retention_in_days = 7

  tags = local.common_tags
}

# CloudWatch Alarms for audit trail
resource "aws_cloudwatch_metric_alarm" "audit_empty" {
  alarm_name          = "a2a-trust-poc-audit-empty"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "IncomingLogEvents"
  namespace           = "AWS/Logs"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert if audit log has no entries"

  dimensions = {
    LogGroupName = aws_cloudwatch_log_group.audit.name
  }
}
