# IAM policy for services to read secrets from Secrets Manager
resource "aws_iam_policy" "read_secrets" {
  name        = "a2a-trust-poc-read-secrets"
  description = "Allow services to read a2a-trust-poc secrets from Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.a2a_poc.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.secrets.arn
      }
    ]
  })
}

# IAM policy for services to write to CloudWatch Logs
resource "aws_iam_policy" "write_logs" {
  name        = "a2a-trust-poc-write-logs"
  description = "Allow services to write to CloudWatch Logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          aws_cloudwatch_log_group.audit.arn,
          aws_cloudwatch_log_group.mcp_server.arn,
          aws_cloudwatch_log_group.admin_bootstrap.arn,
          aws_cloudwatch_log_group.demo_web.arn
        ]
      }
    ]
  })
}

# IAM policy for services to access S3
resource "aws_iam_policy" "s3_access" {
  name        = "a2a-trust-poc-s3-access"
  description = "Allow services to read/write S3 events"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.events.arn,
          "${aws_s3_bucket.events.arn}/*"
        ]
      }
    ]
  })
}

# IAM policy for services to access DynamoDB
resource "aws_iam_policy" "dynamodb_access" {
  name        = "a2a-trust-poc-dynamodb-access"
  description = "Allow services to read/write DynamoDB Template Registry"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Scan",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.template_registry.arn,
          "${aws_dynamodb_table.template_registry.arn}/index/*"
        ]
      }
    ]
  })
}
