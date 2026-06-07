resource "aws_kms_key" "secrets" {
  description             = "KMS key for a2a-trust-poc secrets encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = local.common_tags
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/a2a-trust-poc-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

resource "aws_secretsmanager_secret" "a2a_poc" {
  name                    = "a2a-trust-poc/secrets"
  description             = "Secrets for A2A Trust PoC (KMS encrypted)"
  kms_key_id              = aws_kms_key.secrets.id
  recovery_window_in_days = 7

  tags = local.common_tags
}

# NOTE: Secret value is created manually via AWS console or AWS CLI
# terraform apply will fail if secret value is not populated in AWS Secrets Manager
# After Terraform apply, populate the secret with:
# aws secretsmanager put-secret-value --secret-id a2a-trust-poc/secrets --secret-string '{"jwt_secret":"...","hmac_secret":"...","admin_api_key":"..."}'

output "kms_key_id" {
  value       = aws_kms_key.secrets.id
  description = "KMS key ID for secrets encryption"
}

output "secrets_manager_secret_name" {
  value       = aws_secretsmanager_secret.a2a_poc.name
  description = "Secrets Manager secret name"
}
