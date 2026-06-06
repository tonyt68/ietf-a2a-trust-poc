resource "aws_dynamodb_table" "template_registry" {
  name           = "a2a-trust-poc-template-registry"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "template_id"

  attribute {
    name = "template_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = local.common_tags
}

# Global secondary index for state-based queries
resource "aws_dynamodb_table" "template_registry_gsi" {
  depends_on = [aws_dynamodb_table.template_registry]

  name            = "a2a-trust-poc-template-registry-gsi"
  billing_mode    = "PAY_PER_REQUEST"
  hash_key        = "template_id"
  range_key       = "state"

  attribute {
    name = "template_id"
    type = "S"
  }

  attribute {
    name = "state"
    type = "S"
  }

  tags = local.common_tags
}
