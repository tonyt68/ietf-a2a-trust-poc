terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# Variables
variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "gcp_project_id" {
  description = "GCP project ID"
}

variable "gcp_region" {
  description = "GCP region"
  default     = "us-central1"
}

# Tags for all resources
locals {
  common_tags = {
    Project     = "A2A-Trust-PoC"
    Environment = "dev"
    IaC         = "Terraform"
  }
}

# Outputs
output "s3_bucket_name" {
  value       = aws_s3_bucket.events.id
  description = "S3 bucket for events"
}

output "dynamodb_table_name" {
  value       = aws_dynamodb_table.template_registry.name
  description = "DynamoDB Template Registry table"
}

output "cloudwatch_log_group" {
  value       = aws_cloudwatch_log_group.audit.name
  description = "CloudWatch Logs group for audit trail"
}
