resource "google_logging_project_sink" "a2a_audit" {
  name                   = "a2a-trust-poc-audit-sink"
  destination            = "logging.googleapis.com/projects/${var.gcp_project_id}/logs/a2a-trust-poc-audit"
  filter                 = "resource.type = \"api\" AND severity >= DEFAULT"
  unique_writer_identity = true
}

resource "google_logging_project_sink" "a2a_events" {
  name                   = "a2a-trust-poc-events-sink"
  destination            = "logging.googleapis.com/projects/${var.gcp_project_id}/logs/a2a-trust-poc-events"
  filter                 = "resource.type = \"api\""
  unique_writer_identity = true
}

# Log bucket for audit trail
resource "google_logging_project_bucket_config" "audit" {
  project_id      = var.gcp_project_id
  location        = var.gcp_region
  bucket_id       = "a2a-trust-poc-audit"
  retention_days  = 30
  enable_analytics = true
}

# Log bucket for events
resource "google_logging_project_bucket_config" "events" {
  project_id      = var.gcp_project_id
  location        = var.gcp_region
  bucket_id       = "a2a-trust-poc-events"
  retention_days  = 7
  enable_analytics = false
}
