output "log_bucket" {
  value = aws_s3_bucket.logs.id
}
output "trail_arn" {
  value = aws_cloudtrail.lab.arn
}
output "collector_role_arn" {
  value = aws_iam_role.collector.arn
}
output "coverage_manifest" {
  value = {
    account               = local.account
    management_regions    = "all supported regions"
    management_read_write = "all"
    global_service_events = true
    selected_data_buckets = var.monitored_bucket_arns
    raw_retention_days    = 30
    integrity_digests     = true
    integrity_validated   = false
  }
}
