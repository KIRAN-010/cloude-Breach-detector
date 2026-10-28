variable "region" {
  type    = string
  default = "ap-south-1"
}
variable "name" {
  type    = string
  default = "cloude-breach-lab"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,25}$", var.name))
    error_message = "Use 3-26 lowercase letters, digits or hyphens, starting with a letter."
  }
}
variable "owner" {
  type = string
}
variable "expiry" {
  type        = string
  description = "Review/cleanup date, YYYY-MM-DD; this tag does not automate deletion."
}
variable "collector_principal_arn" {
  type        = string
  description = "Exact pre-existing IAM role allowed to assume the read-only collector."
  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", var.collector_principal_arn))
    error_message = "Specify an exact IAM role ARN, not account root or wildcard."
  }
}
variable "collector_external_id" {
  type        = string
  description = "External ID used in the collector AWS profile."
  sensitive   = true
}
variable "monitored_bucket_arns" {
  type    = list(string)
  default = []
}
variable "monthly_budget_usd" {
  type    = string
  default = "15"
}
variable "budget_email" {
  type = string
}
