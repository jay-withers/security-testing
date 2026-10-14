variable "project_name" {
  description = "Short name for this project, used by the naming module for every resource."
  type        = string
  default     = "sectest"

  validation {
    # Lowercase only (container apps reject uppercase), and short enough that
    # `caj-<project>-<env>-zap` fits the 32 characters container apps allow —
    # the naming module truncates silently rather than failing. At `sectest`
    # that job name is 19 of 32.
    condition     = can(regex("^[a-z][a-z0-9]{1,14}$", var.project_name))
    error_message = "project_name must be 2-15 lowercase alphanumerics starting with a letter."
  }
}

variable "tags" {
  description = "Tags merged over the defaults in locals.tf."
  type        = map(string)
  default     = {}
}

variable "report_reader_object_ids" {
  description = "Extra Entra object IDs granted Storage Blob Data Reader on the reports container. Whoever runs `terraform apply` is always included, so this is only for a second person or a second machine."
  type        = list(string)
  default     = []
}

# --- the shared platform ------------------------------------------------------
#
# Resolved by name rather than from the platform's Terraform state. These
# defaults match jay-withers/azure-container-apps at its own defaults; run
# `make outputs` there to confirm.

variable "platform_resource_group_name" {
  description = "Resource group holding the shared Container Apps environment, Log Analytics workspace and action group."
  type        = string
  default     = "rg-platform-dev"
}

variable "platform_environment_name" {
  description = "Name of the shared Container Apps environment the scanner job runs on."
  type        = string
  default     = "cae-platform-dev"
}

variable "platform_log_analytics_workspace_name" {
  description = "Name of the shared Log Analytics workspace the environment logs to. The findings alert queries it."
  type        = string
  default     = "log-platform-dev"
}

variable "platform_action_group_name" {
  description = "Name of the shared action group the findings alert notifies."
  type        = string
  default     = "mag-platform-dev"
}

# --- the scan -----------------------------------------------------------------

variable "target_subscription_ids" {
  description = "Subscription IDs to discover container apps in. The scanner's identity gets Reader on each. Empty means the subscription this is applied into."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.target_subscription_ids : can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", id))])
    error_message = "target_subscription_ids must contain subscription GUIDs."
  }
}

variable "passive_scan_cron_expression" {
  description = "When the passive scan of every app runs, in **UTC** — Container Apps jobs have no timezone setting. The default is 02:00 UTC daily: overnight under both GMT and BST."
  type        = string
  default     = "0 2 * * *"

  validation {
    condition     = can(regex("^\\S+(\\s+\\S+){4}$", trimspace(var.passive_scan_cron_expression)))
    error_message = "passive_scan_cron_expression must be a 5-field cron expression, e.g. \"0 2 * * *\"."
  }
}

variable "active_scan_cron_expression" {
  description = "When the active (attack) scan runs, in **UTC**. The default is 04:00 UTC on Sundays — two hours after that night's passive scan starts, which is that scan's full timeout, so the two never overlap on the same app."
  type        = string
  default     = "0 4 * * 0"

  validation {
    condition     = can(regex("^\\S+(\\s+\\S+){4}$", trimspace(var.active_scan_cron_expression)))
    error_message = "active_scan_cron_expression must be a 5-field cron expression, e.g. \"0 4 * * 0\"."
  }
}

variable "passive_scan_timeout_seconds" {
  description = "Upper bound on one whole passive run, across every target."
  type        = number
  default     = 7200

  validation {
    condition     = var.passive_scan_timeout_seconds > 0 && var.passive_scan_timeout_seconds <= 86400
    error_message = "passive_scan_timeout_seconds must be between 1 and 86400."
  }
}

variable "active_scan_timeout_seconds" {
  description = "Upper bound on one whole active run, across every target. Active scans take far longer per app than passive ones."
  type        = number
  default     = 21600

  validation {
    condition     = var.active_scan_timeout_seconds > 0 && var.active_scan_timeout_seconds <= 86400
    error_message = "active_scan_timeout_seconds must be between 1 and 86400."
  }
}

variable "scan_fail_on" {
  description = "Lowest ZAP alert risk that raises the findings alert: `Low`, `Medium` or `High`. Findings never fail the job itself — see main.alerts.tf."
  type        = string
  default     = "High"

  validation {
    condition     = contains(["Low", "Medium", "High"], var.scan_fail_on)
    error_message = "scan_fail_on must be one of: Low, Medium, High."
  }
}

variable "report_retention_days" {
  description = "Days scan reports are kept before the lifecycle policy deletes them."
  type        = number
  default     = 90

  validation {
    condition     = var.report_retention_days >= 1
    error_message = "report_retention_days must be at least 1."
  }
}
