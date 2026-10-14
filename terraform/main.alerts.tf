# Findings, alerted on from the shared workspace.
#
# **Why the job exits 0 when it finds something.** The platform's
# workload-crashed alert fires on any job execution that fails
# (`BackoffLimitExceeded`), and means "this workload is broken". A scan that
# worked and found a High-risk alert is not that — so scan.py exits non-zero
# only when a scan itself failed, which the platform rule then catches for free,
# and reports findings as a `scan_finished` line with `over_threshold: true`,
# which this rule catches instead. Two different problems, two different alerts.
#
# Split on the target app, so a second app's findings are not masked by the
# first one's alert already firing.
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "findings" {
  name                = "alert-${var.project_name}-${var.environment}-findings"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  description         = "The DAST scanner found alerts at or above ${var.scan_fail_on} risk on a container app. The report path is in the alert payload."
  severity            = 2

  # Without this every evaluation re-notifies while the rows are still in the
  # window — see the platform's main.alerts.tf for the incident that taught it.
  auto_mitigation_enabled = true

  scopes                = [data.azurerm_log_analytics_workspace.platform.id]
  evaluation_frequency  = "PT15M"
  window_duration       = "PT30M"
  target_resource_types = ["Microsoft.OperationalInsights/workspaces"]

  criteria {
    # `union isfuzzy=true` plus an empty datatable, as in the platform's own
    # rules: the console-log table is created lazily on first ingestion, and a
    # plain reference fails rule creation on a workspace that has never seen
    # one. `source` is filtered on so another tenant's JSON logs that happen to
    # share an event name cannot trip this.
    query = <<-KQL
      union isfuzzy=true
        ContainerAppConsoleLogs_CL,
        (datatable(TimeGenerated: datetime, Log_s: string) [])
      | where Log_s has "scan_finished" and Log_s has "${local.log_source}"
      | extend e = parse_json(Log_s)
      | where tostring(e.source) == "${local.log_source}" and tostring(e.event) == "scan_finished" and tobool(e.over_threshold)
      | project TimeGenerated, Target = tostring(e.target), Url = tostring(e.url), Risks = tostring(e.risks), Report = tostring(e.report)
    KQL

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    dimension {
      name     = "Target"
      operator = "Include"
      values   = ["*"]
    }

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [data.azurerm_monitor_action_group.platform.id]
  }

  tags = local.tags
}
