# Supplies object_id for the deployer's read access to the reports.
data "azurerm_client_config" "current" {}

# Default scan scope when var.target_subscription_ids is empty.
data "azurerm_subscription" "current" {}

# The shared platform (jay-withers/azure-container-apps), resolved by name
# rather than by reading its Terraform state. No shared state credentials, and
# the coupling stays a convention.
#
# The consequence is that a plan against an environment the platform has not
# been applied to fails at plan time — which is why only dev exists here.
data "azurerm_container_app_environment" "platform" {
  name                = var.platform_environment_name
  resource_group_name = var.platform_resource_group_name
}

# The workspace the shared environment already ships console logs to. The
# scanner's per-target JSON lines land there with no wiring from this repo;
# it is looked up only so the findings alert in main.alerts.tf can query it.
data "azurerm_log_analytics_workspace" "platform" {
  name                = var.platform_log_analytics_workspace_name
  resource_group_name = var.platform_resource_group_name
}

# Findings alerts go to the same people as the platform's own alerts.
data "azurerm_monitor_action_group" "platform" {
  name                = var.platform_action_group_name
  resource_group_name = var.platform_resource_group_name
}
