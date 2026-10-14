# One identity for the scanner job: it discovers targets and writes reports.
#
# Per-project rather than shared across the platform: its Reader grant spans
# every target subscription, and its blob grant reaches the reports. Neither
# should be reachable from any other tenant's image.
resource "azurerm_user_assigned_identity" "this" {
  name                = module.naming.user_assigned_identity.name
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tags                = local.tags
}

# Reader on each target subscription: enough for Resource Graph to list
# container apps and their ingress FQDNs, and nothing more. The scan itself
# needs no Azure permission at all — it goes over the public internet like any
# other client.
#
# Whoever applies needs to be able to create role assignments at subscription
# scope (Owner or User Access Administrator) on every target subscription.
resource "azurerm_role_assignment" "identity_reader" {
  for_each = toset(local.target_subscription_ids)

  scope                = "/subscriptions/${each.value}"
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
  # Stated explicitly: without it the provider looks the principal up in the
  # directory, which fails intermittently on an identity created moments ago.
  principal_type = "ServicePrincipal"
}
