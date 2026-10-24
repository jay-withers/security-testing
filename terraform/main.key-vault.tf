# The digest's two secrets, read by scan.py at the end of every run. Mirrors
# jay-withers/finances' main.key-vault.tf; the reasoning behind each setting is
# there too. Because the vault holds only this project's secrets, the
# identity's grant can be vault-wide without widening anything.
#
# Both are set by hand (`make secrets`), and Terraform manages neither:
#
#   RESEND-API-KEY   sends the digest
#   DIGEST-EMAIL-TO  comma-separated recipients; absent means the digest skips
#
# No `prevent_destroy`, for the same reason purge protection is off: both
# secrets are re-set in a minute, and a destroy should free the name.
# tflint-ignore: azurerm_resources_missing_prevent_destroy
resource "azurerm_key_vault" "this" {
  # checkov:skip=CKV_AZURE_42: purge protection deliberately off — see below.
  # checkov:skip=CKV_AZURE_110: same.
  # checkov:skip=CKV_AZURE_109: no network ACLs — see CKV_AZURE_189.
  # checkov:skip=CKV_AZURE_189: public access stays enabled. Restricting it needs a
  #   private endpoint (a standing monthly cost, and the shared environment has
  #   no VNet) or a static egress IP a Consumption job does not have.
  # checkov:skip=CKV2_AZURE_32: no private endpoint, as above.
  # `.name_unique`: vault names are global across every Azure tenant, and
  # finances' first apply collided on the plain `.name`.
  name                = module.naming.key_vault.name_unique
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = true

  # Off so `terraform destroy` really removes it rather than leaving a
  # soft-deleted vault holding a globally unique name. Paired with
  # `purge_soft_delete_on_destroy` in versions.tf.
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  # Stated rather than defaulted, because the skip above claims it.
  public_network_access_enabled = true

  tags = local.tags
}

resource "azurerm_role_assignment" "identity_secrets_user" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
  # Stated explicitly: without it the provider looks the principal up in the
  # directory, which fails intermittently on an identity created moments ago.
  principal_type = "ServicePrincipal"
}

# So the administrator can set the two secrets. No `azurerm_key_vault_secret`:
# a secret value belongs in neither source nor state. Not "whoever applies":
# cd-terraform applies as the pipeline identity, which would move this grant
# to itself on every run, and cannot write role assignments.
resource "azurerm_role_assignment" "deployer_secrets_officer" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = var.administrator_object_id
}
