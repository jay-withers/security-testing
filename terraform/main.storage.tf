# Where scan reports land: HTML, JSON and Markdown per target, under
# <date>/<time>/<subscription>/<resource group>/<app>/, plus one summary.json
# per run.
#
# Reports are regenerable — the next run produces fresh ones — so unlike a
# store of record this carries no `prevent_destroy`, and a lifecycle policy
# expires them.
# tflint-ignore: azurerm_resources_missing_prevent_destroy
resource "azurerm_storage_account" "reports" {
  # checkov:skip=CKV_AZURE_206: LRS on purpose. The reports are rebuilt by the
  #   next scheduled run; geo-redundancy would protect nothing that matters.
  # checkov:skip=CKV_AZURE_59: public network access stays enabled — a job on a
  #   Consumption-only shared environment has neither a VNet to peer nor a
  #   static egress IP to allow.
  # checkov:skip=CKV_AZURE_33: no queues are used, so queue logging has nothing
  #   to log.
  # checkov:skip=CKV2_AZURE_1: platform-managed keys. A CMK needs a Key Vault
  #   key, rotation and an identity grant on it, for regenerable reports.
  # checkov:skip=CKV2_AZURE_33: no private endpoint, as above.
  # checkov:skip=CKV2_AZURE_47: public access as above.
  # `.name_unique`, not `.name`: storage account names are globally unique
  # across every Azure tenant, not just this subscription.
  name                = module.naming.storage_account.name_unique
  resource_group_name = data.azurerm_resource_group.this.name
  location            = data.azurerm_resource_group.this.location

  account_tier             = "Standard"
  account_kind             = "StorageV2"
  account_replication_type = "LRS"

  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  public_network_access           = "Enabled"

  # **Entra ID only.** No connection string and no SAS exists to leak, and RBAC
  # is the only way in. It also means `az storage blob` needs
  # `--auth-mode login`.
  shared_access_key_enabled = false

  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

  tags = local.tags
}

# tflint-ignore: azurerm_resources_missing_prevent_destroy
resource "azurerm_storage_container" "reports" {
  # checkov:skip=CKV2_AZURE_21: no blob read logging. It would land in the shared
  #   Log Analytics workspace, whose `daily_quota_gb` is split across every
  #   tenant on the platform — spent on recording that someone opened a report.
  name                  = "reports"
  storage_account_id    = azurerm_storage_account.reports.id
  container_access_type = "private"
}

resource "azurerm_storage_management_policy" "reports" {
  storage_account_id = azurerm_storage_account.reports.id

  rule {
    name    = "expire-reports"
    enabled = true

    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["${azurerm_storage_container.reports.name}/"]
    }

    actions {
      base_blob {
        delete_after_days_since_creation_greater_than = var.report_retention_days
      }
    }
  }
}

# The scanner writes reports through this. Scoped to the container rather than
# the account: the identity has no reason to reach anything else.
resource "azurerm_role_assignment" "identity_reports_contributor" {
  scope                = local.reports_container_scope
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
  principal_type       = "ServicePrincipal"
}

# The administrator can read the reports — which is what `make reports` does.
# Reader, not Contributor: nothing but the scanner should be writing here.
resource "azurerm_role_assignment" "deployer_reports_reader" {
  for_each = toset(concat([var.administrator_object_id], var.report_reader_object_ids))

  scope                = local.reports_container_scope
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = each.value
}
