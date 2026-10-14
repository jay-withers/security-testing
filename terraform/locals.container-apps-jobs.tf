locals {
  # Assembled by hand: `azurerm_storage_container` exports no Resource Manager
  # id, and its `id` is the data-plane URL, which a role assignment rejects.
  reports_container_scope = "${azurerm_storage_account.reports.id}/blobServices/default/containers/${azurerm_storage_container.reports.name}"

  # **A placeholder, not the scanner.** Terraform only needs an image to create
  # the job; `make deploy IMAGE_TAG=vX.Y.Z` puts the real one on, and the image
  # is under `ignore_changes`, so Terraform never touches it again. Microsoft's
  # quickstart job image prints a line and exits 0.
  #
  # **Run `make deploy` after any apply that creates or replaces the job** — the
  # first apply, and any change to a ForceNew argument such as
  # scan_cron_expression. A replaced job comes back on this placeholder, and
  # because it exits 0 nothing alerts: runs "succeed" and no scan happens.
  placeholder_image = "mcr.microsoft.com/k8se/quickstart-jobs:latest"

  container_cpu    = 1
  container_memory = "2Gi"

  # Subscriptions the scanner discovers container apps in (and gets Reader on).
  # Defaults to the subscription this is applied into.
  target_subscription_ids = length(var.target_subscription_ids) > 0 ? var.target_subscription_ids : [data.azurerm_subscription.current.subscription_id]

  # Stamped on every JSON log line scan.py writes, and filtered on by the
  # findings alert, so another tenant's logs can never match it.
  log_source = "sectest"

  scanner_env = {
    AZURE_CLIENT_ID         = azurerm_user_assigned_identity.this.client_id
    TARGET_SUBSCRIPTION_IDS = join(",", local.target_subscription_ids)
    REPORT_CONTAINER_URL    = "${azurerm_storage_account.reports.primary_blob_endpoint}${azurerm_storage_container.reports.name}"
    SCAN_FAIL_ON            = var.scan_fail_on
    ENVIRONMENT             = var.environment
    LOG_SOURCE              = local.log_source
  }
}
