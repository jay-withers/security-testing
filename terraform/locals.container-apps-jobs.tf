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
  # first apply, and any change to a ForceNew argument such as a job's trigger
  # type (scheduled or manual; a new cron expression is in place). A replaced job comes back on this placeholder, and
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

  # One job per profile, same image. Passive is every app, weekly, never
  # attacks anything, and ends by emailing the digest (src/sectest/digest.py).
  # Weekly rather than nightly because passive findings change when apps are
  # deployed, not overnight, and every run wakes each scale-to-zero app and
  # lands in the shared workspace's HTTP logs; `make scan` covers a deploy
  # worth checking sooner. Active sends real attack payloads to every app that hasn't
  # opted out (security-scan-mode = "passive"), and has no schedule (cron =
  # null): a clean passive run says nothing about what an attack would find,
  # but a weekly attack run cost a weekly app-error alert per app and login
  # floods for little gain, so it runs on demand — after significant changes
  # to a login or form, or before a release. See src/sectest/scan.py.
  #
  # Active scans take far longer per app, hence the longer timeouts: the
  # per-target one stops a single slow app eating the whole run.
  scan_profiles = {
    passive = {
      job_name       = module.naming_scanner.container_app_job.name
      cron           = var.passive_scan_cron_expression
      timeout        = var.passive_scan_timeout_seconds
      target_timeout = 1800
    }
    active = {
      job_name       = module.naming_scanner_active.container_app_job.name
      cron           = null
      timeout        = var.active_scan_timeout_seconds
      target_timeout = 3600
    }
  }

  # Shared by both jobs; each adds its SCAN_PROFILE and SCAN_TARGET_TIMEOUT.
  # The digest settings reach the active job too and go unused there.
  scanner_env = {
    AZURE_CLIENT_ID         = azurerm_user_assigned_identity.this.client_id
    TARGET_SUBSCRIPTION_IDS = join(",", local.target_subscription_ids)
    REPORT_CONTAINER_URL    = "${azurerm_storage_account.reports.primary_blob_endpoint}${azurerm_storage_container.reports.name}"
    SCAN_FAIL_ON            = var.scan_fail_on
    ENVIRONMENT             = var.environment
    LOG_SOURCE              = local.log_source
    KEY_VAULT_URI           = azurerm_key_vault.this.vault_uri
    DIGEST_EMAIL_FROM       = var.digest_email_from
  }
}
