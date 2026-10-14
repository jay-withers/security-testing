# The scanners: one job per profile in local.scan_profiles — a nightly passive
# scan of every app, and an active (attack) scan of every app that has not opted
# out, which only runs when started by hand (`make scan PROFILE=active`).
#
# Cron expressions are evaluated in **UTC**, so the wall-clock time shifts by an
# hour with British Summer Time. The trigger is ForceNew: changing a schedule,
# or switching a job between scheduled and manual, replaces that job rather
# than updating it — and a replaced job is back on the placeholder image until
# the next `make deploy`.
resource "azurerm_container_app_job" "scanner" {
  for_each = local.scan_profiles

  name                         = each.value.job_name
  container_app_environment_id = data.azurerm_container_app_environment.platform.id
  resource_group_name          = azurerm_resource_group.this.name
  # Stated, not left to default. The shared environment is a workload-profiles
  # environment, so Azure assigns every job the built-in "Consumption" profile
  # and reports it back; left unset, every plan shows it being cleared to null
  # and no apply ever makes that diff go away.
  workload_profile_name = "Consumption"
  # Unlike a container app, a job **requires** location and the provider rejects
  # it being omitted. Same region as the environment either way.
  location = azurerm_resource_group.this.location

  # Bounds the whole run across every target; scan.py also bounds each target
  # on its own, so one hung scan cannot eat the others' time.
  replica_timeout_in_seconds = each.value.timeout
  # No retry: a retry would scan every target a second time, doubling the
  # traffic (and the shared workspace's HTTP log ingestion) for a run whose
  # failure is almost always the same on the second attempt.
  replica_retry_limit = 0

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.this.id]
  }

  # Exactly one trigger per job: a schedule when the profile has a cron, manual
  # (start-by-hand only) when it has none.
  dynamic "schedule_trigger_config" {
    for_each = each.value.cron != null ? [each.value.cron] : []
    content {
      cron_expression          = schedule_trigger_config.value
      parallelism              = 1
      replica_completion_count = 1
    }
  }

  dynamic "manual_trigger_config" {
    for_each = each.value.cron == null ? [true] : []
    content {
      parallelism              = 1
      replica_completion_count = 1
    }
  }

  template {
    container {
      name = "scanner"
      # Placeholder; see locals.container-apps-jobs.tf.
      image = local.placeholder_image
      # ZAP runs a JVM; 1 vCPU / 2 GiB is the smallest combination it runs
      # comfortably in. A job only bills while it runs, so this costs minutes a
      # night, not a standing replica.
      cpu    = local.container_cpu
      memory = local.container_memory

      # No `command` and no `args`: the image's ENTRYPOINT is the single source
      # of truth for what runs. See finances' main.container-apps.tf for the
      # market-agent outage a stale `command` caused.

      dynamic "env" {
        for_each = merge(local.scanner_env, {
          SCAN_PROFILE        = each.key
          SCAN_TARGET_TIMEOUT = tostring(each.value.target_timeout)
        })
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  tags = local.tags

  # `make deploy` (az cli) owns the image entirely — Terraform only ever sets
  # the placeholder, and ignores whatever a deploy puts there afterwards.
  #
  # Only the image is ignored, unlike finances, which ignores the whole env map
  # because it carries IMAGE_TAG there. Nothing in scanner_env changes per
  # deploy, so Terraform keeps owning it — changing the target subscriptions or
  # the fail threshold lands on the next apply.
  lifecycle {
    ignore_changes = [
      template[0].container[0].image,
    ]
  }

  # Both grants must exist before the first scheduled run, or discovery or the
  # report upload fails with a 403.
  depends_on = [
    azurerm_role_assignment.identity_reader,
    azurerm_role_assignment.identity_reports_contributor,
  ]
}

# The single job that existed before the active profile was added is the passive
# one, under the same name — so this re-addresses it in state rather than
# destroying and recreating it (which would also put it back on the placeholder
# image).
moved {
  from = azurerm_container_app_job.scanner
  to   = azurerm_container_app_job.scanner["passive"]
}
