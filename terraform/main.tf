# This project's own infrastructure: a scheduled DAST scanner (OWASP ZAP) that
# discovers every container app with external ingress and scans it from the
# internet. The Container Apps environment it runs on, and the Log Analytics
# workspace its output lands in, are **not** here — they are shared, live in
# jay-withers/azure-container-apps, and are resolved by name in data.tf.
#
# Everything this project owns is in its own resource group with its own
# identity and storage, so the reports — which describe exactly where every
# app is weak — are readable by nothing else on the platform.
module "naming" {
  # checkov:skip=CKV_TF_1: Terraform Registry module pinned by semver
  # (version below), not a git source — there's no commit hash to pin.
  source  = "Azure/naming/azurerm"
  version = "~> 0.4"
  suffix  = [var.project_name, var.environment]
}

# One instance per scanner job, suffixed with its workload. The platform's
# workload-crashed alert splits on JobName_s, so a job's name has to carry which
# workload it is: caj-<project>-<env>-<workload>.
#
# `caj-sectest-dev-zap` (passive) is 19 and `caj-sectest-dev-zapfull` (active)
# 23 of the 32 characters container apps allow — 31 at the longest
# project_name. The naming module truncates silently rather than failing, so
# check with `terraform console` before renaming any part. `zap` is kept for
# the passive job because renaming it would replace the existing job.
module "naming_scanner" {
  # checkov:skip=CKV_TF_1: Terraform Registry module pinned by semver, as above.
  source  = "Azure/naming/azurerm"
  version = "~> 0.4"
  suffix  = [var.project_name, var.environment, "zap"]
}

module "naming_scanner_active" {
  # checkov:skip=CKV_TF_1: Terraform Registry module pinned by semver, as above.
  source  = "Azure/naming/azurerm"
  version = "~> 0.4"
  suffix  = [var.project_name, var.environment, "zapfull"]
}

# The resource group is github-repos' (`create_resource_groups`), which
# imported the one this config's first apply made, and grants the pipeline
# Contributor and conditioned RBAC Administrator on it. Dropped from this state
# without touching Azure; data.tf looks it up by the same name.
removed {
  from = azurerm_resource_group.this

  lifecycle {
    destroy = false
  }
}
