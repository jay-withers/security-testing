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

# A second instance for the scanner job, suffixed with its workload. The
# platform's workload-crashed alert splits on JobName_s, so a job's name has to
# carry which workload it is: caj-<project>-<env>-<workload>.
#
# `caj-sectest-dev-zap` is 19 of the 32 characters container apps allow. The
# naming module truncates silently rather than failing, so check with
# `terraform console` before renaming either part.
module "naming_scanner" {
  # checkov:skip=CKV_TF_1: Terraform Registry module pinned by semver, as above.
  source  = "Azure/naming/azurerm"
  version = "~> 0.4"
  suffix  = [var.project_name, var.environment, "zap"]
}

resource "azurerm_resource_group" "this" {
  name = module.naming.resource_group.name
  # Must match the shared environment's region: a job may sit in a different
  # resource group from its environment, but not a different region.
  location = data.azurerm_container_app_environment.platform.location
  tags     = local.tags
}
