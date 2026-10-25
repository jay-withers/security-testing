# Terraform — DAST scanner root configuration

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.6 |
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | ~> 5.0 |
| <a name="requirement_random"></a> [random](#requirement\_random) | >= 3.3.2 |

## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | ~> 5.0 |

## Modules

| Name | Source | Version |
| ---- | ------ | ------- |
| <a name="module_naming"></a> [naming](#module\_naming) | Azure/naming/azurerm | ~> 0.4 |
| <a name="module_naming_scanner"></a> [naming\_scanner](#module\_naming\_scanner) | Azure/naming/azurerm | ~> 0.4 |
| <a name="module_naming_scanner_active"></a> [naming\_scanner\_active](#module\_naming\_scanner\_active) | Azure/naming/azurerm | ~> 0.4 |

## Resources

| Name | Type |
| ---- | ---- |
| [azurerm_container_app_job.scanner](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_app_job) | resource |
| [azurerm_key_vault.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault) | resource |
| [azurerm_monitor_scheduled_query_rules_alert_v2.findings](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_scheduled_query_rules_alert_v2) | resource |
| [azurerm_resource_group.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group) | resource |
| [azurerm_role_assignment.deployer_reports_reader](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.deployer_secrets_officer](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.identity_reader](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.identity_reports_contributor](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.identity_secrets_user](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_storage_account.reports](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account) | resource |
| [azurerm_storage_container.reports](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container) | resource |
| [azurerm_storage_management_policy.reports](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_management_policy) | resource |
| [azurerm_user_assigned_identity.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/user_assigned_identity) | resource |
| [azurerm_client_config.current](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/client_config) | data source |
| [azurerm_container_app_environment.platform](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/container_app_environment) | data source |
| [azurerm_log_analytics_workspace.platform](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/log_analytics_workspace) | data source |
| [azurerm_monitor_action_group.platform](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/monitor_action_group) | data source |
| [azurerm_subscription.current](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/subscription) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_active_scan_timeout_seconds"></a> [active\_scan\_timeout\_seconds](#input\_active\_scan\_timeout\_seconds) | Upper bound on one whole active run, across every target. Active scans take far longer per app than passive ones. | `number` | `21600` | no |
| <a name="input_administrator_object_id"></a> [administrator\_object\_id](#input\_administrator\_object\_id) | Entra object ID of the administrator granted Key Vault Secrets Officer (to set the secrets) and Storage Blob Data Reader on the reports container. Explicit rather than taken from whoever runs `terraform apply`, because cd-terraform applies as the pipeline identity. | `string` | n/a | yes |
| <a name="input_digest_email_from"></a> [digest\_email\_from](#input\_digest\_email\_from) | Sender of the digest, e.g. `Security scans <sectest@jaywithers.uk>`. Must be on a domain verified in Resend. The recipients are the Key Vault secret `DIGEST-EMAIL-TO`, not a variable, so no address lands in the repository or the state. | `string` | `"Security scans <sectest@jaywithers.uk>"` | no |
| <a name="input_environment"></a> [environment](#input\_environment) | Deployment environment. Drives resource naming, and selects which shared platform environment this project deploys onto. | `string` | n/a | yes |
| <a name="input_passive_scan_cron_expression"></a> [passive\_scan\_cron\_expression](#input\_passive\_scan\_cron\_expression) | When the passive scan of every app runs, in **UTC** — Container Apps jobs have no timezone setting. Each run ends by emailing the digest. The default is 06:00 UTC every Monday, so the digest is waiting at the start of the week under both GMT and BST. | `string` | `"0 6 * * 1"` | no |
| <a name="input_passive_scan_timeout_seconds"></a> [passive\_scan\_timeout\_seconds](#input\_passive\_scan\_timeout\_seconds) | Upper bound on one whole passive run, across every target. | `number` | `7200` | no |
| <a name="input_platform_action_group_name"></a> [platform\_action\_group\_name](#input\_platform\_action\_group\_name) | Name of the shared action group the findings alert notifies. | `string` | `"mag-platform-dev"` | no |
| <a name="input_platform_environment_name"></a> [platform\_environment\_name](#input\_platform\_environment\_name) | Name of the shared Container Apps environment the scanner job runs on. | `string` | `"cae-platform-dev"` | no |
| <a name="input_platform_log_analytics_workspace_name"></a> [platform\_log\_analytics\_workspace\_name](#input\_platform\_log\_analytics\_workspace\_name) | Name of the shared Log Analytics workspace the environment logs to. The findings alert queries it. | `string` | `"log-platform-dev"` | no |
| <a name="input_platform_resource_group_name"></a> [platform\_resource\_group\_name](#input\_platform\_resource\_group\_name) | Resource group holding the shared Container Apps environment, Log Analytics workspace and action group. | `string` | `"rg-platform-dev"` | no |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Short name for this project, used by the naming module for every resource. | `string` | `"sectest"` | no |
| <a name="input_report_reader_object_ids"></a> [report\_reader\_object\_ids](#input\_report\_reader\_object\_ids) | Extra Entra object IDs granted Storage Blob Data Reader on the reports container. `administrator_object_id` is always included, so this is only for a second person or a second machine. | `list(string)` | `[]` | no |
| <a name="input_report_retention_days"></a> [report\_retention\_days](#input\_report\_retention\_days) | Days scan reports are kept before the lifecycle policy deletes them. | `number` | `90` | no |
| <a name="input_scan_fail_on"></a> [scan\_fail\_on](#input\_scan\_fail\_on) | Lowest ZAP alert risk that raises the findings alert: `Low`, `Medium` or `High`. Findings never fail the job itself — see main.alerts.tf. | `string` | `"High"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags merged over the defaults in locals.tf. | `map(string)` | `{}` | no |
| <a name="input_target_subscription_ids"></a> [target\_subscription\_ids](#input\_target\_subscription\_ids) | Subscription IDs to discover container apps in. The scanner's identity gets Reader on each. Empty means the subscription this is applied into. | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_identity_client_id"></a> [identity\_client\_id](#output\_identity\_client\_id) | Client ID of the scanner's identity, which the job receives as `AZURE_CLIENT_ID`. |
| <a name="output_key_vault_name"></a> [key\_vault\_name](#output\_key\_vault\_name) | Key Vault holding the digest's RESEND-API-KEY and DIGEST-EMAIL-TO, for `make secrets`. |
| <a name="output_reports_container_url"></a> [reports\_container\_url](#output\_reports\_container\_url) | Blob container scan reports are written to, for `make reports`. |
| <a name="output_reports_storage_account_name"></a> [reports\_storage\_account\_name](#output\_reports\_storage\_account\_name) | Storage account holding the reports, for `az storage blob download --auth-mode login`. |
| <a name="output_resource_group_name"></a> [resource\_group\_name](#output\_resource\_group\_name) | This project's resource group. |
| <a name="output_scanner_job_name_active"></a> [scanner\_job\_name\_active](#output\_scanner\_job\_name\_active) | Name of the on-demand active (attack) scanner job, for `make deploy` and `make scan PROFILE=active`. |
| <a name="output_scanner_job_name_passive"></a> [scanner\_job\_name\_passive](#output\_scanner\_job\_name\_passive) | Name of the weekly passive scanner job, which also sends the digest, for `make deploy` and `make scan`. |
<!-- END_TF_DOCS -->
