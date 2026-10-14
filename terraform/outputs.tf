output "resource_group_name" {
  description = "This project's resource group."
  value       = azurerm_resource_group.this.name
}

output "scanner_job_name" {
  description = "Name of the scanner job, for `make deploy` and for starting a run by hand with `make scan`."
  value       = azurerm_container_app_job.scanner.name
}

output "identity_client_id" {
  description = "Client ID of the scanner's identity, which the job receives as `AZURE_CLIENT_ID`."
  value       = azurerm_user_assigned_identity.this.client_id
}

output "reports_container_url" {
  description = "Blob container scan reports are written to, for `make reports`."
  value       = "${azurerm_storage_account.reports.primary_blob_endpoint}${azurerm_storage_container.reports.name}"
}

output "reports_storage_account_name" {
  description = "Storage account holding the reports, for `az storage blob download --auth-mode login`."
  value       = azurerm_storage_account.reports.name
}
