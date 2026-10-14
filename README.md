# security-testing

A scheduled DAST scanner for the shared Azure Container Apps platform
([jay-withers/azure-container-apps](https://github.com/jay-withers/azure-container-apps)).
Every night a Container Apps **job** finds every container app with **external
ingress** in the target subscriptions, runs an [OWASP ZAP](https://www.zaproxy.org/)
scan against each one from the public internet, and writes the reports to
Blob Storage.

It is a tenant of the platform, the same way `finances` is. The shared
Container Apps environment (`cae-platform-dev`) and Log Analytics workspace
(`log-platform-dev`) are resolved by name in `terraform/data.tf`. Nothing here
creates or changes them.

```text
caj-sectest-dev-zap  (cron, 02:00 UTC)        identity: Reader on target subscriptions
  1. Resource Graph: container apps with external ingress
  2. per app: zap-baseline.py | zap-api-scan.py | zap-full-scan.py
  3. reports  ──▶ st…/reports/<date>/<time>/<sub>/<rg>/<app>/report.{html,json,md}
                  st…/reports/<date>/<time>/summary.json
  4. stdout   ──▶ shared environment ──▶ log-platform-dev  ──▶ findings alert
```

## Controlling what gets scanned

Every app with external ingress is scanned with the **passive baseline** scan
by default. That scan spiders for a few minutes and only reads the responses,
so it is safe against production. Tags on the *target* container app change
that:

| Tag | Effect |
| --- | --- |
| `security-scan = "false"` | Skip this app. |
| `security-scan-openapi = "/openapi.json"` | Run an API scan against that spec path instead of spidering. The value must be a path on the app's own FQDN. |
| `security-scan-mode = "full"` | Run an **active** scan, which sends attack payloads. Opt-in per app only. Expect it to write junk data into anything the app persists, and to generate far more traffic (see below). |

Apps that are stopped or have no ingress FQDN are skipped. Each skip is logged
with its reason.

## Findings and failures

These are two different signals, and they go to two different alerts.

- **The scan found something** at or above `scan_fail_on` (default `High`).
  The job still **exits 0**. Each target logs a `scan_finished` JSON line with
  `over_threshold: true`, and this repo's own alert
  (`terraform/main.alerts.tf`) fires against the shared workspace, split per
  target app, through the platform's action group.
- **The scan itself broke**: ZAP crashed, a target timed out, or there was an
  RBAC 403. The job **exits 1**. The platform's existing workload-crashed
  alert picks that up with no wiring from here.

The job exits 0 on findings because a failed execution means "this workload
is broken" to the platform. A finding is not that.

## Impact on the shared platform

Read this before adding targets or enabling full scans.

- **HTTP log volume.** Every request ZAP makes to a target app becomes a row
  in `ContainerAppHTTPLogs`, and those rows count against the shared
  workspace's 0.15 GB/day cap. Hitting that cap blinds every tenant's alerts
  for the rest of the day. A baseline scan is a few hundred requests per app,
  which is negligible. A full scan can be tens of thousands, so enable it
  sparingly and watch the platform's log-quota alert the first time.
- **The platform's app-error alert.** That rule fires when the same
  (app, path, 4xx/5xx) repeats 3 or more times in 15 minutes. Baseline scans
  should stay under that. Full scans will not. Every scan request carries the
  User-Agent `sectest-dast-scanner (…)` (`USER_AGENT` in
  `src/sectest/scan.py`), so the platform rule can exclude scanner traffic
  rather than fire on it. That change belongs in azure-container-apps, not
  here.
- **Egress IP.** On the Consumption plan the job's outbound IP is not static.
  A target that restricts ingress by IP will reject the scan, and the result
  will look like a near-empty report.

Only scan apps you own, and follow Microsoft's
[penetration testing rules of engagement](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement).

## First deployment

1. Create the state container `security-testing` in `sttfsharedjw`
   (`rg-tfstate-shared`). The shared state account is created once by hand,
   and each repo's container must exist before the first `init`.
2. Make sure the platform is applied (`rg-platform-dev`, `cae-platform-dev`,
   `log-platform-dev`, `mag-platform-dev`). The data sources fail at plan time
   otherwise.
3. Run `make plan`, then `make apply`. Whoever applies needs Owner or User
   Access Administrator on every target subscription, because the scanner's
   identity is granted Reader there. The job is created on a **placeholder
   image** that does nothing.
4. Let `cd-tag` publish an image (or `make build push`), then
   `make deploy IMAGE_TAG=vX.Y.Z` to put the scanner on the job.
5. Run `make scan` to run once now, then `make logs` and `make reports`.

## Commands

```bash
make install    # pre-commit hooks + uv venv
make test       # pytest — no Azure, no ZAP
make lint       # every pre-commit hook
make build      # docker build for linux/amd64
make deploy IMAGE_TAG=v0.2.0   # roll a released image onto the job
make scan       # start a run now, outside the schedule
make logs       # the latest run's log lines
make reports    # the latest run summaries in Blob Storage
make plan / make apply         # ENV=dev by default
```

Terraform never sets the real image. It creates the job on a placeholder
(`mcr.microsoft.com/k8se/quickstart-jobs`), the image is under
`ignore_changes`, and `make deploy` is the only thing that sets the scanner
image. Everything else in the job, including the target subscriptions, the
threshold and the schedule, is still Terraform's.

**Run `make deploy` again after any apply that recreates the job.** Changing
`scan_cron_expression` replaces it, for example. The new job comes back on
the placeholder, which exits 0, so no alert fires: runs "succeed" and nothing
is scanned. If `make reports` shows no new runs, check this first.

Reports are only readable with Entra auth (shared keys are disabled):

```bash
az storage blob download --auth-mode login \
  --account-name "$(terraform -chdir=terraform output -raw reports_storage_account_name)" \
  --container-name reports --name '<date>/<time>/summary.json' --file summary.json
```

## Structure

```text
Dockerfile                 # FROM zaproxy/zap-stable + the sectest venv
pyproject.toml / uv.lock   # the scanner package
src/sectest/scan.py        # discovery, scan dispatch, report upload
tests/                     # pytest, pure functions only
terraform/
  data.tf                  # the shared platform, resolved by name
  main.tf                  # naming + resource group
  main.container-apps-jobs.tf  # the scheduled scanner job
  main.identity.tf         # identity + Reader on target subscriptions
  main.storage.tf          # reports storage, lifecycle, RBAC
  main.alerts.tf           # findings alert on the shared workspace
  backends/dev.hcl         # partial backend config
  environments/dev.tfvars
.github/workflows/
  ci-python.yml  ci-container-build.yml  ci-terraform.yml  ci-pre-commit.yml
  cd-tag.yml  cd-publish.yml   # release → publish ghcr.io/jay-withers/security-testing/sectest
```
