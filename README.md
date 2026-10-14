# security-testing

A scheduled DAST scanner for the shared Azure Container Apps platform
([jay-withers/azure-container-apps](https://github.com/jay-withers/azure-container-apps)).
Two Container Apps **jobs** find every container app with **external
ingress** in the target subscriptions, run an [OWASP ZAP](https://www.zaproxy.org/)
scan against each one from the public internet, and write the reports to
Blob Storage:

- **Passive**, nightly: every app. Browses like a normal visitor and inspects
  the responses (missing security headers, insecure cookies, leaked versions).
  It never sends anything a browser wouldn't, so it can't change or break
  anything.
- **Active**, **on demand only**: every app that hasn't opted out. Fills every
  form field, parameter and API input it can reach with attack strings (SQL
  injection, XSS, path traversal, …) to find what is actually exploitable. It
  really submits them, so any unauthenticated form that saves data fills with
  junk records. Run it with `make scan PROFILE=active` after significant
  changes to a login or form, or before a release.

A clean passive scan does **not** mean an active scan would find nothing. They
look for different things. Passive sees misconfiguration that shows in normal
responses. Injection flaws only show when an attack is sent. Active scanning is
on demand because, for apps whose only public surface is a login form, a
weekly run's cost (an app-error alert per app, a flood of failed logins)
outweighed what it added. Code scanning in each app's CI (CodeQL, bandit,
`pip-audit`) is the cheaper way to catch injection bugs in your own code,
including behind the login, which ZAP can't reach.

It is a tenant of the platform, the same way `finances` is. The shared
Container Apps environment (`cae-platform-dev`) and Log Analytics workspace
(`log-platform-dev`) are resolved by name in `terraform/data.tf`. Nothing here
creates or changes them.

```text
caj-sectest-dev-zap      passive  daily   02:00 UTC   zap-baseline.py | zap-api-scan.py -S
caj-sectest-dev-zapfull  active   manual  make scan PROFILE=active   zap-full-scan.py | zap-api-scan.py
  1. Resource Graph: container apps with external ingress (identity: Reader)
  2. one ZAP scan per app, per the profile and the app's tags
  3. reports  ──▶ st…/reports/<date>/<time>-<profile>/<sub>/<rg>/<app>/report.{html,json,md}
                  st…/reports/<date>/<time>-<profile>/summary.json
  4. stdout   ──▶ shared environment ──▶ log-platform-dev  ──▶ findings alert
```

## Controlling what gets scanned

Both scans are **opt-out**: every app with external ingress gets the nightly
passive scan, and is included in any active run, unless it's tagged otherwise.
Tags go on the *target* container app:

| Tag | Effect |
| --- | --- |
| `security-scan = "false"` | Skip this app in both scans. |
| `security-scan-mode = "passive"` | Opt out of **active** runs only. The app still gets the nightly passive scan. Use this for anything whose stored data you can't have junk written into, that locks out after repeated failed logins, or that can't take the traffic. |
| `security-scan-openapi = "/openapi.json"` | Scan the endpoints in that spec instead of spidering, in whichever profile is running. The passive run still never attacks (it passes ZAP's safe mode, `-S`). The value must be a path on the app's own FQDN. |

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

Read this before starting an active run, because it includes every app that
isn't tagged `security-scan-mode = "passive"`.

- **HTTP log volume.** Every request ZAP makes to a target app becomes a row
  in `ContainerAppHTTPLogs`, and those rows count against the shared
  workspace's 0.15 GB/day cap. Hitting that cap blinds every tenant's alerts
  for the rest of the day. A passive scan is a few hundred requests per app,
  which is negligible. An active scan can be thousands to tens of thousands
  per app. Watch the platform's log-quota alert after an active run, and
  don't start one late in a day that's already been busy.
- **The platform's app-error alert.** That rule fires when the same
  (app, path, 4xx/5xx) repeats 3 or more times in 15 minutes. Passive scans
  should stay under that. Active scans will not, so expect it to fire for
  each app an active run attacks, until the rule excludes the scanner. The
  rule ignores 401s, so attacks refused by a login don't count, but 422s
  from malformed form data do. Every scan request carries the
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
   `make deploy IMAGE_TAG=vX.Y.Z` to put the scanner on both jobs.
5. Run `make scan` for a passive run now, then `make logs` and
   `make reports`.
6. Before your first `make scan PROFILE=active`, tag anything that shouldn't
   be attacked `security-scan-mode = "passive"`.

## Commands

```bash
make install    # pre-commit hooks + uv venv
make test       # pytest — no Azure, no ZAP
make lint       # every pre-commit hook
make build      # docker build for linux/amd64
make deploy IMAGE_TAG=v0.2.0   # roll a released image onto both jobs
make scan       # start a passive run now, outside the schedule
make scan PROFILE=active       # start an active (attack) run now
make logs       # the latest passive run's log lines (PROFILE=active for the other)
make reports    # the latest run summaries in Blob Storage
make plan / make apply         # ENV=dev by default
```

Terraform never sets the real image. It creates both jobs on a placeholder
(`mcr.microsoft.com/k8se/quickstart-jobs`), the image is under
`ignore_changes`, and `make deploy` is the only thing that sets the scanner
image, on both jobs at once. Everything else in the jobs, including the target
subscriptions, the threshold and the schedules, is still Terraform's.

**Run `make deploy` again after any apply that recreates a job.** Changing
either cron expression replaces that job, for example. The new job comes back on
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
