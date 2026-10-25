# security-testing

A scheduled DAST scanner for the shared Azure Container Apps platform
([jay-withers/azure-container-apps](https://github.com/jay-withers/azure-container-apps)).
Two Container Apps **jobs** find every container app with **external
ingress** in the target subscriptions, run an [OWASP ZAP](https://www.zaproxy.org/)
scan against each one from the public internet, and write the reports to
Blob Storage:

- **Passive**, weekly (Monday 06:00 UTC): every app. Browses like a normal
  visitor and inspects the responses (missing security headers, insecure
  cookies, leaked versions). It never sends anything a browser wouldn't, so it
  can't change or break anything. Each run ends by emailing a
  [digest](#the-digest) of what changed since the previous one.
- **Active**, **on demand only**: every app that hasn't opted out. Fills every
  form field, parameter and API input it can reach with attack strings (SQL
  injection, XSS, path traversal, …) to find what is actually exploitable. It
  really submits them, so any unauthenticated form that saves data fills with
  junk records. Run it with `make scan PROFILE=active` after significant
  changes to a login or form, or before a release. Each run ends by emailing
  its findings.

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
caj-sectest-dev-zap      passive  weekly  Mon 06:00 UTC   zap-baseline.py | zap-api-scan.py -S
caj-sectest-dev-zapfull  active   manual  make scan PROFILE=active   zap-full-scan.py | zap-api-scan.py
  1. Resource Graph: container apps with external ingress (identity: Reader)
  2. one ZAP scan per app, per the profile and the app's tags
  3. reports  ──▶ st…/reports/<date>/<time>-<profile>/<sub>/<rg>/<app>/report.{html,json,md}
                  st…/reports/<date>/<time>-<profile>/summary.json
  4. stdout   ──▶ shared environment ──▶ log-platform-dev  ──▶ findings alert (passive only)
  5. compare with the previous run of the same profile ──▶ Resend ──▶ digest email
```

## Controlling what gets scanned

Both scans are **opt-out**: every app with external ingress gets the weekly
passive scan, and is included in any active run, unless it's tagged otherwise.
Tags go on the *target* container app:

| Tag | Effect |
| --- | --- |
| `security-scan = "false"` | Skip this app in both scans. |
| `security-scan-mode = "passive"` | Opt out of **active** runs only. The app still gets the weekly passive scan. Use this for anything whose stored data you can't have junk written into, that locks out after repeated failed logins, or that can't take the traffic. |
| `security-scan-openapi = "/openapi.json"` | Scan the endpoints in that spec instead of spidering, in whichever profile is running. The passive run still never attacks (it passes ZAP's safe mode, `-S`). The value must be a path on the app's own FQDN. |

Apps that are stopped or have no ingress FQDN are skipped. Each skip is logged
with its reason.

## Findings and failures

These are two different signals, and they go to two different alerts.

- **The scan found something** at or above `scan_fail_on` (default `High`).
  The job still **exits 0**. Each target logs a `scan_finished` JSON line with
  `over_threshold: true`. For a passive run, this repo's own alert
  (`terraform/main.alerts.tf`) fires against the shared workspace, split per
  target app, through the platform's action group. An active run's findings
  arrive in [its digest email](#the-digest) instead, not as alerts.
- **The scan itself broke**: ZAP crashed, a target timed out, or there was an
  RBAC 403. The job **exits 1**. The platform's existing workload-crashed
  alert picks that up with no wiring from here.

The job exits 0 on findings because a failed execution means "this workload
is broken" to the platform. A finding is not that.

## The digest

Every passive run, scheduled or started with `make scan`, ends by emailing
what changed since the previous passive run:

- open High / Medium / Low findings per app, with the change from last time
- **new** and **resolved** findings, where a finding is an app plus a ZAP rule
  plus its risk (Informational alerts are left out)
- scans that failed, and apps that were skipped

An app whose scan failed has no findings marked resolved, and an app scanned
for the first time is listed as a first scan rather than as new findings.

Active runs email a digest too, with "Active security scan" in the subject.
It is compared only with the previous active run, never with a passive one,
and it lists every open finding as well as what changed, because the email is
how an active run's result arrives. Active findings don't trigger the
findings alert.

Mail goes through [Resend](https://resend.com), as in finances. The API key
and the recipients are Key Vault secrets (`make secrets` prints the commands).
Until `DIGEST-EMAIL-TO` is set, each run logs `digest` with
`status: skipped`. The sender, `digest_email_from`, must be on a domain
verified in Resend. Sending never fails the job: a broken digest logs
`status: failed` and the run exits on the scan's own result.

The scan runs weekly rather than nightly because passive findings change when
apps are deployed, not overnight, and each run wakes every scale-to-zero app.
Run `make scan` after a deploy you want checked sooner, and the digest
emails you the difference.

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
5. Set the digest's secrets with the commands `make secrets` prints.
6. Run `make scan` for a passive run now, then `make logs` and
   `make reports`. The first digest has nothing to compare with.
7. Before your first `make scan PROFILE=active`, tag anything that shouldn't
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
make secrets    # print the az commands that set the digest's secrets
make plan / make apply         # ENV=dev by default
```

Terraform never sets the real image. It creates both jobs on a placeholder
(`mcr.microsoft.com/k8se/quickstart-jobs`), the image is under
`ignore_changes`, and `make deploy` is the only thing that sets the scanner
image, on both jobs at once. Everything else in the jobs, including the target
subscriptions, the threshold and the schedules, is still Terraform's.

**Releases deploy themselves.** When a merge publishes a new image,
`cd-publish`'s `deploy` job runs this same `make deploy IMAGE_TAG=<release>`
against dev, through the shared `container-apps-deploy.yml` (OIDC in the `dev`
GitHub environment). To redeploy an existing tag — after a failed deploy, or an
apply that recreated a workload — run `cd-publish` from the Actions tab with
that tag. Running `make deploy` by hand is for anything else, such as a
rollback.

**Every deploy is checked, and a failed one rolls back.** Before deploying,
the workflow records `make deployed-tag` (the tag on the job now). After it,
`make smoke` (`scripts/smoke.sh`) checks that both scanner jobs are configured with the new
tag, then starts one run of each with its args swapped for `sectest selfcheck`,
which checks the settings, secrets and storage a real run needs and does
nothing else, and waits for it to succeed. If the deploy or the check fails, the workflow redeploys the recorded tag and fails the run, so a
`deploy-failed` issue says whether the job is back on the old version.

**Run `make deploy` again after any apply that recreates a job.** Switching
a job between scheduled and manual replaces it, for example (a new cron
expression updates in place). The new job comes back on
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
src/sectest/digest.py      # each run's digest: compare, render, send
src/sectest/mailer.py      # Resend, with secrets from Key Vault
tests/                     # pytest, pure functions only
terraform/
  data.tf                  # the shared platform, resolved by name
  main.tf                  # naming + resource group
  main.container-apps-jobs.tf  # the scheduled scanner job
  main.identity.tf         # identity + Reader on target subscriptions
  main.storage.tf          # reports storage, lifecycle, RBAC
  main.alerts.tf           # findings alert on the shared workspace
  main.key-vault.tf        # the digest's Resend key and recipients
  backends/dev.hcl         # partial backend config
  environments/dev.tfvars
.github/workflows/
  ci-python.yml  ci-container-build.yml  ci-terraform.yml  ci-pre-commit.yml
  cd-tag.yml  cd-publish.yml   # release → publish ghcr.io/jay-withers/security-testing/sectest
```
