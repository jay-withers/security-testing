# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo does

A scheduled DAST scanner (OWASP ZAP) that runs as a Container Apps **job** on
the shared platform environment from
[jay-withers/azure-container-apps](https://github.com/jay-withers/azure-container-apps).
It discovers every container app with external ingress (Azure Resource Graph),
scans each one over the public internet, and writes the reports to Blob
Storage. There are two jobs on the same image, chosen by `SCAN_PROFILE`:
**passive**, weekly, for every app, which never sends attack payloads and
ends by emailing a digest of what changed since the previous passive run, and
**active**, which is **opt-out** (`security-scan-mode = "passive"`), attacks,
has **no schedule**, and ends by emailing its findings instead of alerting. It's a manual-trigger job (`make scan PROFILE=active`),
because `local.scan_profiles.active.cron = null`. `security-scan = "false"` skips an app in both. The passive
profile must never attack. `zap-api-scan.py` is active by default, so it
always gets `-S` there, and the "never attacks in the passive profile" test in `tests/scan.test.ts` guards this. It is a platform *tenant* shaped like
[jay-withers/finances](https://github.com/jay-withers/finances): follow that
repo's conventions when in doubt.

## Layout

The scanner is TypeScript (ported from Python in November 2026), run by Node
straight from `src/*.ts`: type stripping, no build step. Keep to erasable
syntax (`erasableSyntaxOnly` enforces it) and import the `.ts` file.

- `src/digest.ts` and `mailer.ts`: the digest every run emails (via
  Resend, secrets from this repo's Key Vault). Each profile is compared only
  with its own earlier runs, and an active digest lists every open finding. It
  compares only apps scanned in both runs, so a failed scan never reads as
  resolved, and it never throws, so it can't change the job's exit code.
  `tests/parity.test.ts` holds its output, byte for byte, to what the Python
  rendered (`tests/fixtures/`); a deliberate change to the email rewrites the
  golden file (`tests/fixtures/README.md`) and reviews its diff.
- `src/accepted.ts`: findings accepted as risks, by ZAP `alertRef`
  and app (or `*`), each with a reason pointing at where the decision is
  written. The digest sets them aside as it reads every run, so they are
  never open, new or resolved, and lists them under "Accepted" instead.
  Only the digest reads it; the `over_threshold` alert counts every finding.
  Removing an entry makes its findings read as new again.
- `src/scan.ts`: the whole scanner. Pure functions (`selectTargets`,
  `buildCommand`, `countRisks`, `exceedsThreshold`) that `tests/scan.test.ts`
  covers, plus the ZAP glue (`runScan`'s completed/error/timeout,
  `stopProcessGroup` against real processes) and `main()`, which
  `tests/runner.test.ts` covers through its seams. Azure is behind small
  interfaces (`ResourceGraph`, `Container`, `SecretStore`) the SDK clients
  satisfy; `src/azure.ts` only builds the clients, and it and `src/main.ts`
  are left out of coverage. `summary.json` keeps the Python scanner's
  snake_case keys, because the digest reads earlier runs, the Python's
  included.
- `Dockerfile`: `FROM zaproxy/zap-stable` (bookworm, uid 1000), with `node`
  copied in from the official `node:<mise.toml's version>-bookworm-slim`
  image, the production `node_modules` from a builder stage, and `src/`.
  **The ENTRYPOINT is `tini -- node /app/src/main.ts`, and tini must stay.**
  A ZAP wrapper exits leaving its JVM and Xvfb behind, re-parented to PID 1;
  Node only reaps its own children, so as PID 1 it leaves them as zombies,
  `processGroupAlive` reads them as alive, and every scan waits out the 120s
  grace. The `zap-*.py` wrappers run on the image's system `python3`, where
  the base image installed their `zaproxy` client; nothing here uses it. The
  image creates `/zap/wrk` because the packaged scans refuse to write reports
  without it.
- `terraform/` is a **root configuration** (partial `azurerm` backend in
  `backends/<env>.hcl`, committed `.terraform.lock.hcl`, azurerm `~> 5.0`), not
  a reusable module. There are no examples and no terraform tests. Only `dev`
  exists, because the platform data sources fail to plan against an
  environment the platform hasn't been applied to.

## Contract with the shared platform

- The environment, workspace and action group are resolved **by name** in
  `terraform/data.tf` (`rg-platform-dev`, `cae-platform-dev`,
  `log-platform-dev`, `mag-platform-dev`). The resource group is
  github-repos' (`create_resource_groups`), read here by data source; it sits
  in the environment's region, because a job must.
- Job names come from `module.naming_scanner` (`caj-<project>-<env>-zap`,
  passive) and `module.naming_scanner_active` (`…-zapfull`, active). They're
  `for_each` over `local.scan_profiles`, and a `moved` block keeps the
  original single job as `["passive"]`. Names carry the workload because the
  platform's workload-crashed alert
  splits on `JobName_s`.
- **Exit codes:** the job exits non-zero only when a scan *failed*, which the
  platform alert catches. Findings exit 0 and are logged as `scan_finished`
  JSON with `over_threshold`, which `terraform/main.alerts.tf` alerts on for
  passive runs only (active findings arrive by email). Don't make findings fail
  the job.
- Every log line carries `source` (`LOG_SOURCE`, set from `local.log_source`).
  The findings alert filters on it, so keep the two in step.
- Every scan request sends `USER_AGENT` from `scan.ts`, so the platform's
  app-error rule can exclude scanner traffic.
- The shared workspace has a 0.15 GB/day cap for all tenants. Don't add
  diagnostic settings that ship to it (hence the `CKV2_AZURE_21` skip), and
  remember that scan requests themselves land in `ContainerAppHTTPLogs`.

## Deploys

Terraform creates both jobs on a **placeholder image**
(`local.placeholder_image`) and ignores the image from then on. There is no
image variable. `make deploy IMAGE_TAG=vX.Y.Z` (`az containerapp job update`)
is the only thing that sets the scanner image, always on both jobs, and it rejects moving tags
(`latest`/`main`). Any apply that creates or replaces the job (the first
apply, or a ForceNew change like switching a job between scheduled and manual;
a new cron expression updates in place) must be followed by `make deploy`,
or the job silently runs the placeholder, which exits 0, so no alert fires. `cd-tag` publishes
`ghcr.io/jay-withers/security-testing/sectest:{vX.Y.Z,<sha>}` via
`cd-publish.yml` when `src/`, `Dockerfile`, `.dockerignore`, `package.json` or
`package-lock.json` changed since the previous release. Keep that path list in step with
`ci-container-build.yml`'s filter. `cd-publish`'s `deploy` job then runs `make deploy IMAGE_TAG=<release>` against dev through the shared `container-apps-deploy.yml` (OIDC in the `dev` GitHub environment; `cd-tag`'s `publish` job grants `id-token: write` for it). An apply that recreates a workload does not trigger it: re-run `cd-publish` with `workflow_dispatch` and the current tag.

## File layout is enforced

`locals`/`variable`/`output`/`data` blocks must live in
`locals*.tf`/`variables*.tf`/`outputs*.tf`/`data*.tf`, and
`terraform{}`/`provider{}` in `versions*.tf`. Topic-scoped variants like
`locals.container-apps-jobs.tf` and `variables.optional.tf` are fine.
Resources go in `main.tf` or `main.<topic>.tf`. The local pre-commit hook
`scripts/check-tf-standards.sh` enforces this. This repo carries a verbatim
copy of that script, so change it upstream rather than here.

## Commands

`make` with no target prints the help. Key targets:

```bash
make install   # mise tools, pre-commit hooks + npm ci
make test      # vitest (no Azure, no ZAP)
make typecheck # tsc, as CI runs it
make lint      # every pre-commit hook (hadolint, tflint/checkov per env, …)
make lint-node # ESLint and Prettier, as ci-node runs them
make validate  # terraform init -backend=false + validate (no credentials)
make plan      # needs Azure credentials and the platform applied
make deploy IMAGE_TAG=vX.Y.Z
make scan      # start a passive run now (PROFILE=active attacks)
```

## Commit messages

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/), enforced by commitlint at commit-msg time.

## CI

- **ci-pre-commit**: all hooks, via the shared `pre-commit.yml`.
- **ci-codeql**: CodeQL over the TypeScript (`javascript-typescript`) and the workflows; high/critical alerts block merges.
- **ci-node**: `test / Test`, the required check: the vitest suite, `tsc`, ESLint and Prettier, with 90% total and diff coverage floors, via the shared `node.yml` (workflows v1.36.0+) on `mise.toml`'s Node.
- **ci-container-build**: builds the image without pushing, and checks its `node` major is the one `mise.toml` pins (workflows v1.36.0+). A `changes` job path-filters the build rather than the trigger, so the always-reporting `container-build` gate can be (and is) a required check.
- **ci-terraform**: `validate` via the shared `terraform.yml` (`terraform / Terraform`), then a dev plan via the shared `terraform-deploy.yml`, commented on the PR, behind the always-reporting `terraform-plan` gate. `terraform-deploy.yml` runs in the `dev` GitHub environment, where `github-repos` sets `AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/`AZURE_SUBSCRIPTION_ID` and federates this repo's OIDC identity to `<repo prefix>:environment:dev`; callers pass no credentials. Only dev is planned: it is the only platform environment with an identity.
- **cd-terraform**: plans dev on every merge to `main` that touches Terraform, through the same `terraform-deploy.yml`, and **applies only when run by hand** (Actions → Run workflow). A merge whose plan has changes opens a `terraform-pending` issue (emailed, and listed in repo-agent's weekly digest); the manual run applies exactly the plan it prints and closes it. Apply that way rather than with a local `make apply`. The pipeline identity is Contributor and conditioned RBAC Administrator on `rg-sectest-dev`, both granted by github-repos, which also owns the group, so role assignments inside the group apply here too; one outside it needs a local `make apply`. Key Vault and reports access go to `administrator_object_id` in `environments/dev.tfvars`, never to "whoever applies", or every pipeline run would try to move them to itself. The scanner identity's subscription-scope Reader grants (`main.identity.tf`) are outside the group, so changing them is still a local apply.
- **cd-tag** → **cd-publish**: semver tag on merge, then the GHCR publish when image sources changed.

## Type checking and coverage gates

`test / Test` gates more than the tests: `tsc` over `src/` and `tests/`
(`tsconfig.json`, so `make typecheck` runs the same check), ESLint and
Prettier (the scripts `make lint-node` runs) and coverage. Total line coverage
must be at least 90%, and so must the lines a PR changes; the table is in the
job summary, not a PR comment. Don't meet either floor with a test that only
asserts a mock; test the behaviour.

## Decisions not to re-litigate

- **The scanner validates all of its configuration up front**, unlike the
  Python it replaced, which crashed on a missing variable or a bad number
  (exit 1, with a traceback). `readConfig` turns a missing
  `TARGET_SUBSCRIPTION_IDS` or `REPORT_CONTAINER_URL`, or a bad
  `SCAN_SPIDER_MINUTES` or `SCAN_TARGET_TIMEOUT`, into `config_error` and
  exit 2. Either fails the job, so the workload-crashed alert fires as it did.
  `SCAN_TARGET_TIMEOUT` is capped at 2147483 seconds, because Node's
  `setTimeout` clamps anything longer to 1ms and would time every scan out at
  once.
- **No build step.** Node runs the `.ts` files directly, so the image ships
  `src/` as written, with nothing compiled to diverge from what was tested.
  Revisit if a dependency needs syntax type stripping can't erase.
