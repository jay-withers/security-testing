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
always gets `-S` there, and `test_passive_profile_never_attacks` guards this. It is a platform *tenant* shaped like
[jay-withers/finances](https://github.com/jay-withers/finances): follow that
repo's conventions when in doubt.

## Layout

- `src/sectest/digest.py` and `mailer.py`: the digest every run emails (via
  Resend, secrets from this repo's Key Vault). Each profile is compared only
  with its own earlier runs, and an active digest lists every open finding. It
  compares only apps scanned in both runs, so a failed scan never reads as resolved, and it never
  raises, so it can't change the job's exit code.
- `src/sectest/accepted.py`: findings accepted as risks, by ZAP `alertRef`
  and app (or `*`), each with a reason pointing at where the decision is
  written. The digest sets them aside as it reads every run, so they are
  never open, new or resolved, and lists them under "Accepted" instead.
  Only the digest reads it; the `over_threshold` alert counts every finding.
  Removing an entry makes its findings read as new again.
- `src/sectest/scan.py`: the whole scanner. It has pure functions
  (`select_targets`, `build_command`, `count_risks`, `exceeds_threshold`) that
  `tests/test_scan.py` covers, plus the Azure/ZAP glue. `tests/test_runner.py`
  covers the glue that decides whether a scan counts (`run_scan`'s
  completed/error/timeout, `stop_process_group` against real processes,
  `discover_targets`' paging, `upload_reports`), faked at `subprocess.Popen`
  and the Azure clients; `main()` itself is untested, and marked `# pragma: no cover` so the
  coverage floors don't push a mock-only test onto it. The console script
  `sectest` is the image's ENTRYPOINT.
- `Dockerfile`: `FROM zaproxy/zap-stable` (bookworm, Python 3.11, uid 1000),
  with the package installed into `/app/.venv` by uv. **The venv must stay off
  PATH.** The `zap-*.py` scripts use `#!/usr/bin/env python3` and need the
  system interpreter, which has their `zaproxy` client. The image creates
  `/zap/wrk` because the packaged scans refuse to write reports without it.
- `src/*.ts`, `tests/*.test.ts`, `package.json`: the **TypeScript port**,
  beside the Python, module for module, and not yet run by anything (the
  README's "The TypeScript port" section). Keep the two in step until the
  cutover: a behaviour change lands in both, with a test in each, and a change
  to the digest's output regenerates `tests/fixtures/digest-golden.json` from
  the Python (`tests/fixtures/README.md`). Node runs the `.ts` files directly,
  so keep to erasable syntax (`erasableSyntaxOnly` enforces it) and import
  the `.ts` file. `summary.json`'s keys stay snake_case for the digest's sake.
  The cutover's image must run `node` under `tini`: Node can't reap the JVM
  the ZAP wrapper orphans, and `processGroupAlive` would then wait out the
  grace on every scan.
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
- Every scan request sends `USER_AGENT` from `scan.py`, so the platform's
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
`cd-publish.yml` when `src/sectest/`, `Dockerfile`, `.dockerignore`, `pyproject.toml` or `uv.lock`
changed since the previous release (not `src/` as a whole: the TypeScript port
beside it isn't in the image until the cutover). Keep that path list in step with
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
make install   # pre-commit hooks + uv sync --extra dev + npm ci
make test      # pytest and vitest (no Azure, no ZAP)
make typecheck # mypy and tsc, as CI runs them
make lint      # every pre-commit hook (ruff, hadolint, tflint/checkov per env, …)
make lint-node # ESLint and Prettier over the TypeScript port, as ci-node runs them
make validate  # terraform init -backend=false + validate (no credentials)
make plan      # needs Azure credentials and the platform applied
make deploy IMAGE_TAG=vX.Y.Z
make scan      # start a passive run now (PROFILE=active attacks)
```

## Commit messages

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/), enforced by commitlint at commit-msg time.

## CI

- **ci-pre-commit**: all hooks, via the shared `pre-commit.yml`.
- **ci-python**: pytest on Python 3.11 (`mise.toml` pins the ZAP image's 3.11, and `ci-container-build` checks the two match), then mypy, via the shared `python.yml`, plus ruff. Total coverage and the lines a PR changes must both be at least 90%.
- **ci-node**: the TypeScript port's vitest suite, `tsc`, ESLint and Prettier, with the same 90% total and diff coverage floors, via the shared `node.yml` (workflows v1.36.0+) on `mise.toml`'s Node. Its check, `node / Test`, is not required until the cutover renames the job to `test`.
- **ci-container-build**: builds the image without pushing, and checks its `python3` is the Python `mise.toml` pins (workflows v1.35.0+). A `changes` job path-filters the build rather than the trigger, so the always-reporting `container-build` gate can be (and is) a required check.
- **ci-terraform**: `validate` via the shared `terraform.yml` (`terraform / Terraform`), then a dev plan via the shared `terraform-deploy.yml`, commented on the PR, behind the always-reporting `terraform-plan` gate. `terraform-deploy.yml` runs in the `dev` GitHub environment, where `github-repos` sets `AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/`AZURE_SUBSCRIPTION_ID` and federates this repo's OIDC identity to `<repo prefix>:environment:dev`; callers pass no credentials. Only dev is planned: it is the only platform environment with an identity.
- **cd-terraform**: plans dev on every merge to `main` that touches Terraform, through the same `terraform-deploy.yml`, and **applies only when run by hand** (Actions → Run workflow). A merge whose plan has changes opens a `terraform-pending` issue (emailed, and listed in repo-agent's weekly digest); the manual run applies exactly the plan it prints and closes it. Apply that way rather than with a local `make apply`. The pipeline identity is Contributor and conditioned RBAC Administrator on `rg-sectest-dev`, both granted by github-repos, which also owns the group, so role assignments inside the group apply here too; one outside it needs a local `make apply`. Key Vault and reports access go to `administrator_object_id` in `environments/dev.tfvars`, never to "whoever applies", or every pipeline run would try to move them to itself. The scanner identity's subscription-scope Reader grants (`main.identity.tf`) are outside the group, so changing them is still a local apply.
- **cd-tag** → **cd-publish**: semver tag on merge, then the GHCR publish when image sources changed.

## Type checking and coverage gates

CI gates three more things, all inside `test / Test`: mypy over `src/` and
`tests/` (`[tool.mypy]` in `pyproject.toml`, so `make typecheck` runs the same
check), ruff (`ruff check` and `ruff format --check`, the same ruff `make lint`
runs) and coverage. Total coverage of `sectest` must be at least 90%, and so
must the lines a PR changes; the table is in the job summary, not a PR comment.
Don't meet either floor with a test that only asserts a mock; test the
behaviour.

## Decisions not to re-litigate

- **The TypeScript port validates all of its configuration; the Python
  doesn't, and isn't changed to match.** `readConfig` turns a missing
  `TARGET_SUBSCRIPTION_IDS` or `REPORT_CONTAINER_URL`, or a bad
  `SCAN_SPIDER_MINUTES` or `SCAN_TARGET_TIMEOUT`, into `config_error` and
  exit 2, where `scan.py` raises (exit 1, with a traceback). Both fail the
  job, so the workload-crashed alert fires either way. The Python goes at the
  cutover, so fixing it now would be work thrown away. `SCAN_TARGET_TIMEOUT`
  is also capped at 2147483 seconds, because Node's `setTimeout` clamps
  anything longer to 1ms and would time every scan out at once. Revisit only
  if the cutover is abandoned.
