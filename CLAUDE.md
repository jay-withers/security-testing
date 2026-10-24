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
- `src/sectest/scan.py`: the whole scanner. It has pure functions
  (`select_targets`, `build_command`, `count_risks`, `exceeds_threshold`) that
  `tests/` covers, plus the Azure/ZAP glue in `main()`. The console script
  `sectest` is the image's ENTRYPOINT.
- `Dockerfile`: `FROM zaproxy/zap-stable` (bookworm, Python 3.11, uid 1000),
  with the package installed into `/app/.venv` by uv. **The venv must stay off
  PATH.** The `zap-*.py` scripts use `#!/usr/bin/env python3` and need the
  system interpreter, which has their `zaproxy` client. The image creates
  `/zap/wrk` because the packaged scans refuse to write reports without it.
- `terraform/` is a **root configuration** (partial `azurerm` backend in
  `backends/<env>.hcl`, committed `.terraform.lock.hcl`, azurerm `~> 5.0`), not
  a reusable module. There are no examples and no terraform tests. Only `dev`
  exists, because the platform data sources fail to plan against an
  environment the platform hasn't been applied to.

## Contract with the shared platform

- The environment, workspace and action group are resolved **by name** in
  `terraform/data.tf` (`rg-platform-dev`, `cae-platform-dev`,
  `log-platform-dev`, `mag-platform-dev`). The resource group takes its
  location from the environment, because a job must be in its environment's
  region.
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
`cd-publish.yml` when `src/`, `Dockerfile`, `pyproject.toml` or `uv.lock`
changed since the previous release. Keep that path list in step with
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
make install   # pre-commit hooks + uv sync --extra dev
make test      # pytest (no Azure, no ZAP)
make lint      # every pre-commit hook (ruff, hadolint, tflint/checkov per env, …)
make validate  # terraform init -backend=false + validate (no credentials)
make plan      # needs Azure credentials and the platform applied
make deploy IMAGE_TAG=vX.Y.Z
make scan      # start a passive run now (PROFILE=active attacks)
```

## Commit messages

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/), enforced by commitlint at commit-msg time.

## CI

- **ci-pre-commit**: all hooks, via the shared `pre-commit.yml`.
- **ci-python**: pytest on Python 3.11 (matches the ZAP image), via the shared `python.yml`.
- **ci-container-build**: builds the image without pushing. A `changes` job path-filters the build rather than the trigger, so the always-reporting `container-build` gate can be (and is) a required check.
- **ci-terraform**: `validate` via the shared `terraform.yml` (`terraform / Terraform`), then a dev plan via the shared `terraform-deploy.yml`, commented on the PR, behind the always-reporting `terraform-plan` gate. `terraform-deploy.yml` runs in the `dev` GitHub environment, where `github-repos` sets `AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/`AZURE_SUBSCRIPTION_ID` and federates this repo's OIDC identity to `<repo prefix>:environment:dev`; callers pass no credentials. Only dev is planned: it is the only platform environment with an identity.
- **cd-terraform**: applies dev on every merge to `main` that touches Terraform, through the same `terraform-deploy.yml` (plan, then apply that exact plan; skipped when nothing changed; `workflow_dispatch` re-runs it). Don't `make apply` dev after a merge. The pipeline identity is only Contributor on `rg-sectest-dev`, so a change that adds or replaces a role assignment fails there and needs a local `make apply`. Key Vault and reports access go to `administrator_object_id` in `environments/dev.tfvars`, never to "whoever applies", or every pipeline run would try to move them to itself. The scanner identity's subscription-scope Reader grants (`main.identity.tf`) are role assignments too.
- **cd-tag** → **cd-publish**: semver tag on merge, then the GHCR publish when image sources changed.
