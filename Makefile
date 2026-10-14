TF_DIR := terraform
# Every state-touching target initialises against backends/$(ENV).hcl and plans
# with environments/$(ENV).tfvars. dev is the only environment that exists.
ENV ?= dev

IMAGE_REGISTRY ?= ghcr.io/jay-withers/security-testing
# Defaults to the local commit, which is what you want when iterating: build,
# push, and the tag you just built is the one you reference.
IMAGE_TAG ?= $(shell git rev-parse --short HEAD)
# `file` means the ?= default fired rather than the caller passing one.
IMAGE_TAG_EXPLICIT := $(filter-out file,$(origin IMAGE_TAG))

# Which scanner job `scan` and `logs` act on: passive (nightly, every app,
# nothing attacked) or active (weekly, sends attack payloads).
PROFILE ?= passive

.DEFAULT_GOAL := help

.PHONY: help install lint test build push deploy scan logs reports init fmt validate plan apply

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

# Expected to be re-run after a dev container rebuild, not just after a clone:
# uv installs into ~/.local/bin, which does not survive one.
install: ## Install pre-commit hooks and Python dependencies
	pre-commit install
	pre-commit install --hook-type commit-msg
	command -v uv >/dev/null || curl -fsSL https://astral.sh/uv/install.sh | sh
	uv sync --extra dev

test: ## Run the test suite (no Azure, no ZAP)
	uv run --extra dev pytest

lint: ## Run every pre-commit hook against every file
	pre-commit run --all-files

# `--platform linux/amd64` is not optional: Container Apps runs amd64 only, and
# the ZAP base image is amd64-only too.
build: ## Build the image for linux/amd64 (set IMAGE_TAG, defaults to the git SHA)
	docker buildx build --platform linux/amd64 --load \
		-t $(IMAGE_REGISTRY)/sectest:$(IMAGE_TAG) .

push: ## Push the image to ghcr.io (needs write:packages)
	gh auth token | docker login ghcr.io -u $$(gh api user --jq .login) --password-stdin
	docker push $(IMAGE_REGISTRY)/sectest:$(IMAGE_TAG)

# A bare `make deploy` is a hard error: the default tag is the local commit,
# which may never have been pushed to ghcr.io at all.
# Both jobs, always together: they run the same image, and a deploy that moved
# one would leave the passive and active scans running different scanner code.
deploy: ## Roll an image tag onto both scanner jobs (IMAGE_TAG required)
	@if [ -z "$(IMAGE_TAG_EXPLICIT)" ]; then \
		echo "error: pass a tag explicitly, e.g. make deploy IMAGE_TAG=v0.1.0" >&2; exit 1; fi
	@case "$(IMAGE_TAG)" in latest|main|unset) \
		echo "error: $(IMAGE_TAG) is a moving tag. Container Apps only creates a revision when the template changes, so re-pushing one deploys nothing and reports success." >&2; exit 1;; esac
	$(MAKE) --no-print-directory init
	@for profile in passive active; do \
		echo "==> $$profile"; \
		az containerapp job update \
			--name "$$(terraform -chdir=$(TF_DIR) output -raw scanner_job_name_$$profile)" \
			--resource-group "$$(terraform -chdir=$(TF_DIR) output -raw resource_group_name)" \
			--image $(IMAGE_REGISTRY)/sectest:$(IMAGE_TAG) || exit 1; \
	done

scan: init ## Start a scan now (PROFILE=passive by default; PROFILE=active attacks)
	az containerapp job start \
		--name "$$(terraform -chdir=$(TF_DIR) output -raw scanner_job_name_$(PROFILE))" \
		--resource-group "$$(terraform -chdir=$(TF_DIR) output -raw resource_group_name)"

logs: init ## Show the latest run's log lines (PROFILE=passive by default)
	az containerapp job logs show \
		--name "$$(terraform -chdir=$(TF_DIR) output -raw scanner_job_name_$(PROFILE))" \
		--resource-group "$$(terraform -chdir=$(TF_DIR) output -raw resource_group_name)" \
		--container scanner

# Entra auth only — the storage account has shared keys disabled.
reports: init ## List the latest run summaries in Blob Storage
	az storage blob list --auth-mode login \
		--account-name "$$(terraform -chdir=$(TF_DIR) output -raw reports_storage_account_name)" \
		--container-name reports --query "[?ends_with(name, 'summary.json')].name | sort(@) | [-5:]" -o tsv

init: ## terraform init against the ENV backend (default dev)
	terraform -chdir=$(TF_DIR) init -reconfigure -backend-config=backends/$(ENV).hcl

fmt: ## terraform fmt -recursive
	terraform -chdir=$(TF_DIR) fmt -recursive

# Deliberately not `init`: validate must work with no Azure credentials (CI,
# a fresh clone), so it skips the backend entirely.
validate: ## terraform init -backend=false + validate (no Azure credentials needed)
	terraform -chdir=$(TF_DIR) init -backend=false
	terraform -chdir=$(TF_DIR) validate

plan: init ## terraform init + plan (ENV, default dev)
	terraform -chdir=$(TF_DIR) plan -var-file=environments/$(ENV).tfvars

apply: init ## terraform init + apply (ENV, default dev)
	terraform -chdir=$(TF_DIR) apply -var-file=environments/$(ENV).tfvars
