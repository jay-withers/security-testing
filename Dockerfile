# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Container Apps runs linux/amd64 only. Every build for deployment must pass
# --platform linux/amd64 — the Makefile's `build` target does it rather than
# leaving it to memory.

# The ZAP image is the base, not a python image with ZAP added: the packaged
# scans (zap-baseline.py and friends) are thin Python wrappers around a JVM
# daemon, and reproducing their Java, add-ons and scripts layout ourselves would
# be a second ZAP install to keep current. Renovate bumps this digest.
#
# Builder and runtime both derive from `base`, so the virtualenv is built by the
# same interpreter (bookworm's python3, 3.11) that runs it — a venv is bound to
# the exact minor version that created it.
FROM zaproxy/zap-stable:2.17.0@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2 AS base


FROM base AS builder

USER root

COPY --from=ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/bin/python3

WORKDIR /app

# Dependencies before source, so editing a module does not re-resolve the whole
# environment. --frozen fails rather than silently updating uv.lock.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev --no-editable

COPY src ./src
# --no-editable: the runtime stage copies only the virtualenv, so an editable
# install's link back to /app/src would point at nothing there.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable


FROM base AS runtime

# Connects the pushed package to this repository, which is what gives a
# workflow's GITHUB_TOKEN write access to it.
LABEL org.opencontainers.image.source="https://github.com/jay-withers/security-testing"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER root
# The packaged scans refuse to write reports unless /zap/wrk exists — they
# expect it to be a bind mount, and the image does not create it.
RUN mkdir -p /zap/wrk && chown 1000:1000 /zap/wrk

COPY --from=builder --chown=1000:1000 /app/.venv /app/.venv

# The ZAP image's own `zap` user, by number: a runtime enforcing runAsNonRoot
# has to resolve the user before the container starts.
USER 1000

# A batch job: there is no long-running process for a health check to probe,
# and Container Apps jobs do not run Docker HEALTHCHECKs. Disable the base
# image's, which polls a ZAP API port that is only open mid-scan.
HEALTHCHECK NONE

# **The virtualenv is deliberately not on PATH.** The zap-*.py scripts run via
# `#!/usr/bin/env python3` and need the system interpreter, where the base image
# installed their `zaproxy` client; a venv first on PATH would hand them an
# interpreter without it, and every scan would die on an ImportError.
#
# This ENTRYPOINT is the single source of truth for the executable's name.
ENTRYPOINT ["/app/.venv/bin/sectest"]
