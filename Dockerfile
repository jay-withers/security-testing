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

# The builder needs root to write /app and uv's cache under /root; nothing from
# this stage runs — only the venv is copied out, and the runtime stage below
# ends on uid 1000. Numeric so it resolves without /etc/passwd.
# hadolint ignore=DL3002
USER 0

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

# Patch the vendor image in one root layer, because Trivy fails a build on
# fixable HIGH/CRITICAL findings and the ZAP image ships them between its own
# releases:
#
# - apt-get upgrade: Debian bookworm packages with published fixes (firefox-esr,
#   jq, libexpat1, libbrotli1, linux-libc-dev were the first).
# - /zap/webswing goes: it is ZAP's in-browser desktop GUI and carries its own
#   Jetty (CVEs in jetty-http/-server/-security). The packaged headless scans
#   (zap-baseline.py, zap-full-scan.py) never start it.
# - certifi and urllib3 are upgraded in the system Python, which the zap-*.py
#   scripts run under for their `zaproxy` client; then pip itself goes, since it
#   vendors stale copies of both (plus msgpack and setuptools' pkg_resources)
#   and nothing at runtime installs anything. The image carries Debian's
#   python3-pip and a newer pip in /usr/local, so both go: apt for the one,
#   then pip uninstall until no pip answers.
# - The packaged scans refuse to write reports unless /zap/wrk exists — they
#   expect a bind mount, and the image does not create it. Created here as root,
#   so it is handed to uid 1000 explicitly.
USER 0
# hadolint ignore=DL3008,DL3013
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /zap/webswing \
    && python3 -m pip install --no-cache-dir --break-system-packages --upgrade certifi urllib3 \
    && if dpkg -s python3-pip >/dev/null 2>&1; then apt-get purge -y python3-pip; fi \
    && while python3 -m pip --version >/dev/null 2>&1; do \
         python3 -m pip uninstall -y --break-system-packages pip || exit 1; \
       done \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /zap/wrk \
    && chown 1000:1000 /zap/wrk

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
