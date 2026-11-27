# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183

# Container Apps runs linux/amd64 only. Every build for deployment must pass
# --platform linux/amd64 — the Makefile's `build` target does it rather than
# leaving it to memory.

# Node comes from dev-containers' node-app, the estate's Node runtime base, not
# apt (Debian's nodejs is years behind). This image can't be built FROM it, as
# its base has to be ZAP's, so the node binary is copied out of it below. Both
# are Debian bookworm, so it runs on the ZAP image's glibc as it is. node-app's
# Node should be the release mise.toml pins, which local runs and ci-node test
# on (ci-container-build checks the majors match). Renovate moves node-app and
# node-app-builder together, in one PR, at any time.
FROM ghcr.io/jay-withers/dev-containers/node-app:v0.25.1@sha256:b85c9fbc858c750d8cc20cd040a924561fd45b89381da4c9c7ebcee70bed862b AS node

# Production dependencies only, installed by node-app-builder (node-app plus
# that Node release's npm), at node-app's version. --omit=dev overrides the
# builder's NODE_ENV=development. --ignore-scripts, as in CI: none of them
# needs an install script, and none gets to run one. npm ci fails rather than
# resolving anything package-lock.json doesn't record.
FROM ghcr.io/jay-withers/dev-containers/node-app-builder:v0.25.1@sha256:bcb0a63e11c6da407e59b506b4f53d30c0bf139329006c22a9f7e40a2b57c872 AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev --ignore-scripts

# The ZAP image is the base, not a node image with ZAP added: the packaged
# scans (zap-baseline.py and friends) are thin Python wrappers around a JVM
# daemon, and reproducing their Java, add-ons and scripts layout ourselves would
# be a second ZAP install to keep current. Renovate bumps this digest.
FROM zaproxy/zap-stable:2.17.0@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af AS runtime

# Connects the pushed package to this repository, which is what gives a
# workflow's GITHUB_TOKEN write access to it.
LABEL org.opencontainers.image.source="https://github.com/jay-withers/security-testing"

# For the zap-*.py wrappers, which still run on the system Python: unbuffered,
# so their output interleaves with the scanner's log lines in order.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NODE_ENV=production

# Patch the vendor image in one root layer, because Trivy fails a build on
# fixable HIGH/CRITICAL findings and the ZAP image ships them between its own
# releases:
#
# - apt-get upgrade: Debian bookworm packages with published fixes (firefox-esr,
#   jq, libexpat1, libbrotli1, linux-libc-dev were the first).
# - /zap/webswing goes: it is ZAP's in-browser desktop GUI and carries its own
#   Jetty (CVEs in jetty-http/-server/-security). The packaged headless scans
#   (zap-baseline.py, zap-full-scan.py) never start it.
# - Every pip-installed package in the system Python (/usr/local, where the
#   image put the `zaproxy` client the zap-*.py scripts run under, plus awscli,
#   requests, pyasn1, rsa and their dependencies) is upgraded in one resolve,
#   which keeps each package's own pins, and `pip check` fails the build if the
#   result is inconsistent. All of them, not a named list: the list (certifi,
#   urllib3, then pyasn1) only ever grew after a CVE had already failed the
#   gate on every open PR. Debian's own /usr/lib/python3 packages are apt's,
#   covered by the upgrade above. Then pip itself goes, since it vendors stale
#   copies of certifi and urllib3 (plus msgpack and setuptools' pkg_resources)
#   and nothing at runtime installs anything. The image carries Debian's
#   python3-pip and a newer pip in /usr/local, so both go: apt for the one,
#   then pip uninstall until no pip answers.
# - tini, as PID 1. The ZAP wrapper exits leaving its JVM behind, which is
#   re-parented to PID 1. The Python scanner reaped it there with os.waitpid;
#   Node only reaps its own children, so with node as PID 1 the dead JVM would
#   stay a zombie, answer kill(-pgid, 0) as alive, and make every scan wait out
#   the 120s shutdown grace before the next could start. tini reaps it.
# - The packaged scans refuse to write reports unless /zap/wrk exists — they
#   expect a bind mount, and the image does not create it. Created here as root,
#   so it is handed to uid 1000 explicitly.
USER 0
#
# OS_PATCH_DATE is today's date, passed by jay-withers/workflows' docker.yml.
# The CI build caches layers by instruction, so declaring it here makes this
# layer re-run once a day; without it the upgrade was reused from whenever the
# layer was first cached, and fixes published since never got in.
ARG OS_PATCH_DATE
# hadolint ignore=DL3008,DL3013
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /zap/webswing \
    && site="$(python3 -c 'import sysconfig; print(sysconfig.get_path("purelib"))')" \
    && python3 -m pip list --path "$site" --format=freeze --exclude pip \
         > /tmp/system-python.txt \
    && sed -i 's/==.*//' /tmp/system-python.txt \
    && test -s /tmp/system-python.txt \
    && python3 -m pip install --no-cache-dir --break-system-packages --upgrade \
         -r /tmp/system-python.txt \
    && python3 -m pip check \
    && rm /tmp/system-python.txt \
    && if dpkg -s python3-pip >/dev/null 2>&1; then apt-get purge -y python3-pip; fi \
    && while python3 -m pip --version >/dev/null 2>&1; do \
         python3 -m pip uninstall -y --break-system-packages pip || exit 1; \
       done \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /zap/wrk \
    && chown 1000:1000 /zap/wrk

COPY --from=node /usr/local/bin/node /usr/local/bin/node

# Root-owned and read-only to the scanner: it writes nothing but reports, and
# those go to /zap/wrk. package.json is what makes the .ts files ES modules.
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src

# The ZAP image's own `zap` user, by number: a runtime enforcing runAsNonRoot
# has to resolve the user before the container starts.
USER 1000

# A batch job: there is no long-running process for a health check to probe,
# and Container Apps jobs do not run Docker HEALTHCHECKs. Disable the base
# image's, which polls a ZAP API port that is only open mid-scan.
HEALTHCHECK NONE

# Node runs the TypeScript sources directly (type stripping), so there is no
# build output to ship. The zap-*.py scripts still run via
# `#!/usr/bin/env python3` on the system interpreter, where the base image
# installed their `zaproxy` client, so nothing here touches that Python.
# `sectest selfcheck` passes `selfcheck` through as main.ts's argument.
#
# This ENTRYPOINT is the single source of truth for the command.
ENTRYPOINT ["/usr/bin/tini", "--", "node", "/app/src/main.ts"]
