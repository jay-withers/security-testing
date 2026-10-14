"""DAST scanner for Azure Container Apps.

Discovers Container Apps with external ingress via Azure Resource Graph, runs an
OWASP ZAP scan against each one, and uploads the reports to Blob Storage.

Two profiles run the same image, selected by SCAN_PROFILE:

  passive   nightly. Every app; spider + passive rules only, nothing is attacked.
  active    weekly. Every app that has not opted out; sends attack payloads.

Active scanning is **opt-out**. Per-app behaviour is controlled by tags on the
target Container App:

  security-scan = "false"                  skip this app in both profiles
  security-scan-mode = "passive"           opt out of the active profile only
  security-scan-openapi = "/openapi.json"  scan the API in this spec instead of spidering

zap-api-scan.py is active by default, so the passive profile passes it -S
(safe mode) — an openapi tag never turns a passive run into an attack.

Configuration comes from environment variables (set by the Terraform module):

  TARGET_SUBSCRIPTION_IDS  comma-separated subscription IDs to discover apps in
  REPORT_CONTAINER_URL     blob container for reports, e.g. https://acct.blob.core.windows.net/reports
  SCAN_FAIL_ON             lowest risk flagged as over_threshold: Low|Medium|High (default High)
  SCAN_SPIDER_MINUTES      spider time cap per target (default 5)
  SCAN_TARGET_TIMEOUT      hard timeout per target in seconds (default 1800)
  SCAN_PROFILE             passive | active (default passive — the safe one)
  ENVIRONMENT              recorded in the run summary
  LOG_SOURCE               stamped on every log line; the findings alert filters on it
  AZURE_CLIENT_ID          user-assigned managed identity (read by DefaultAzureCredential)

Exit status is 0 whenever every scan ran, **even if it found something**. A
non-zero exit fails the job execution, which the shared platform's
workload-crashed alert reads as "this workload is broken". Findings are reported
as `scan_finished` lines with `over_threshold: true` instead, and alerted on by
terraform/main.alerts.tf.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import signal
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

ZAP_WORK_DIR = Path("/zap/wrk")

# Sent on every request, so the scan is identifiable in ContainerAppHTTPLogs
# and the platform's app-error alert can exclude it rather than fire on it.
USER_AGENT = "sectest-dast-scanner (OWASP ZAP; +https://github.com/jay-withers/security-testing)"
LOG_SOURCE = os.environ.get("LOG_SOURCE", "sectest")

RESOURCE_GRAPH_QUERY = """
resources
| where type =~ 'microsoft.app/containerapps'
| where tobool(properties.configuration.ingress.external) == true
| project id, name, resourceGroup, subscriptionId,
          fqdn = tostring(properties.configuration.ingress.fqdn),
          runningStatus = tostring(properties.runningStatus),
          tags
"""

TAG_ENABLED = "security-scan"
TAG_OPENAPI = "security-scan-openapi"
TAG_MODE = "security-scan-mode"

PROFILES = ("passive", "active")

# (has openapi tag, profile) -> mode. Only the *full modes are active.
SCAN_MODES = {
    (False, "passive"): "baseline",
    (False, "active"): "full",
    (True, "passive"): "api",
    (True, "active"): "api-full",
}

# ZAP traditional-json riskcode values.
RISK_LEVELS = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
RISK_NAMES = {v: k for k, v in RISK_LEVELS.items()}


@dataclass
class Target:
    id: str
    name: str
    resource_group: str
    subscription_id: str
    fqdn: str
    mode: str  # baseline | full | api | api-full — only *full modes are active
    openapi_path: str | None = None

    @property
    def url(self) -> str:
        return f"https://{self.fqdn}"

    @property
    def slug(self) -> str:
        return re.sub(r"[^a-z0-9-]", "-", f"{self.resource_group}-{self.name}".lower())


@dataclass
class ScanResult:
    target: Target
    status: str  # completed | error | timeout
    exit_code: int | None = None
    risk_counts: dict[str, int] = field(default_factory=dict)
    report_prefix: str | None = None
    error: str | None = None


def log(event: str, **fields) -> None:
    """One JSON line per event, so it can be queried in Log Analytics."""
    print(json.dumps({"source": LOG_SOURCE, "event": event, **fields}, default=str), flush=True)


def select_targets(rows: list[dict], profile: str = "passive") -> tuple[list[Target], list[dict]]:
    """Turn Resource Graph rows into scan targets for a profile, applying the tag filters.

    Returns (targets, skipped) where skipped entries explain why.
    """
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}, not {profile!r}")
    targets: list[Target] = []
    skipped: list[dict] = []
    for row in rows:
        tags = {k.lower(): str(v) for k, v in (row.get("tags") or {}).items()}
        name = row.get("name", "")
        fqdn = (row.get("fqdn") or "").strip()

        openapi_path = tags.get(TAG_OPENAPI)

        reason = None
        if tags.get(TAG_ENABLED, "").lower() == "false":
            reason = "opted out via tag"
        elif not fqdn:
            reason = "no ingress FQDN"
        elif (row.get("runningStatus") or "").lower() == "stopped":
            reason = "app is stopped"
        elif openapi_path is not None and not openapi_path.startswith("/"):
            reason = f"{TAG_OPENAPI} must be a path starting with '/'"
        elif profile == "active" and tags.get(TAG_MODE, "").lower() == "passive":
            reason = "opted out of active scans via tag"
        if reason:
            skipped.append({"id": row.get("id"), "name": name, "reason": reason})
            continue

        mode = SCAN_MODES[(bool(openapi_path), profile)]

        targets.append(
            Target(
                id=row.get("id", ""),
                name=name,
                resource_group=row.get("resourceGroup", ""),
                subscription_id=row.get("subscriptionId", ""),
                fqdn=fqdn,
                mode=mode,
                openapi_path=openapi_path,
            )
        )
    return targets, skipped


def build_command(target: Target, spider_minutes: int) -> list[str]:
    """ZAP packaged-scan command line for a target. Reports land in /zap/wrk."""
    reports = [
        "-J",
        f"{target.slug}.json",
        "-r",
        f"{target.slug}.html",
        "-w",
        f"{target.slug}.md",
    ]
    # -I: don't fail on warnings — severity is judged from the JSON report.
    common = ["-I", "-z", f"-config connection.defaultUserAgent='{USER_AGENT}'", *reports]
    if target.mode in ("api", "api-full"):
        return [
            "zap-api-scan.py",
            "-t",
            f"{target.url}{target.openapi_path}",
            "-f",
            "openapi",
            # -S: safe mode, skipping the active scan. zap-api-scan.py attacks
            # by default, so passive has to be asked for explicitly here.
            *(["-S"] if target.mode == "api" else []),
            *common,
        ]
    script = "zap-full-scan.py" if target.mode == "full" else "zap-baseline.py"
    return [script, "-t", target.url, "-m", str(spider_minutes), *common]


def count_risks(report: dict) -> dict[str, int]:
    """Count alerts by risk level from a ZAP traditional-json report."""
    counts = {name: 0 for name in RISK_LEVELS}
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            try:
                code = int(alert.get("riskcode", 0))
            except (TypeError, ValueError):
                continue
            counts[RISK_NAMES.get(code, "Informational")] += 1
    return counts


def exceeds_threshold(counts: dict[str, int], fail_on: str) -> bool:
    threshold = RISK_LEVELS[fail_on]
    return any(n > 0 and RISK_LEVELS[risk] >= threshold for risk, n in counts.items())


def run_scan(target: Target, spider_minutes: int, timeout: int) -> ScanResult:
    cmd = build_command(target, spider_minutes)
    log("scan_started", target=target.name, url=target.url, mode=target.mode)
    # New session so a timeout can kill the whole process group — the ZAP
    # wrapper scripts start a JVM daemon that would otherwise outlive them.
    proc = subprocess.Popen(cmd, cwd=ZAP_WORK_DIR, start_new_session=True)
    try:
        exit_code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        return ScanResult(target, "timeout", error=f"exceeded {timeout}s")

    # ZAP exit codes: 0 pass, 1 FAIL rules hit, 2 WARN only, 3 other failure.
    report_path = ZAP_WORK_DIR / f"{target.slug}.json"
    if exit_code == 3 or not report_path.exists():
        return ScanResult(target, "error", exit_code, error="ZAP did not produce a report")
    counts = count_risks(json.loads(report_path.read_text()))
    return ScanResult(target, "completed", exit_code, risk_counts=counts)


def discover_targets(credential, subscription_ids: list[str]) -> list[dict]:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    client = ResourceGraphClient(credential)
    rows: list[dict] = []
    skip_token = None
    while True:
        response = client.resources(
            QueryRequest(
                subscriptions=subscription_ids,
                query=RESOURCE_GRAPH_QUERY,
                options=QueryRequestOptions(skip_token=skip_token, result_format="objectArray"),
            )
        )
        rows.extend(response.data)
        skip_token = response.skip_token
        if not skip_token:
            return rows


def upload_reports(container_client, run_prefix: str, result: ScanResult) -> None:
    from azure.storage.blob import ContentSettings

    t = result.target
    prefix = f"{run_prefix}/{t.subscription_id}/{t.resource_group}/{t.name}"
    content_types = {"json": "application/json", "html": "text/html", "md": "text/markdown"}
    for ext, content_type in content_types.items():
        path = ZAP_WORK_DIR / f"{t.slug}.{ext}"
        if path.exists():
            with path.open("rb") as fh:
                container_client.upload_blob(
                    f"{prefix}/report.{ext}",
                    fh,
                    overwrite=True,
                    content_settings=ContentSettings(content_type=content_type),
                )
    result.report_prefix = prefix


def main() -> int:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import ContainerClient

    subscription_ids = [s.strip() for s in os.environ["TARGET_SUBSCRIPTION_IDS"].split(",") if s.strip()]
    container_url = os.environ["REPORT_CONTAINER_URL"]
    fail_on = os.environ.get("SCAN_FAIL_ON", "High")
    if fail_on not in RISK_LEVELS:
        log("config_error", error=f"SCAN_FAIL_ON must be one of {list(RISK_LEVELS)}")
        return 2
    profile = os.environ.get("SCAN_PROFILE", "passive")
    if profile not in PROFILES:
        log("config_error", error=f"SCAN_PROFILE must be one of {list(PROFILES)}")
        return 2
    spider_minutes = int(os.environ.get("SCAN_SPIDER_MINUTES", "5"))
    timeout = int(os.environ.get("SCAN_TARGET_TIMEOUT", "1800"))

    started = dt.datetime.now(dt.UTC)
    # The profile is in the path so a passive and an active run on the same
    # day are told apart at a glance in `make reports`.
    run_prefix = f"{started:%Y-%m-%d/%H%M%SZ}-{profile}"

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    targets, skipped = select_targets(discover_targets(credential, subscription_ids), profile)
    for s in skipped:
        log("target_skipped", **s)
    log("discovery_complete", profile=profile, targets=len(targets), skipped=len(skipped))

    container_client = ContainerClient.from_container_url(container_url, credential=credential)

    results: list[ScanResult] = []
    for target in targets:
        try:
            result = run_scan(target, spider_minutes, timeout)
            upload_reports(container_client, run_prefix, result)
        except Exception as exc:  # one bad target must not stop the run
            result = ScanResult(target, "error", error=str(exc))
        results.append(result)
        log(
            "scan_finished",
            target=target.name,
            url=target.url,
            profile=profile,
            mode=target.mode,
            status=result.status,
            risks=result.risk_counts,
            report=result.report_prefix,
            error=result.error,
            over_threshold=exceeds_threshold(result.risk_counts, fail_on),
        )

    failing = [r for r in results if exceeds_threshold(r.risk_counts, fail_on)]
    errored = [r for r in results if r.status != "completed"]
    summary = {
        "environment": os.environ.get("ENVIRONMENT"),
        "profile": profile,
        "started": started.isoformat(),
        "finished": dt.datetime.now(dt.UTC).isoformat(),
        "fail_on": fail_on,
        "results": [{**asdict(r), "target": {**asdict(r.target), "url": r.target.url}} for r in results],
        "skipped": skipped,
    }
    container_client.upload_blob(f"{run_prefix}/summary.json", json.dumps(summary, indent=2), overwrite=True)
    log(
        "run_complete",
        scanned=len(results),
        failing=len(failing),
        errored=len(errored),
        summary=f"{run_prefix}/summary.json",
    )

    # Findings alone never fail the run — see the module docstring.
    return 1 if errored else 0


def cli() -> None:
    """Console-script entry point (`sectest`), which the image's ENTRYPOINT names."""
    sys.exit(main())


if __name__ == "__main__":
    cli()
