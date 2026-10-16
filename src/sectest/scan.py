"""DAST scanner for Azure Container Apps.

Discovers Container Apps with external ingress via Azure Resource Graph, runs an
OWASP ZAP scan against each one, and uploads the reports to Blob Storage.

Two profiles run the same image, selected by SCAN_PROFILE:

  passive   weekly. Every app; spider + passive rules only, nothing is attacked.
            Ends by emailing a digest of what changed (digest.py).
  active    on demand only (no schedule). Every app that has not opted out;
            sends attack payloads. Ends by emailing its findings (digest.py).

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
  KEY_VAULT_URI            vault holding RESEND-API-KEY and DIGEST-EMAIL-TO (see mailer.py)
  DIGEST_EMAIL_FROM        sender of the digest, on a domain verified in Resend
  AZURE_CLIENT_ID          user-assigned managed identity (read by DefaultAzureCredential)

Exit status is 0 whenever every scan ran, **even if it found something**. A
non-zero exit fails the job execution, which the shared platform's
workload-crashed alert reads as "this workload is broken". Findings are reported
as `scan_finished` lines with `over_threshold: true` instead. A passive run's
are alerted on by terraform/main.alerts.tf; an active run's arrive by email.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

ZAP_WORK_DIR = Path("/zap/wrk")

# Sent on every request, so the scan is identifiable in ContainerAppHTTPLogs
# and the platform's app-error alert can exclude it rather than fire on it.
USER_AGENT = "sectest-dast-scanner (OWASP ZAP; +https://github.com/jay-withers/security-testing)"
LOG_SOURCE = os.environ.get("LOG_SOURCE", "sectest")

# Apps on the platform scale to zero, so the first request to one waits for a
# replica to cold-start — longer than ZAP's default read timeout, which made
# every cold app's scan fail with "Read timed out" and no report. warm_up()
# wakes each app before ZAP starts; the longer ZAP timeout is the backstop for
# an app that scales back down mid-scan.
WARM_UP_DEADLINE_SECONDS = 180
WARM_UP_REQUEST_TIMEOUT_SECONDS = 60
WARM_UP_RETRY_SECONDS = 10
# What Envoy returns while no replica is ready yet; anything else (a 401, a
# 404) means the app itself answered, so it is awake.
COLD_START_STATUSES = {502, 503, 504}
# An app is woken one ahead of its scan (warm_ahead). A warm-up older than this
# by the time its scan starts is redone: the scan before it ran long (an active
# scan can take an hour), and the app may have scaled back to zero since. Well
# under the ~300s idle period after which Container Apps scales an app to zero.
WARM_UP_STALE_SECONDS = 120
ZAP_READ_TIMEOUT_SECONDS = 120
# The packaged scans end by asking ZAP to shut down and exit without waiting
# for the JVM. Until it has gone it holds the lock on ZAP's home directory, and
# the next scan's ZAP refuses to start ("The home directory is already in
# use"), so the wrapper waits 600s for it and fails with no report. After an
# active scan the JVM takes long enough to exit that every other app failed.
# run_scan waits this long for the JVM to exit, then kills it.
ZAP_SHUTDOWN_GRACE_SECONDS = 120
ZAP_SHUTDOWN_POLL_SECONDS = 1.0

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
    zap_options = (
        f"-config connection.defaultUserAgent='{USER_AGENT}' "
        f"-config connection.timeoutInSecs={ZAP_READ_TIMEOUT_SECONDS}"
    )
    common = ["-I", "-z", zap_options, *reports]
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


def _fetch_status(url: str, timeout: float) -> int:
    """HTTP status of a GET, error statuses included rather than raised."""
    # S310: the URL is always https://<fqdn> built in Target.url, never caller-supplied.
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    try:
        # S310: the URL is always https://<fqdn> built in Target.url, never caller-supplied.
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def warm_up(
    url: str,
    fetch=_fetch_status,
    sleep=time.sleep,
    clock=time.monotonic,
    deadline: float = WARM_UP_DEADLINE_SECONDS,
) -> tuple[bool, str]:
    """Wake a scale-to-zero app before scanning it.

    Retries until the app itself answers (any status but a cold-start 5xx) or
    the deadline passes. Returns (awake, detail) — detail is the last status or
    error, for the log line.
    """
    give_up_at = clock() + deadline
    while True:
        try:
            status = fetch(url, WARM_UP_REQUEST_TIMEOUT_SECONDS)
            if status not in COLD_START_STATUSES:
                return True, f"HTTP {status}"
            detail = f"HTTP {status}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            detail = f"{type(exc).__name__}: {exc}"
        if clock() + WARM_UP_RETRY_SECONDS >= give_up_at:
            return False, detail
        sleep(WARM_UP_RETRY_SECONDS)


def warm_ahead(
    targets: list[Target], warm: Callable[[Target], tuple[bool, str]]
) -> Iterator[tuple[Target, Future]]:
    """Yield each target with its warm-up, starting the next one's early.

    Scans stay one at a time, but each app's cold start (~25s measured)
    happens while the previous app is being scanned rather than before its
    own scan. Only one app ahead, not all of them at the start: Container Apps
    scales an idle app back to zero after about five minutes, so with enough
    apps the later ones would fall asleep again before their turn.
    """
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="warm-up")
    try:
        upcoming = pool.submit(warm, targets[0]) if targets else None
        for i, target in enumerate(targets):
            current = upcoming
            upcoming = pool.submit(warm, targets[i + 1]) if i + 1 < len(targets) else None
            yield target, current
    finally:
        # Not a `with` block, which would wait out an in-flight warm-up (up to
        # WARM_UP_DEADLINE_SECONDS) before an interrupt could surface.
        pool.shutdown(wait=False, cancel_futures=True)


def fresh_warm_up(
    target: Target,
    warmed: tuple[bool, str, float],
    clock: Callable[[], float] = time.monotonic,
    rewarm: Callable[[str], tuple[bool, str]] = lambda url: warm_up(url),
) -> tuple[bool, str]:
    """An early warm-up's result, or a new one if it has gone stale."""
    awake, detail, finished_at = warmed
    if clock() - finished_at > WARM_UP_STALE_SECONDS:
        return rewarm(target.url)
    return awake, detail


def _timed_warm_up(target: Target) -> tuple[bool, str, float]:
    awake, detail = warm_up(target.url)
    return awake, detail, time.monotonic()


def scan_target(
    target: Target,
    warming: Future,
    spider_minutes: int,
    timeout: int,
    scan: Callable[..., ScanResult] | None = None,
    fresh: Callable[[Target, tuple[bool, str, float]], tuple[bool, str]] = fresh_warm_up,
) -> ScanResult:
    """Scan one target with its early warm-up, re-waking it first if stale."""
    scan = scan or run_scan
    return scan(target, spider_minutes, timeout, warmed=fresh(target, warming.result()))


def _process_group_alive(pgid: int) -> bool:
    # Reap exited members first. The image's ENTRYPOINT is PID 1, so the JVM
    # the wrapper orphaned is re-parented to this process, and as an unreaped
    # zombie it would still answer signal 0 after it has exited.
    while True:
        try:
            pid, _ = os.waitpid(-pgid, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            break
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    return True


def stop_process_group(
    pgid: int,
    grace: float = ZAP_SHUTDOWN_GRACE_SECONDS,
    poll: float = ZAP_SHUTDOWN_POLL_SECONDS,
) -> bool:
    """Wait up to grace seconds for a process group to exit, then SIGKILL it.

    Returns True if it had to be killed.
    """
    deadline = time.monotonic() + grace
    while _process_group_alive(pgid):
        if time.monotonic() >= deadline:
            break
        time.sleep(poll)
    else:
        return False
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return False
    kill_deadline = time.monotonic() + 10
    while _process_group_alive(pgid) and time.monotonic() < kill_deadline:
        time.sleep(0.1)
    return True


def run_scan(
    target: Target, spider_minutes: int, timeout: int, warmed: tuple[bool, str] | None = None
) -> ScanResult:
    awake, detail = warmed if warmed is not None else warm_up(target.url)
    # Scanned either way: ZAP's own, longer timeout may still get through, and
    # a failed scan is reported as an error rather than silently skipped.
    log("warm_up", target=target.name, url=target.url, awake=awake, detail=detail)
    cmd = build_command(target, spider_minutes)
    log("scan_started", target=target.name, url=target.url, mode=target.mode)
    # New session so a timeout can kill the whole process group — the ZAP
    # wrapper scripts start a JVM daemon that would otherwise outlive them.
    # S603: argument list, no shell; the script names are fixed and the target URL is one this module built.
    proc = subprocess.Popen(cmd, cwd=ZAP_WORK_DIR, start_new_session=True)  # noqa: S603
    try:
        exit_code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_process_group(proc.pid, grace=0)
        proc.wait()
        return ScanResult(target, "timeout", error=f"exceeded {timeout}s")
    # The wrapper has exited, but ZAP's JVM (same process group) may not have.
    if stop_process_group(proc.pid):
        log("zap_killed", target=target.name, grace_seconds=ZAP_SHUTDOWN_GRACE_SECONDS)

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
    uploaded = False
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
            uploaded = True
    # Only set when something is actually there, so a failed scan's log line
    # and summary entry don't point at an empty path.
    if uploaded:
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
    for target, warming in warm_ahead(targets, _timed_warm_up):
        try:
            result = scan_target(target, warming, spider_minutes, timeout)
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

    # After the summary is uploaded, because the digest reads it back. It never
    # raises, so it cannot change the exit code.
    from .digest import send_digest

    send_digest(container_client, credential, run_prefix, os.environ.get("DIGEST_EMAIL_FROM", ""))

    # Findings alone never fail the run — see the module docstring.
    return 1 if errored else 0


def cli() -> None:
    """Console-script entry point (`sectest`), which the image's ENTRYPOINT names."""
    sys.exit(main())


if __name__ == "__main__":
    cli()
