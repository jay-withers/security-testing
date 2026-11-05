"""The glue around ZAP: how a run is classified, killed, discovered and stored.

test_scan.py covers the pure functions. This covers what decides whether a
scan *counts*: a ZAP that crashed or hung must come out as `error` or
`timeout`, never as a clean `completed`, and an app on a second page of
Resource Graph results must still be scanned. ZAP and Azure are faked at the
module's seams (`subprocess.Popen`, `ResourceGraphClient`, the container
client), and process-group handling runs against real processes.
"""

import json
import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from sectest import scan


@pytest.fixture
def target():
    targets, _ = scan.select_targets(
        [
            {
                "id": "/subscriptions/sub/resourceGroups/rg-app/providers/Microsoft.App/containerApps/app",
                "name": "app",
                "resourceGroup": "rg-app",
                "subscriptionId": "sub",
                "fqdn": "app.example.azurecontainerapps.io",
                "runningStatus": "Running",
                "tags": None,
            }
        ]
    )
    return targets[0]


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "ZAP_WORK_DIR", tmp_path)
    return tmp_path


# --- run_scan ------------------------------------------------------------------


@pytest.fixture
def zap(monkeypatch, workdir):
    """A fake ZAP wrapper. Set `exit_code`, `report` (written on start) or `hangs`."""
    fake = SimpleNamespace(exit_code=0, report=None, hangs=False, cmd=None, cwd=None)
    stopped = []

    class _Popen:
        pid = 4242

        def __init__(self, cmd, cwd, start_new_session):
            assert start_new_session, "a timeout must be able to kill the whole process group"
            fake.cmd, fake.cwd = cmd, cwd
            if fake.report is not None:
                (workdir / f"{_target_slug(cmd)}.json").write_text(json.dumps(fake.report))

        def wait(self, timeout=None):
            if fake.hangs and timeout is not None:
                raise subprocess.TimeoutExpired("zap", timeout)
            return fake.exit_code

    monkeypatch.setattr(scan.subprocess, "Popen", _Popen)
    monkeypatch.setattr(scan, "stop_process_group", lambda pgid, **kw: stopped.append((pgid, kw)) or False)
    fake.stopped = stopped
    return fake


def _target_slug(cmd):
    """The report name ZAP is told to write, from the command run_scan built."""
    name = cmd[cmd.index("-J") + 1]
    return name.removesuffix(".json")


def test_a_scan_with_a_report_is_completed_with_its_counts(target, zap, workdir):
    zap.exit_code = 2
    zap.report = {"site": [{"alerts": [{"riskcode": "2"}, {"riskcode": "1"}]}]}

    result = scan.run_scan(target, spider_minutes=1, timeout=60, warmed=(True, "200"))

    assert result.status == "completed"
    assert result.exit_code == 2
    assert result.risk_counts == {"Informational": 0, "Low": 1, "Medium": 1, "High": 0}
    assert zap.cwd == workdir
    assert [pgid for pgid, _ in zap.stopped] == [4242], "ZAP's JVM is reaped after every scan"


def test_exit_code_3_is_an_error_even_with_a_report(target, zap):
    """3 is ZAP's "other failure": a partial report from it is not a clean scan."""
    zap.exit_code = 3
    zap.report = {"site": []}

    result = scan.run_scan(target, spider_minutes=1, timeout=60, warmed=(True, "200"))

    assert result.status == "error"
    assert result.risk_counts == {}


def test_no_report_is_an_error_not_a_pass(target, zap):
    """The failure that would read as a clean bill of health if counted as zero alerts."""
    zap.exit_code = 0

    result = scan.run_scan(target, spider_minutes=1, timeout=60, warmed=(True, "200"))

    assert result.status == "error"
    assert result.error == "ZAP did not produce a report"


def test_a_hung_scan_times_out_and_kills_the_group_at_once(target, zap):
    zap.hangs = True

    result = scan.run_scan(target, spider_minutes=1, timeout=5, warmed=(True, "200"))

    assert result.status == "timeout"
    assert result.error == "exceeded 5s"
    assert zap.stopped == [(4242, {"grace": 0})]


def test_a_cold_app_is_still_scanned(target, zap):
    """warm_up failing is logged, not a skip: ZAP's longer timeout may still get through."""
    zap.report = {"site": []}

    result = scan.run_scan(target, spider_minutes=1, timeout=60, warmed=(False, "timed out"))

    assert result.status == "completed"


# --- stop_process_group, against real processes -------------------------------


def _spawn(seconds: float) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", f"import time; time.sleep({seconds})"], start_new_session=True
    )


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="process groups are POSIX")
def test_a_group_that_exits_within_grace_is_not_killed():
    proc = _spawn(0.2)
    started = time.monotonic()
    assert scan.stop_process_group(proc.pid, grace=5, poll=0.05) is False
    assert time.monotonic() - started < 5, "returned once the group exited, not at the deadline"
    proc.wait(timeout=5)  # settles Popen's bookkeeping (ECHILD reads as 0)


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="process groups are POSIX")
def test_a_group_that_outlives_grace_is_killed():
    """The JVM the ZAP wrapper leaves behind, which would otherwise outlive the job."""
    proc = _spawn(60)
    started = time.monotonic()

    assert scan.stop_process_group(proc.pid, grace=0.2, poll=0.05) is True
    assert time.monotonic() - started < 10
    # stop_process_group reaps the group itself, so Popen cannot report the
    # signal; the group being gone is the observable result.
    with pytest.raises(ProcessLookupError):
        os.killpg(proc.pid, 0)
    proc.wait(timeout=5)  # settles Popen's bookkeeping (ECHILD reads as 0)


# --- discover_targets -----------------------------------------------------------


def test_discovery_follows_every_page(monkeypatch):
    """An app on page two that went unread would simply never be scanned."""
    import azure.mgmt.resourcegraph

    pages = {
        None: SimpleNamespace(data=[{"name": "a"}], skip_token="page-2"),
        "page-2": SimpleNamespace(data=[{"name": "b"}], skip_token="page-3"),
        "page-3": SimpleNamespace(data=[{"name": "c"}], skip_token=None),
    }
    requests = []

    class _Client:
        def __init__(self, credential):
            assert credential == "the-credential"

        def resources(self, request):
            requests.append(request)
            return pages[request.options.skip_token]

    monkeypatch.setattr(azure.mgmt.resourcegraph, "ResourceGraphClient", _Client)

    rows = scan.discover_targets("the-credential", ["sub-1", "sub-2"])

    assert [r["name"] for r in rows] == ["a", "b", "c"]
    assert all(r.subscriptions == ["sub-1", "sub-2"] for r in requests)
    assert requests[0].query == scan.RESOURCE_GRAPH_QUERY


# --- upload_reports ---------------------------------------------------------------


class _Container:
    def __init__(self):
        self.blobs = {}

    def upload_blob(self, name, data, overwrite, content_settings):
        assert overwrite is True
        self.blobs[name] = (data.read(), content_settings.content_type)


def test_reports_land_under_run_subscription_group_and_app(target, workdir):
    (workdir / f"{target.slug}.json").write_text("{}")
    (workdir / f"{target.slug}.html").write_text("<html/>")
    result = scan.ScanResult(target, "completed")
    container = _Container()

    scan.upload_reports(container, "2026-11-05/060000Z-passive", result)

    prefix = "2026-11-05/060000Z-passive/sub/rg-app/app"
    assert container.blobs == {
        f"{prefix}/report.json": (b"{}", "application/json"),
        f"{prefix}/report.html": (b"<html/>", "text/html"),
    }
    assert result.report_prefix == prefix


def test_no_reports_leaves_no_prefix_to_point_at(target, workdir):
    """A failed scan's summary must not link to an empty path."""
    result = scan.ScanResult(target, "error")
    container = _Container()

    scan.upload_reports(container, "2026-11-05/060000Z-passive", result)

    assert container.blobs == {}
    assert result.report_prefix is None
