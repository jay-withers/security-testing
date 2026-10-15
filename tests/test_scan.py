"""Unit tests for the pure parts of scan.py — no Azure and no ZAP needed."""

import shlex

import pytest

from sectest import scan


def row(name="app", fqdn="app.example.azurecontainerapps.io", tags=None, **extra):
    return {
        "id": f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/containerApps/{name}",
        "name": name,
        "resourceGroup": "rg",
        "subscriptionId": "sub",
        "fqdn": fqdn,
        "runningStatus": "Running",
        "tags": tags,
        **extra,
    }


def test_default_is_baseline():
    targets, skipped = scan.select_targets([row()])
    assert skipped == []
    assert [t.mode for t in targets] == ["baseline"]
    assert targets[0].url == "https://app.example.azurecontainerapps.io"


def test_opt_out_tag_is_case_insensitive():
    targets, skipped = scan.select_targets([row(tags={"Security-Scan": "FALSE"})])
    assert targets == []
    assert skipped[0]["reason"] == "opted out via tag"


def test_skips_apps_without_fqdn_or_stopped():
    targets, skipped = scan.select_targets([row(name="a", fqdn=""), row(name="b", runningStatus="Stopped")])
    assert targets == []
    assert {s["name"]: s["reason"] for s in skipped} == {"a": "no ingress FQDN", "b": "app is stopped"}


def test_passive_profile_never_attacks():
    rows = [
        row(name="plain"),
        row(name="api", tags={"security-scan-openapi": "/openapi.json"}),
        # A leftover opt-in tag from the old model must not make the passive run active.
        row(name="legacy", tags={"security-scan-mode": "full"}),
    ]
    targets, skipped = scan.select_targets(rows, "passive")
    assert skipped == []
    assert {t.name: t.mode for t in targets} == {"plain": "baseline", "api": "api", "legacy": "baseline"}
    for t in targets:
        cmd = scan.build_command(t, spider_minutes=5)
        assert cmd[0] != "zap-full-scan.py"
        # zap-api-scan.py attacks by default; -S is what keeps it passive.
        assert cmd[0] != "zap-api-scan.py" or "-S" in cmd


def test_active_profile_is_the_default_for_every_app():
    targets, _ = scan.select_targets(
        [row(), row(name="api", tags={"security-scan-openapi": "/o.json"})], "active"
    )
    assert [t.mode for t in targets] == ["full", "api-full"]
    full, api = (scan.build_command(t, spider_minutes=3) for t in targets)
    assert full[:5] == ["zap-full-scan.py", "-t", "https://app.example.azurecontainerapps.io", "-m", "3"]
    assert api[0] == "zap-api-scan.py"
    assert "https://app.example.azurecontainerapps.io/o.json" in api
    assert "-S" not in api


def test_passive_tag_opts_out_of_active_only():
    tagged = row(tags={"Security-Scan-Mode": "Passive"})
    active, skipped = scan.select_targets([tagged], "active")
    assert active == []
    assert skipped[0]["reason"] == "opted out of active scans via tag"
    passive, _ = scan.select_targets([tagged], "passive")
    assert [t.mode for t in passive] == ["baseline"]


def test_opt_out_of_everything_applies_to_both_profiles():
    for profile in scan.PROFILES:
        targets, _ = scan.select_targets([row(tags={"security-scan": "false"})], profile)
        assert targets == []


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        scan.select_targets([row()], "aggressive")


def test_openapi_tag_must_be_a_path():
    targets, skipped = scan.select_targets([row(tags={"security-scan-openapi": "https://evil.example/spec"})])
    assert targets == []
    assert "must be a path" in skipped[0]["reason"]


def test_baseline_command_writes_all_reports():
    target = scan.select_targets([row(name="My_App")])[0][0]
    cmd = scan.build_command(target, spider_minutes=5)
    assert cmd[0] == "zap-baseline.py"
    assert "-I" in cmd
    for flag, ext in (("-J", "json"), ("-r", "html"), ("-w", "md")):
        assert cmd[cmd.index(flag) + 1] == f"rg-my-app.{ext}"


def test_count_risks():
    report = {
        "site": [
            {"alerts": [{"riskcode": "3"}, {"riskcode": "1"}, {"riskcode": "1"}]},
            {"alerts": [{"riskcode": "0"}, {"riskcode": "bogus"}]},
        ]
    }
    assert scan.count_risks(report) == {"Informational": 1, "Low": 2, "Medium": 0, "High": 1}


def test_exceeds_threshold():
    counts = {"Informational": 4, "Low": 1, "Medium": 0, "High": 0}
    assert not scan.exceeds_threshold(counts, "High")
    assert not scan.exceeds_threshold(counts, "Medium")
    assert scan.exceeds_threshold(counts, "Low")


def test_every_scan_sends_the_identifying_user_agent():
    for profile, tags in (
        ("passive", {}),
        ("passive", {"security-scan-openapi": "/openapi.json"}),
        ("active", {}),
        ("active", {"security-scan-openapi": "/openapi.json"}),
    ):
        target = scan.select_targets([row(tags=tags)], profile)[0][0]
        cmd = scan.build_command(target, spider_minutes=5)
        # ZAP shlex-splits -z itself, so the quoted UA must survive as one value.
        options = shlex.split(cmd[cmd.index("-z") + 1])
        assert f"connection.defaultUserAgent={scan.USER_AGENT}" in options
        assert f"connection.timeoutInSecs={scan.ZAP_READ_TIMEOUT_SECONDS}" in options


def test_log_lines_carry_the_source(capsys):
    scan.log("scan_finished", target="app", over_threshold=True)
    line = capsys.readouterr().out.strip()
    assert '"source": "sectest"' in line
    assert '"over_threshold": true' in line


class FakeClock:
    """Deterministic time for warm_up: sleep() advances now()."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def test_warm_up_returns_as_soon_as_the_app_answers():
    clock = FakeClock()
    assert scan.warm_up("https://a", fetch=lambda u, t: 200, sleep=clock.sleep, clock=clock) == (
        True,
        "HTTP 200",
    )
    assert clock.now == 0


def test_warm_up_treats_any_app_status_as_awake():
    # A 401 is the app answering — it is awake, just protected.
    clock = FakeClock()
    awake, _ = scan.warm_up("https://a", fetch=lambda u, t: 401, sleep=clock.sleep, clock=clock)
    assert awake


def test_warm_up_retries_through_cold_start():
    clock = FakeClock()
    responses = iter([503, 503, 200])
    awake, detail = scan.warm_up(
        "https://a", fetch=lambda u, t: next(responses), sleep=clock.sleep, clock=clock
    )
    assert (awake, detail) == (True, "HTTP 200")
    assert clock.now == 2 * scan.WARM_UP_RETRY_SECONDS


def test_warm_up_gives_up_at_the_deadline():
    clock = FakeClock()

    def timing_out(url, timeout):
        raise TimeoutError("read timed out")

    awake, detail = scan.warm_up("https://a", fetch=timing_out, sleep=clock.sleep, clock=clock, deadline=60)
    assert not awake
    assert "TimeoutError" in detail
    assert clock.now < 60


def test_warm_ahead_wakes_the_next_app_while_the_current_one_scans():
    import threading

    targets, _ = scan.select_targets([row(name=n, fqdn=f"{n}.example") for n in ("a", "b", "c")])
    started = {n: threading.Event() for n in ("a", "b", "c")}
    order = []

    def warm(target):
        order.append(f"warm {target.name}")
        started[target.name].set()
        return True, "HTTP 200"

    for target, warming in scan.warm_ahead(targets, warm):
        assert warming.result() == (True, "HTTP 200")
        nxt = {"a": "b", "b": "c"}.get(target.name)
        # The "scan" of this target only finishes once the next app's warm-up
        # has begun, which it can only do if it was started concurrently.
        if nxt:
            assert started[nxt].wait(timeout=5), f"{nxt} was not warmed during {target.name}'s scan"
        order.append(f"scan {target.name}")

    assert order.index("warm b") < order.index("scan a")
    assert order.index("warm c") < order.index("scan b")
    assert order.count("warm a") == 1


def test_warm_ahead_with_no_targets_yields_nothing():
    assert list(scan.warm_ahead([], lambda t: (True, ""))) == []


def test_a_warm_up_error_surfaces_on_that_target_only():
    targets, _ = scan.select_targets([row(name=n, fqdn=f"{n}.example") for n in ("a", "b")])

    def warm(target):
        if target.name == "a":
            raise RuntimeError("dns")
        return True, "HTTP 200"

    outcomes = []
    for target, warming in scan.warm_ahead(targets, warm):
        try:
            outcomes.append((target.name, warming.result()))
        except RuntimeError as exc:
            outcomes.append((target.name, str(exc)))

    assert outcomes == [("a", "dns"), ("b", (True, "HTTP 200"))]


def test_a_fresh_early_warm_up_is_used_as_is():
    target = scan.select_targets([row()])[0][0]

    def rewarm(url):
        raise AssertionError("rewarmed")

    assert scan.fresh_warm_up(target, (True, "HTTP 200", 100.0), clock=lambda: 160.0, rewarm=rewarm) == (
        True,
        "HTTP 200",
    )


def test_a_stale_warm_up_wakes_the_app_again():
    """After a long scan before it, the app may have scaled back to zero."""
    target = scan.select_targets([row()])[0][0]
    calls = []

    def rewarm(url):
        calls.append(url)
        return True, "HTTP 401"

    result = scan.fresh_warm_up(
        target, (True, "HTTP 200", 100.0), clock=lambda: 100.0 + scan.WARM_UP_STALE_SECONDS + 1, rewarm=rewarm
    )

    assert result == (True, "HTTP 401")
    assert calls == [target.url]


def test_warm_ahead_stays_only_one_app_ahead():
    """Waking every app at the start would let later ones scale back to zero."""
    import threading

    targets, _ = scan.select_targets([row(name=n, fqdn=f"{n}.example") for n in ("a", "b", "c")])
    started = {n: threading.Event() for n in ("a", "b", "c")}
    release = {n: threading.Event() for n in ("a", "b", "c")}

    def warm(target):
        started[target.name].set()
        release[target.name].wait(timeout=5)
        return True, "HTTP 200"

    release["a"].set()
    release["b"].set()
    walk = scan.warm_ahead(targets, warm)
    target, warming = next(walk)
    assert target.name == "a"
    warming.result()
    # b's warm-up runs and finishes during a's turn; c's must not follow it
    # until b is current. Anything queued early would start here.
    assert started["b"].wait(timeout=5)
    assert not started["c"].wait(timeout=0.5), "c was woken while a was still current"

    target, _ = next(walk)
    assert target.name == "b"
    assert started["c"].wait(timeout=5)
    release["c"].set()
    walk.close()


def test_scan_target_passes_the_fresh_warm_up_to_the_scan():
    from concurrent.futures import Future

    target = scan.select_targets([row()])[0][0]
    early = Future()
    early.set_result((True, "HTTP 200", 1.0))
    seen = {}

    def fresh(t, warmed):
        seen["fresh"] = warmed
        return False, "rewoken"

    def fake_scan(t, spider_minutes, timeout, warmed):
        seen["scan"] = warmed
        return scan.ScanResult(t, "completed")

    scan.scan_target(target, early, 5, 60, scan=fake_scan, fresh=fresh)

    assert seen == {"fresh": (True, "HTTP 200", 1.0), "scan": (False, "rewoken")}


def test_run_scan_does_not_repeat_an_early_warm_up(monkeypatch, tmp_path):
    def no_warm_up(url):
        raise AssertionError("warmed again")

    class Proc:
        pid = 1

        def wait(self, timeout=None):
            return 3  # ZAP "other failure": run_scan returns before reading a report

    monkeypatch.setattr(scan, "warm_up", no_warm_up)
    monkeypatch.setattr(scan, "ZAP_WORK_DIR", tmp_path)
    monkeypatch.setattr(scan.subprocess, "Popen", lambda *a, **k: Proc())
    target = scan.select_targets([row()])[0][0]

    result = scan.run_scan(target, 5, 60, warmed=(True, "HTTP 200"))

    assert result.status == "error"


def test_timed_warm_up_stamps_when_the_warm_up_finished(monkeypatch):
    now = {"t": 10.0}

    def slow_warm_up(url):
        now["t"] = 40.0
        return True, "HTTP 200"

    monkeypatch.setattr(scan, "warm_up", slow_warm_up)
    monkeypatch.setattr(scan.time, "monotonic", lambda: now["t"])

    assert scan._timed_warm_up(scan.select_targets([row()])[0][0]) == (True, "HTTP 200", 40.0)
