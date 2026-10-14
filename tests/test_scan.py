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
        # A leftover opt-in tag from the old model must not make the nightly run active.
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
        assert shlex.split(cmd[cmd.index("-z") + 1]) == [
            "-config",
            f"connection.defaultUserAgent={scan.USER_AGENT}",
        ]


def test_log_lines_carry_the_source(capsys):
    scan.log("scan_finished", target="app", over_threshold=True)
    line = capsys.readouterr().out.strip()
    assert '"source": "sectest"' in line
    assert '"over_threshold": true' in line
