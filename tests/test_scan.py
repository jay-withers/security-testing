"""Unit tests for the pure parts of scan.py — no Azure and no ZAP needed."""

import shlex

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


def test_openapi_tag_alone_is_a_passive_api_scan():
    targets, _ = scan.select_targets([row(tags={"security-scan-openapi": "/openapi.json"})])
    assert targets[0].mode == "api"
    cmd = scan.build_command(targets[0], spider_minutes=5)
    assert cmd[0] == "zap-api-scan.py"
    assert "https://app.example.azurecontainerapps.io/openapi.json" in cmd
    assert cmd[cmd.index("-f") + 1] == "openapi"
    # zap-api-scan.py is active by default; -S is what keeps this passive.
    assert "-S" in cmd


def test_openapi_tag_must_be_a_path():
    targets, skipped = scan.select_targets([row(tags={"security-scan-openapi": "https://evil.example/spec"})])
    assert targets == []
    assert "must be a path" in skipped[0]["reason"]


def test_openapi_plus_full_is_an_active_api_scan():
    targets, _ = scan.select_targets(
        [row(tags={"security-scan-mode": "full", "security-scan-openapi": "/openapi.json"})]
    )
    assert targets[0].mode == "api-full"
    cmd = scan.build_command(targets[0], spider_minutes=3)
    assert cmd[0] == "zap-api-scan.py"
    assert "-S" not in cmd


def test_only_full_mode_is_ever_active():
    for tags in ({}, {"security-scan-openapi": "/openapi.json"}, {"security-scan-mode": "FULLish"}):
        cmd = scan.build_command(scan.select_targets([row(tags=tags)])[0][0], spider_minutes=5)
        assert cmd[0] != "zap-full-scan.py"
        assert cmd[0] != "zap-api-scan.py" or "-S" in cmd


def test_full_tag_without_openapi_is_a_full_scan():
    targets, _ = scan.select_targets([row(tags={"security-scan-mode": "full"})])
    assert targets[0].mode == "full"
    assert scan.build_command(targets[0], spider_minutes=3)[:5] == [
        "zap-full-scan.py",
        "-t",
        "https://app.example.azurecontainerapps.io",
        "-m",
        "3",
    ]


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
    for tags in ({}, {"security-scan-openapi": "/openapi.json"}, {"security-scan-mode": "full"}):
        target = scan.select_targets([row(tags=tags)])[0][0]
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
