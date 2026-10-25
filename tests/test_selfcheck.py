"""`sectest selfcheck`, which `make smoke` runs in each scanner job after a deploy.

It has to fail on exactly what would break a scan, and touch nothing: a false
failure rolls back a good release, and a scan would fire on every deploy.
"""

import sys

import pytest

from sectest import scan, selfcheck


@pytest.fixture
def healthy(monkeypatch):
    monkeypatch.setenv("TARGET_SUBSCRIPTION_IDS", "sub-1")
    monkeypatch.setenv("REPORT_CONTAINER_URL", "https://acct.blob.core.windows.net/reports")
    monkeypatch.delenv("DIGEST_EMAIL_TO", raising=False)
    monkeypatch.delenv("KEY_VAULT_URI", raising=False)
    monkeypatch.setattr(selfcheck.shutil, "which", lambda name: f"/zap/{name}")
    monkeypatch.setattr(scan, "discover_targets", lambda credential, subs: [])

    class Container:
        def get_container_properties(self):
            return {}

    from azure.storage.blob import ContainerClient

    monkeypatch.setattr(ContainerClient, "from_container_url", lambda url, credential: Container())


def test_passes_when_everything_a_scan_needs_is_there(healthy):
    assert selfcheck.run() == 0


def test_fails_without_a_report_container(healthy, monkeypatch, caplog):
    monkeypatch.delenv("REPORT_CONTAINER_URL")
    assert selfcheck.run() == 1
    assert "FAIL config" in caplog.text


def test_fails_when_a_zap_script_is_missing(healthy, monkeypatch, caplog):
    monkeypatch.setattr(selfcheck.shutil, "which", lambda name: None if name == "zap-full-scan.py" else name)
    assert selfcheck.run() == 1
    assert "zap-full-scan.py" in caplog.text


def test_fails_when_a_recipient_has_no_api_key(healthy, monkeypatch, caplog):
    monkeypatch.setenv("DIGEST_EMAIL_TO", "someone@example.com")
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    assert selfcheck.run() == 1
    assert "FAIL digest secrets" in caplog.text
    assert "someone@example.com" not in caplog.text


def test_cli_runs_it_and_refuses_other_arguments(monkeypatch):
    monkeypatch.setattr(selfcheck, "run", lambda: 0)
    monkeypatch.setattr(sys, "argv", ["sectest", "selfcheck"])
    with pytest.raises(SystemExit) as ran:
        scan.cli()
    assert ran.value.code == 0

    monkeypatch.setattr(sys, "argv", ["sectest", "bogus"])
    with pytest.raises(SystemExit) as refused:
        scan.cli()
    assert refused.value.code == 2
