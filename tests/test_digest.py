"""Unit tests for the digest and the mailer — no Azure, no Resend."""

import json

import pytest
from azure.core.exceptions import ResourceNotFoundError

from sectest import digest, mailer


def alert(ref, name, riskcode):
    return {"alertRef": ref, "pluginid": ref.split("-")[0], "name": name, "riskcode": str(riskcode)}


def report(*alerts):
    return {"site": [{"alerts": list(alerts)}]}


CSP = alert("10038", "Content Security Policy (CSP) Header Not Set", 2)
CLICKJACK = alert("10020-1", "Missing Anti-clickjacking Header", 2)
HSTS = alert("10035-1", "Strict-Transport-Security Header Not Set", 1)
INFO = alert("10049-1", "Storable and Cacheable Content", 0)


def summary(*results, started="2026-10-19T06:00:00+00:00", skipped=()):
    return {"started": started, "results": list(results), "skipped": list(skipped)}


def result(name, status="completed", error=None):
    return {
        "target": {"id": f"/sub/rg/{name}", "name": name},
        "status": status,
        "report_prefix": f"run/{name}" if status == "completed" else None,
        "error": error,
    }


def run(prefix, reports, statuses=None, **kwargs):
    statuses = statuses or {}
    results = [
        result(n, statuses.get(n, "completed"), error="boom" if n in statuses else None) for n in reports
    ]
    parsed = {f"/sub/rg/{n}": r for n, r in reports.items() if statuses.get(n, "completed") == "completed"}
    return digest.build_run(prefix, summary(*results, **kwargs), parsed)


def test_informational_alerts_are_not_findings():
    found = digest.findings_from_report("/sub/rg/a", "a", report(CSP, HSTS, INFO))
    assert sorted(f.risk for f in found) == ["Low", "Medium"]


def test_a_rule_is_one_finding_however_many_instances():
    assert len(digest.findings_from_report("a", "a", report(CSP, CSP, CSP))) == 1


def test_previous_prefix_is_the_latest_earlier_passive_run():
    names = [
        "2026-10-12/060101Z-passive/summary.json",
        "2026-10-14/120000Z-active/summary.json",
        "2026-10-15/093000Z-passive/summary.json",
        "2026-10-15/093000Z-passive/sub/rg/app/report.json",
        "2026-10-19/060101Z-passive/summary.json",
    ]
    assert digest.previous_prefix(names, "2026-10-19/060101Z-passive") == "2026-10-15/093000Z-passive"
    assert digest.previous_prefix(names, "2026-10-12/060101Z-passive") is None


def test_new_and_resolved_are_per_app_and_rule():
    before = run("old", {"career": report(CSP, CLICKJACK, HSTS)})
    now = run("new", {"career": report(HSTS, alert("10063-1", "Permissions Policy Header Not Set", 1))})

    d = digest.compare(now, [before])

    assert [f.name for f in d.new] == ["Permissions Policy Header Not Set"]
    assert [f.name for f in d.resolved] == [
        "Content Security Policy (CSP) Header Not Set",
        "Missing Anti-clickjacking Header",
    ]


def test_a_failed_scan_resolves_nothing():
    """An app that errored has not been fixed; its findings must not read as resolved."""
    before = run("old", {"career": report(CSP)})
    now = run("new", {"career": report()}, statuses={"career": "error"})

    d = digest.compare(now, [before])

    assert d.resolved == []
    assert d.current.errored == [("career", "boom")]
    assert "(1 failed)" in digest.subject(d)


def test_an_app_new_to_the_scan_is_a_first_scan_not_new_findings():
    before = run("old", {"career": report(CSP)})
    now = run("new", {"career": report(CSP), "gymlog": report(CSP, HSTS)})

    d = digest.compare(now, [before])

    assert d.new == []
    assert d.first_scans == ["gymlog"]


def test_a_risk_change_reads_as_resolved_and_new():
    before = run("old", {"career": report(CSP)})
    now = run("new", {"career": report({**CSP, "riskcode": "3"})})

    d = digest.compare(now, [before])

    assert [(f.risk) for f in d.new] == ["High"]
    assert [(f.risk) for f in d.resolved] == ["Medium"]


def test_first_digest_has_nothing_to_compare_with():
    d = digest.compare(run("new", {"career": report(CSP, HSTS)}), [])

    assert digest.subject(d) == "Security scan: first digest, 1 Medium, 1 Low open"
    assert d.first_scans == ["career"]


def test_subject_counts_open_findings_across_apps():
    before = run("old", {"a": report(CSP), "b": report(CSP)})
    now = run("new", {"a": report(CSP, HSTS), "b": report()})

    assert (
        digest.subject(digest.compare(now, [before]))
        == "Security scan: 1 new, 1 resolved, 1 Medium, 1 Low open"
    )


def test_text_shows_deltas_against_the_previous_run():
    before = run("old", {"career": report(CSP, CLICKJACK)})
    now = run("new", {"career": report(CSP, HSTS)})

    text = digest.render_text(digest.compare(now, [before]))

    assert "career: 0 / 1 (-1) / 1 (+1)" in text


def test_html_escapes_everything_from_a_report():
    """Alert names come from ZAP, and app names from tags anyone can set."""
    evil = alert("99999", "<script>alert(1)</script>", 2)
    d = digest.compare(run("new", {"<b>app</b>": report(evil)}), [run("old", {"<b>app</b>": report()})])

    rendered = digest.render_html(d)

    assert "<script>" not in rendered
    assert "<b>app</b>" not in rendered
    assert "&lt;script&gt;" in rendered


class FakeBlob:
    def __init__(self, data):
        self.data = data

    def readall(self):
        return self.data


class FakeContainer:
    def __init__(self, blobs):
        self.blobs = {k: json.dumps(v).encode() for k, v in blobs.items()}

    def download_blob(self, name):
        if name not in self.blobs:
            raise ResourceNotFoundError(name)
        return FakeBlob(self.blobs[name])

    def list_blob_names(self):
        return iter(self.blobs)


def test_send_digest_compares_with_the_previous_run_and_logs(monkeypatch, capsys):
    blobs = {
        "2026-10-12/060000Z-passive/summary.json": summary(result("career"), started="2026-10-12T06:00:00"),
        "run/career/report.json": report(CSP),
        "2026-10-19/060000Z-passive/summary.json": summary(result("career")),
    }
    sent = {}

    def fake_send(subject, html, text, sender, credential):
        sent.update(subject=subject, sender=sender)
        return mailer.MailResult(status="sent")

    monkeypatch.setattr(mailer, "send", fake_send)

    digest.send_digest(FakeContainer(blobs), None, "2026-10-19/060000Z-passive", "Scans <s@example.com>")

    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["event"] == "digest"
    assert line["status"] == "sent"
    assert line["previous"] == "2026-10-12/060000Z-passive"
    assert sent["sender"] == "Scans <s@example.com>"


def test_send_digest_never_raises(capsys):
    digest.send_digest(FakeContainer({}), None, "2026-10-19/060000Z-passive", "x")

    line = json.loads(capsys.readouterr().out.strip())
    assert line["status"] == "failed"
    assert "ResourceNotFoundError" in line["error"]


def secrets(**values):
    return lambda name, _credential: values.get(name)


def test_no_recipient_skips_without_posting():
    def post(*_):
        raise AssertionError("posted")

    assert mailer.send("s", "h", "t", "from", None, secret=secrets(), post=post).status == "skipped"


def test_sends_to_every_recipient_with_a_user_agent():
    calls = []

    def post(url, body, headers):
        calls.append((url, body, headers))
        return {"id": "abc"}

    result = mailer.send(
        "s",
        "h",
        "t",
        "Scans <s@example.com>",
        None,
        secret=secrets(**{"DIGEST-EMAIL-TO": "a@example.com, b@example.com", "RESEND-API-KEY": "re_x"}),
        post=post,
    )

    assert result == mailer.MailResult(status="sent", provider_id="abc")
    url, body, headers = calls[0]
    assert url == mailer.RESEND_ENDPOINT
    assert body["to"] == ["a@example.com", "b@example.com"]
    assert headers["Authorization"] == "Bearer re_x"
    assert headers["User-Agent"] == mailer.USER_AGENT


@pytest.mark.parametrize(
    "values",
    [{"DIGEST-EMAIL-TO": "a@example.com"}, {"DIGEST-EMAIL-TO": "a@example.com", "RESEND-API-KEY": "re_x"}],
)
def test_a_failed_send_is_returned_not_raised(values):
    def post(*_):
        raise OSError("network down")

    result = mailer.send("s", "h", "t", "from", None, secret=secrets(**values), post=post)

    assert result.status == "failed"


def test_environment_wins_over_the_vault(monkeypatch):
    monkeypatch.setenv("DIGEST_EMAIL_TO", "me@example.com")
    monkeypatch.delenv("KEY_VAULT_URI", raising=False)

    assert mailer.get_secret("DIGEST-EMAIL-TO", None) == "me@example.com"
    assert mailer.get_secret("RESEND-API-KEY", None) is None


def test_a_failed_scan_carries_its_last_findings_into_the_open_counts():
    before = run("old", {"career": report(CSP, HSTS)})
    now = run("new", {"career": report()}, statuses={"career": "error"})

    d = digest.compare(now, [before])

    assert d.total_open() == {"High": 0, "Medium": 1, "Low": 1}
    assert "career: 0 / 1 / 1  [scan failed; last result" in digest.render_text(d)
    assert "boom (last result carried over)" in digest.render_text(d)


def test_every_app_failing_still_renders():
    d = digest.compare(run("new", {"career": report()}, statuses={"career": "error"}), [])

    assert d.total_open() == {"High": 0, "Medium": 0, "Low": 0}
    assert "boom (no earlier result)" in digest.render_text(d)


def test_an_app_that_failed_last_time_compares_with_its_last_completed_scan():
    """Not a first scan: two runs back it completed, and that is the baseline."""
    r0 = run("r0", {"career": report()}, started="2026-10-05T06:00:00")
    r1 = run("r1", {"career": report()}, statuses={"career": "timeout"})
    r2 = run("r2", {"career": report({**CSP, "riskcode": "3"})})

    d = digest.compare(r2, [r1, r0])

    assert [f.risk for f in d.new] == ["High"]
    assert d.first_scans == []
    assert "[compared with 2026-10-05]" in digest.render_text(d)


def test_an_app_gone_from_the_scan_is_named_not_resolved():
    before = run("old", {"a": report(CSP), "b": report(CSP)})
    now = run("new", {"a": report(CSP)})

    d = digest.compare(now, [before])

    assert d.no_longer_scanned == ["b"]
    assert d.resolved == []
    assert "No longer scanned (findings dropped, not resolved): b" in digest.render_text(d)


def test_an_app_skipped_by_tag_is_not_also_no_longer_scanned():
    before = run("old", {"a": report(CSP), "b": report(CSP)})
    now = run("new", {"a": report(CSP)}, skipped=[{"name": "b", "reason": "opted out via tag"}])

    assert digest.compare(now, [before]).no_longer_scanned == []


def test_a_missing_report_in_an_earlier_run_does_not_stop_the_digest(monkeypatch, capsys):
    blobs = {
        "2026-10-12/060000Z-passive/summary.json": summary(result("career"), started="2026-10-12T06:00:00"),
        # run/career/report.json is missing: lifecycle-expired, or never uploaded.
        "2026-10-19/060000Z-passive/summary.json": summary(result("career")),
    }
    blobs_current = {**blobs, "now/career/report.json": report(CSP)}
    blobs_current["2026-10-19/060000Z-passive/summary.json"] = summary(
        {**result("career"), "report_prefix": "now/career"}
    )
    monkeypatch.setattr(mailer, "send", lambda *a: mailer.MailResult(status="sent"))

    digest.send_digest(FakeContainer(blobs_current), None, "2026-10-19/060000Z-passive", "x")

    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["status"] == "sent"
    assert line["resolved"] == 0


def test_a_completed_target_without_a_report_says_so():
    r = digest.build_run("p", summary(result("career")), reports={})

    assert r.errored == [("career", "report missing")]


def test_resend_rejection_body_is_kept(monkeypatch):
    import io
    import urllib.error

    def reject(*_a, **_k):
        raise urllib.error.HTTPError(
            mailer.RESEND_ENDPOINT, 403, "Forbidden", {}, io.BytesIO(b'{"message":"domain not verified"}')
        )

    monkeypatch.setattr(mailer.urllib.request, "urlopen", reject)
    result = mailer.send(
        "s",
        "h",
        "t",
        "from",
        None,
        secret=secrets(**{"DIGEST-EMAIL-TO": "a@example.com", "RESEND-API-KEY": "re_x"}),
    )

    assert result.status == "failed"
    assert "HTTP 403" in result.error
    assert "domain not verified" in result.error


def test_an_active_run_compares_only_with_earlier_active_runs():
    names = [
        "2026-10-12/060101Z-active/summary.json",
        "2026-10-14/120000Z-passive/summary.json",
    ]

    assert digest.previous_prefix(names, "2026-10-19/060101Z-active") == "2026-10-12/060101Z-active"
    assert digest.previous_prefix(names, "2026-10-19/060101Z-passive") == "2026-10-14/120000Z-passive"


def test_an_active_digest_lists_every_open_finding():
    d = digest.compare(
        run("2026-10-15/202812Z-active", {"career": report(CSP, HSTS), "gymlog": report(CLICKJACK)}), []
    )

    assert digest.subject(d) == "Active security scan: first digest, 2 Medium, 1 Low open"
    text = digest.render_text(d)
    assert "Open findings (3):" in text
    assert "[Medium] career: Content Security Policy (CSP) Header Not Set" in text
    assert "[Low] career: Strict-Transport-Security Header Not Set" in text
    assert "<h3>Open findings (3)</h3>" in digest.render_html(d)


def test_a_passive_digest_does_not_list_every_open_finding():
    d = digest.compare(run("2026-10-19/060000Z-passive", {"career": report(CSP)}), [])

    assert "Open findings" not in digest.render_text(d)
    assert "Open findings" not in digest.render_html(d)


def test_send_digest_for_an_active_run_ignores_passive_runs(monkeypatch, capsys):
    blobs = {
        "2026-10-12/060000Z-passive/summary.json": summary(result("career"), started="2026-10-12T06:00:00"),
        "run/career/report.json": report(CSP),
        "2026-10-15/202812Z-active/summary.json": summary(result("career")),
    }
    sent = {}

    def fake_send(subject, html, text, sender, credential):
        sent.update(subject=subject, text=text)
        return mailer.MailResult(status="sent")

    monkeypatch.setattr(mailer, "send", fake_send)

    digest.send_digest(FakeContainer(blobs), None, "2026-10-15/202812Z-active", "x")

    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["profile"] == "active"
    assert line["previous"] is None
    assert sent["subject"].startswith("Active security scan: first digest")
    assert "[Medium] career: Content Security Policy (CSP) Header Not Set" in sent["text"]
