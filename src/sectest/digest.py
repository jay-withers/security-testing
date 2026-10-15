"""The digest: what changed since the previous passive run, by email.

Sent at the end of every passive run, so the weekly schedule gives a weekly
digest and a `make scan` after a fix emails what that fix changed. Active runs
send nothing: they are started by hand, and their findings are attack results
that don't compare with a passive baseline.

**A finding is an app plus a ZAP rule plus a risk**, keyed on ZAP's `alertRef`
(falling back to `pluginid`), so one rule raising five instances is one
finding, and a rule whose risk changes reads as one resolved and one new.
Informational alerts are left out entirely; they are ZAP noting things, not
problems.

**Only apps scanned in both runs are compared.** An app that errored this run
has not been fixed, so none of its findings are "resolved"; an app with no
earlier completed scan is listed as a first scan rather than flooding "new".

**The digest never fails the run.** The scan's outcome is already decided and
logged by the time this runs. A broken digest logs `digest` with
`status: failed` and the job still exits on the scan's own result, so the
platform's workload-crashed alert keeps meaning "the scanner is broken".
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field

from .scan import RISK_NAMES, log

REPORTED_RISKS = ("High", "Medium", "Low")
SUMMARY_SUFFIX = "-passive/summary.json"


@dataclass(frozen=True, order=True)
class Finding:
    app_id: str
    rule: str
    risk: str
    # Display only: a rule renamed between ZAP releases is still the same finding.
    app: str = field(compare=False)
    name: str = field(compare=False)


@dataclass
class Run:
    prefix: str
    started: str
    # Apps whose scan completed, by resource id, with what it found.
    findings: dict[str, set[Finding]]
    names: dict[str, str]
    errored: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Digest:
    current: Run
    previous: Run | None
    new: list[Finding]
    resolved: list[Finding]
    first_scans: list[str]

    def open_counts(self, app_id: str) -> dict[str, int]:
        return _counts(self.current.findings.get(app_id, set()))

    def previous_counts(self, app_id: str) -> dict[str, int] | None:
        if self.previous is None or app_id not in self.previous.findings:
            return None
        return _counts(self.previous.findings[app_id])

    def total_open(self) -> dict[str, int]:
        return _counts(set().union(*self.current.findings.values()))


def _counts(findings: set[Finding]) -> dict[str, int]:
    counts = dict.fromkeys(REPORTED_RISKS, 0)
    for f in findings:
        counts[f.risk] += 1
    return counts


def findings_from_report(app_id: str, app: str, report: dict) -> set[Finding]:
    """The non-informational findings in a ZAP traditional-json report."""
    found = set()
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            try:
                risk = RISK_NAMES.get(int(alert.get("riskcode", 0)), "Informational")
            except (TypeError, ValueError):
                continue
            if risk not in REPORTED_RISKS:
                continue
            rule = str(alert.get("alertRef") or alert.get("pluginid") or alert.get("name"))
            name = alert.get("name") or alert.get("alert") or rule
            found.add(Finding(app_id, rule, risk, app=app, name=name))
    return found


def previous_prefix(blob_names: list[str], current: str) -> str | None:
    """The latest passive run before `current`, from the container's blob names.

    Run prefixes are `YYYY-MM-DD/HHMMSSZ-<profile>`, so they sort by time.
    """
    runs = sorted(n[: -len("/summary.json")] for n in blob_names if n.endswith(SUMMARY_SUFFIX))
    earlier = [r for r in runs if r < current]
    return earlier[-1] if earlier else None


def build_run(prefix: str, summary: dict, reports: dict[str, dict]) -> Run:
    """A Run from a summary.json and the report.json of each completed target.

    `reports` maps a target's resource id to its parsed report; a completed
    target with no report is treated as errored, since nothing can be said
    about it.
    """
    run = Run(prefix=prefix, started=summary.get("started", ""), findings={}, names={})
    for result in summary.get("results", []):
        target = result.get("target", {})
        app_id, name = target.get("id", ""), target.get("name", "")
        run.names[app_id] = name
        if result.get("status") == "completed" and app_id in reports:
            run.findings[app_id] = findings_from_report(app_id, name, reports[app_id])
        else:
            run.errored.append((name, result.get("error") or result.get("status") or "no report"))
    run.skipped = [(s.get("name", ""), s.get("reason", "")) for s in summary.get("skipped", [])]
    return run


def compare(current: Run, previous: Run | None) -> Digest:
    new: set[Finding] = set()
    resolved: set[Finding] = set()
    first_scans = []
    for app_id, found in current.findings.items():
        before = previous.findings.get(app_id) if previous else None
        if before is None:
            first_scans.append(current.names[app_id])
            continue
        new |= found - before
        resolved |= before - found
    return Digest(
        current, previous, sorted(new, key=_order), sorted(resolved, key=_order), sorted(first_scans)
    )


def _order(f: Finding) -> tuple:
    return (REPORTED_RISKS.index(f.risk), f.app, f.name)


def subject(d: Digest) -> str:
    totals = d.total_open()
    open_part = ", ".join(f"{n} {risk}" for risk, n in totals.items() if n) or "nothing"
    head = "Security scan" if not d.current.errored else f"Security scan ({len(d.current.errored)} failed)"
    if d.previous is None:
        return f"{head}: first digest, {open_part} open"
    return f"{head}: {len(d.new)} new, {len(d.resolved)} resolved, {open_part} open"


def _delta(now: int, before: int | None) -> str:
    if before is None or now == before:
        return ""
    return f" ({'+' if now > before else '-'}{abs(now - before)})"


def render_text(d: Digest) -> str:
    lines = [subject(d), ""]
    since = f"with the run on {d.previous.started[:10]}" if d.previous else "(no earlier run to compare with)"
    lines.append(f"Run {d.current.prefix}, compared {since}.")
    lines.append("")
    lines.append("Open by app (High / Medium / Low):")
    for app_id in sorted(d.current.findings, key=lambda a: d.current.names[a]):
        now, before = d.open_counts(app_id), d.previous_counts(app_id)
        cells = " / ".join(f"{now[r]}{_delta(now[r], before and before[r])}" for r in REPORTED_RISKS)
        lines.append(f"  {d.current.names[app_id]}: {cells}")
    for title, items in (("New", d.new), ("Resolved", d.resolved)):
        lines += ["", f"{title} ({len(items)}):"]
        lines += [f"  [{f.risk}] {f.app}: {f.name}" for f in items] or ["  none"]
    if d.first_scans:
        lines += ["", "First scan, not compared: " + ", ".join(d.first_scans)]
    if d.current.errored:
        lines += ["", "Scans that failed (findings carried over, not resolved):"]
        lines += [f"  {name}: {error}" for name, error in d.current.errored]
    if d.current.skipped:
        lines += ["", "Skipped: " + ", ".join(f"{n} ({r})" for n, r in d.current.skipped)]
    lines += ["", f"Reports: the `reports` container, under {d.current.prefix}/."]
    return "\n".join(lines) + "\n"


_RISK_COLOURS = {"High": "#b42318", "Medium": "#b54708", "Low": "#475467"}


def render_html(d: Digest) -> str:
    e = html.escape
    cell = 'style="padding:4px 10px;border-bottom:1px solid #eaecf0;text-align:{}"'
    since = (
        f"with the run on {e(d.previous.started[:10])}" if d.previous else "(no earlier run to compare with)"
    )
    rows = []
    for app_id in sorted(d.current.findings, key=lambda a: d.current.names[a]):
        now, before = d.open_counts(app_id), d.previous_counts(app_id)
        nums = "".join(
            f"<td {cell.format('right')}>{now[r]}{e(_delta(now[r], before and before[r]))}</td>"
            for r in REPORTED_RISKS
        )
        rows.append(f"<tr><td {cell.format('left')}>{e(d.current.names[app_id])}</td>{nums}</tr>")
    head = "".join(f"<th {cell.format('right')}>{r}</th>" for r in REPORTED_RISKS)

    def finding_list(items: list[Finding]) -> str:
        if not items:
            return "<p>None.</p>"
        lis = "".join(
            f'<li><span style="color:{_RISK_COLOURS[f.risk]};font-weight:600">{e(f.risk)}</span> '
            f"{e(f.app)}: {e(f.name)}</li>"
            for f in items
        )
        return f"<ul>{lis}</ul>"

    parts = [
        '<div style="font-family:system-ui,sans-serif;font-size:14px;color:#101828">',
        f'<h2 style="font-size:18px">{e(subject(d))}</h2>',
        f"<p>Run <code>{e(d.current.prefix)}</code>, compared {since}.</p>",
        f'<table style="border-collapse:collapse"><tr><th {cell.format("left")}>App</th>{head}</tr>',
        *rows,
        "</table>",
        f"<h3>New ({len(d.new)})</h3>",
        finding_list(d.new),
        f"<h3>Resolved ({len(d.resolved)})</h3>",
        finding_list(d.resolved),
    ]
    if d.first_scans:
        parts.append(f"<p>First scan, not compared: {e(', '.join(d.first_scans))}</p>")
    if d.current.errored:
        items = "".join(f"<li>{e(n)}: {e(err)}</li>" for n, err in d.current.errored)
        parts.append(f"<h3>Scans that failed</h3><p>Findings carried over, not resolved.</p><ul>{items}</ul>")
    if d.current.skipped:
        parts.append(f"<p>Skipped: {e(', '.join(f'{n} ({r})' for n, r in d.current.skipped))}</p>")
    parts.append(
        f"<p>Reports: the <code>reports</code> container, under <code>{e(d.current.prefix)}/</code>.</p>"
    )
    parts.append("</div>")
    return "\n".join(parts)


def _load_run(container_client, prefix: str) -> Run:
    summary = json.loads(container_client.download_blob(f"{prefix}/summary.json").readall())
    reports = {}
    for result in summary.get("results", []):
        if result.get("status") == "completed" and result.get("report_prefix"):
            blob = container_client.download_blob(f"{result['report_prefix']}/report.json")
            reports[result["target"]["id"]] = json.loads(blob.readall())
    return build_run(prefix, summary, reports)


def send_digest(container_client, credential, run_prefix: str, sender: str) -> None:
    """Compare this run with the previous passive one and email the result.

    Never raises — see the module docstring.
    """
    from . import mailer

    try:
        current = _load_run(container_client, run_prefix)
        before = previous_prefix(list(container_client.list_blob_names()), run_prefix)
        digest = compare(current, _load_run(container_client, before) if before else None)
        result = mailer.send(subject(digest), render_html(digest), render_text(digest), sender, credential)
        log(
            "digest",
            status=result.status,
            error=result.error,
            previous=before,
            new=len(digest.new),
            resolved=len(digest.resolved),
            open=digest.total_open(),
            errored=len(current.errored),
        )
    except Exception as exc:
        log("digest", status="failed", error=f"{type(exc).__name__}: {exc}")
