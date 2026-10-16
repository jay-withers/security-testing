"""The digest: a run's results and what changed since the previous run, by email.

Sent at the end of every run. A passive run's weekly schedule gives a weekly
digest, and a `make scan` after a fix emails what that fix changed. An active
run is started by hand, so its email is how its result arrives: it lists every
open finding as well as the changes, and the findings alert ignores active
runs. **Each profile is compared only with runs of the same profile**, because
attack results don't compare with a passive baseline.

**A finding is an app plus a ZAP rule plus a risk**, keyed on ZAP's `alertRef`
(falling back to `pluginid`), so one rule raising five instances is one
finding, and a rule whose risk changes reads as one resolved and one new.
Informational alerts are left out entirely; they are ZAP noting things, not
problems.

**Each app is compared with its own last completed scan**, which is usually
the previous run but not always: a scan that failed last week would otherwise
leave this week's result with nothing to compare against. An app that errored
*this* run has not been fixed, so its last known findings are carried into
the open counts, marked as such, and none of them read as resolved. An app
with no completed scan in the runs looked at is a first scan rather than a
flood of "new". An app that has gone from the scan entirely (deleted, or its
ingress removed) is named, and its findings are dropped rather than resolved.

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
PROFILES = ("passive", "active")
# How many earlier runs to read looking for each app's last completed scan.
# Eight weekly runs is two months; an app failing longer than that is a
# problem the failed-scans section already shouts about.
MAX_LOOKBACK = 8


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
    # Every app the run attempted, completed or not, by resource id.
    names: dict[str, str]
    errored: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Digest:
    current: Run
    # The run immediately before this one, for the headline comparison.
    previous: Run | None
    new: list[Finding]
    resolved: list[Finding]
    first_scans: list[str]
    # Per app, the run its comparison was made against, when there was one.
    baseline: dict[str, Run] = field(default_factory=dict)
    # Apps that errored this run, with their last completed scan's findings.
    carried: dict[str, set[Finding]] = field(default_factory=dict)
    no_longer_scanned: list[str] = field(default_factory=list)

    def open_findings(self, app_id: str) -> set[Finding]:
        return self.current.findings.get(app_id) or self.carried.get(app_id, set())

    def open_counts(self, app_id: str) -> dict[str, int]:
        return _counts(self.open_findings(app_id))

    def previous_counts(self, app_id: str) -> dict[str, int] | None:
        if app_id not in self.baseline or app_id in self.carried:
            return None
        return _counts(self.baseline[app_id].findings[app_id])

    @property
    def profile(self) -> str:
        return profile_of(self.current.prefix)

    def all_open(self) -> list[Finding]:
        return sorted(set().union(set(), *self.current.findings.values(), *self.carried.values()), key=_order)

    def total_open(self) -> dict[str, int]:
        return _counts(set(self.all_open()))

    def app_rows(self) -> list[str]:
        """Apps with something to show, by name: completed this run, or carried."""
        return sorted({*self.current.findings, *self.carried}, key=lambda a: self.current.names[a])

    def row_note(self, app_id: str) -> str:
        if app_id in self.carried:
            return f"scan failed; last result, {self.baseline[app_id].started[:10]}"
        run = self.baseline.get(app_id)
        if run is not None and self.previous is not None and run.prefix != self.previous.prefix:
            return f"compared with {run.started[:10]}"
        return ""


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


def profile_of(prefix: str) -> str:
    """The profile a run prefix (`YYYY-MM-DD/HHMMSSZ-<profile>`) belongs to.

    Passive when it names none, the profile every run had before active existed.
    """
    profile = prefix.rsplit("-", 1)[-1]
    return profile if profile in PROFILES else "passive"


def previous_prefix(blob_names: list[str], current: str) -> str | None:
    """The latest run of `current`'s profile before it, from the container's blob names.

    Run prefixes are `YYYY-MM-DD/HHMMSSZ-<profile>`, so they sort by time.
    """
    suffix = f"-{profile_of(current)}/summary.json"
    runs = sorted(n[: -len("/summary.json")] for n in blob_names if n.endswith(suffix))
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
        status = result.get("status")
        if status == "completed" and app_id in reports:
            run.findings[app_id] = findings_from_report(app_id, name, reports[app_id])
        elif status == "completed":
            run.errored.append((name, "report missing"))
        else:
            run.errored.append((name, result.get("error") or status or "unknown"))
    run.skipped = [(s.get("name", ""), s.get("reason", "")) for s in summary.get("skipped", [])]
    return run


def compare(current: Run, earlier: list[Run]) -> Digest:
    """Compare `current` with `earlier` runs, newest first."""
    new: set[Finding] = set()
    resolved: set[Finding] = set()
    first_scans = []
    baseline: dict[str, Run] = {}
    carried: dict[str, set[Finding]] = {}
    for app_id in current.names:
        before = next((r for r in earlier if app_id in r.findings), None)
        if before is not None:
            baseline[app_id] = before
        if app_id not in current.findings:
            if before is not None:
                carried[app_id] = before.findings[app_id]
        elif before is None:
            first_scans.append(current.names[app_id])
        else:
            found, was = current.findings[app_id], before.findings[app_id]
            new |= found - was
            resolved |= was - found

    previous = earlier[0] if earlier else None
    gone = []
    if previous is not None:
        skipped = {name for name, _ in current.skipped}
        gone = sorted(
            previous.names[a]
            for a in previous.names.keys() - current.names.keys()
            if previous.names[a] not in skipped
        )
    return Digest(
        current,
        previous,
        sorted(new, key=_order),
        sorted(resolved, key=_order),
        sorted(first_scans),
        baseline=baseline,
        carried=carried,
        no_longer_scanned=gone,
    )


def _order(f: Finding) -> tuple:
    return (REPORTED_RISKS.index(f.risk), f.app, f.name)


def subject(d: Digest) -> str:
    totals = d.total_open()
    open_part = ", ".join(f"{n} {risk}" for risk, n in totals.items() if n) or "nothing"
    head = "Active security scan" if d.profile == "active" else "Security scan"
    if d.current.errored:
        head += f" ({len(d.current.errored)} failed)"
    if d.previous is None:
        return f"{head}: first digest, {open_part} open"
    return f"{head}: {len(d.new)} new, {len(d.resolved)} resolved, {open_part} open"


def _delta(now: int, before: int | None) -> str:
    if before is None or now == before:
        return ""
    return f" ({'+' if now > before else '-'}{abs(now - before)})"


def _failure_note(d: Digest, name: str) -> str:
    app_id = next((a for a, n in d.current.names.items() if n == name), None)
    return " (last result carried over)" if app_id in d.carried else " (no earlier result)"


def render_text(d: Digest) -> str:
    lines = [subject(d), ""]
    since = f"with the run on {d.previous.started[:10]}" if d.previous else "(no earlier run to compare with)"
    lines.append(f"Run {d.current.prefix}, compared {since}.")
    lines.append("")
    lines.append("Open by app (High / Medium / Low):")
    for app_id in d.app_rows():
        now, before = d.open_counts(app_id), d.previous_counts(app_id)
        cells = " / ".join(f"{now[r]}{_delta(now[r], before and before[r])}" for r in REPORTED_RISKS)
        note = d.row_note(app_id)
        lines.append(f"  {d.current.names[app_id]}: {cells}" + (f"  [{note}]" if note else ""))
    if d.profile == "active":
        found = d.all_open()
        lines += ["", f"Open findings ({len(found)}):"]
        lines += [f"  [{f.risk}] {f.app}: {f.name}" for f in found] or ["  none"]
    for title, items in (("New", d.new), ("Resolved", d.resolved)):
        lines += ["", f"{title} ({len(items)}):"]
        lines += [f"  [{f.risk}] {f.app}: {f.name}" for f in items] or ["  none"]
    if d.first_scans:
        lines += ["", "First scan, not compared: " + ", ".join(d.first_scans)]
    if d.no_longer_scanned:
        lines += ["", "No longer scanned (findings dropped, not resolved): " + ", ".join(d.no_longer_scanned)]
    if d.current.errored:
        lines += ["", "Scans that failed (nothing marked resolved):"]
        lines += [f"  {name}: {error}{_failure_note(d, name)}" for name, error in d.current.errored]
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
    for app_id in d.app_rows():
        now, before = d.open_counts(app_id), d.previous_counts(app_id)
        nums = "".join(
            f"<td {cell.format('right')}>{now[r]}{e(_delta(now[r], before and before[r]))}</td>"
            for r in REPORTED_RISKS
        )
        note = d.row_note(app_id)
        label = e(d.current.names[app_id]) + (
            f' <span style="color:#667085">({e(note)})</span>' if note else ""
        )
        rows.append(f"<tr><td {cell.format('left')}>{label}</td>{nums}</tr>")
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
        *(
            [f"<h3>Open findings ({len(d.all_open())})</h3>", finding_list(d.all_open())]
            if d.profile == "active"
            else []
        ),
        f"<h3>New ({len(d.new)})</h3>",
        finding_list(d.new),
        f"<h3>Resolved ({len(d.resolved)})</h3>",
        finding_list(d.resolved),
    ]
    if d.first_scans:
        parts.append(f"<p>First scan, not compared: {e(', '.join(d.first_scans))}</p>")
    if d.no_longer_scanned:
        parts.append(
            f"<p>No longer scanned (findings dropped, not resolved): {e(', '.join(d.no_longer_scanned))}</p>"
        )
    if d.current.errored:
        items = "".join(f"<li>{e(n)}: {e(err)}{e(_failure_note(d, n))}</li>" for n, err in d.current.errored)
        parts.append(
            f"<h3>Scans that failed</h3><p>Nothing is marked resolved for these.</p><ul>{items}</ul>"
        )
    if d.current.skipped:
        parts.append(f"<p>Skipped: {e(', '.join(f'{n} ({r})' for n, r in d.current.skipped))}</p>")
    parts.append(
        f"<p>Reports: the <code>reports</code> container, under <code>{e(d.current.prefix)}/</code>.</p>"
    )
    parts.append("</div>")
    return "\n".join(parts)


def _load_run(container_client, prefix: str) -> Run:
    from azure.core.exceptions import ResourceNotFoundError

    summary = json.loads(container_client.download_blob(f"{prefix}/summary.json").readall())
    reports = {}
    for result in summary.get("results", []):
        if result.get("status") == "completed" and result.get("report_prefix"):
            try:
                blob = container_client.download_blob(f"{result['report_prefix']}/report.json")
            except ResourceNotFoundError:
                continue  # build_run records it as errored, "report missing"
            reports[result["target"]["id"]] = json.loads(blob.readall())
    return build_run(prefix, summary, reports)


def _earlier_runs(container_client, current: Run) -> list[Run]:
    """Earlier runs of the same profile, newest first, until every app has a baseline.

    Stops at MAX_LOOKBACK, or as soon as each app in `current` has a
    completed scan somewhere in what has been read.
    """
    names = list(container_client.list_blob_names())
    runs: list[Run] = []
    cursor = current.prefix
    while len(runs) < MAX_LOOKBACK and (before := previous_prefix(names, cursor)):
        runs.append(_load_run(container_client, before))
        cursor = before
        if all(any(a in r.findings for r in runs) for a in current.names):
            break
    return runs


def send_digest(container_client, credential, run_prefix: str, sender: str) -> None:
    """Compare this run with earlier ones of its profile and email the result.

    Never raises — see the module docstring.
    """
    from . import mailer

    try:
        current = _load_run(container_client, run_prefix)
        earlier = _earlier_runs(container_client, current)
        digest = compare(current, earlier)
        result = mailer.send(subject(digest), render_html(digest), render_text(digest), sender, credential)
        log(
            "digest",
            profile=digest.profile,
            status=result.status,
            error=result.error,
            provider_id=result.provider_id,
            previous=earlier[0].prefix if earlier else None,
            runs_read=len(earlier),
            new=len(digest.new),
            resolved=len(digest.resolved),
            open=digest.total_open(),
            errored=len(current.errored),
        )
    except Exception as exc:
        log("digest", status="failed", error=f"{type(exc).__name__}: {exc}")
