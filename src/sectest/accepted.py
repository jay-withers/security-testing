"""Findings accepted as risks, which the digest lists apart from what is open.

A finding here is a decision, not a problem: it is never counted as open, new
or resolved, and the digest names it under "Accepted" with its reason, so it
stays visible without reading as news every week. Anything else a rule
raises at a different risk, or on an app the entry doesn't cover, is still
reported as usual.

An entry needs a reason that points at where the decision is written down.
Remove the entry when the decision changes; the finding then reads as new
again, which is the point.

`rule` is ZAP's `alertRef` (https://www.zaproxy.org/docs/alerts/) and `risk`
the risk it is accepted at. `app` is the container app's full name as the scan
names it (`ca-health-dev`, not `health`), or "*" for every app.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Accepted:
    rule: str
    risk: str
    reason: str
    app: str = "*"

    def covers(self, rule: str, risk: str, app: str) -> bool:
        return self.rule == rule and self.risk == risk and self.app in ("*", app)


ACCEPTED: tuple[Accepted, ...] = (
    Accepted(
        rule="10055-6",  # CSP: style-src unsafe-inline
        risk="Medium",
        reason=(
            "Deliberate: scripts are nonce-gated, styles keep 'unsafe-inline' for the "
            "templates' style attributes (appkit headers.py; health#70)"
        ),
    ),
)


def accepted(rule: str, risk: str, app: str, entries: tuple[Accepted, ...] = ACCEPTED) -> Accepted | None:
    """The entry accepting `rule` at `risk` on `app`, if there is one."""
    return next((e for e in entries if e.covers(rule, risk, app)), None)
