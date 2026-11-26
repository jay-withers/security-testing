/**
 * Findings accepted as risks, which the digest lists apart from what is open.
 *
 * A finding here is a decision, not a problem: it is never counted as open,
 * new or resolved, and the digest names it under "Accepted" with its reason,
 * so it stays visible without reading as news every week. Anything else a
 * rule raises at a different risk, or on an app the entry doesn't cover, is
 * still reported as usual.
 *
 * An entry needs a reason that points at where the decision is written down.
 * Remove the entry when the decision changes; the finding then reads as new
 * again, which is the point.
 *
 * `rule` is ZAP's `alertRef` (https://www.zaproxy.org/docs/alerts/) and `risk`
 * the risk it is accepted at. `app` is the container app's full name as the
 * scan names it (`ca-health-dev`, not `health`), or "*" for every app.
 */

export interface Accepted {
  readonly rule: string;
  readonly risk: string;
  readonly reason: string;
  /** Defaults to "*", every app. */
  readonly app?: string;
}

export function covers(entry: Accepted, rule: string, risk: string, app: string): boolean {
  const scope = entry.app ?? "*";
  return entry.rule === rule && entry.risk === risk && (scope === "*" || scope === app);
}

export const ACCEPTED: readonly Accepted[] = [
  {
    rule: "10055-6", // CSP: style-src unsafe-inline
    risk: "Medium",
    reason:
      "Deliberate: scripts are nonce-gated, styles keep 'unsafe-inline' for the " +
      "templates' style attributes (appkit headers.py; health#70)",
  },
];

/** The entry accepting `rule` at `risk` on `app`, if there is one. */
export function accepted(
  rule: string,
  risk: string,
  app: string,
  entries: readonly Accepted[] = ACCEPTED,
): Accepted | undefined {
  return entries.find((e) => covers(e, rule, risk, app));
}
