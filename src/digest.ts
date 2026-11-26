/**
 * The digest: a run's results and what changed since the previous run, by email.
 *
 * Sent at the end of every run. A passive run's weekly schedule gives a
 * weekly digest, and a `make scan` after a fix emails what that fix changed.
 * An active run is started by hand, so its email is how its result arrives: it
 * lists every open finding as well as the changes, and the findings alert
 * ignores active runs. **Each profile is compared only with runs of the same
 * profile**, because attack results don't compare with a passive baseline.
 *
 * **A finding is an app plus a ZAP rule plus a risk**, keyed on ZAP's
 * `alertRef` (falling back to `pluginid`), so one rule raising five instances
 * is one finding, and a rule whose risk changes reads as one resolved and one
 * new. Informational alerts are left out entirely; they are ZAP noting
 * things, not problems. **A finding `accepted.ts` accepts is set aside** as
 * each run is read, in this run and every earlier one alike, so it is never
 * open, new or resolved; the digest lists it under "Accepted" with its reason
 * instead.
 *
 * **Each app is compared with its own last completed scan**, which is usually
 * the previous run but not always: a scan that failed last week would
 * otherwise leave this week's result with nothing to compare against. An app
 * that errored *this* run has not been fixed, so its last known findings are
 * carried into the open counts, marked as such, and none of them read as
 * resolved. An app with no completed scan in the runs looked at is a first
 * scan rather than a flood of "new". An app that has gone from the scan
 * entirely (deleted, or its ingress removed) is named, and its findings are
 * dropped rather than resolved.
 *
 * **The digest never fails the run.** The scan's outcome is already decided
 * and logged by the time this runs. A broken digest logs `digest` with
 * `status: failed` and the job still exits on the scan's own result, so the
 * platform's workload-crashed alert keeps meaning "the scanner is broken".
 */

import { ACCEPTED, accepted, type Accepted } from "./accepted.ts";
import type { MailResult } from "./mailer.ts";
import { RISK_NAMES, alertsOf, log, riskcode, type Container, type ZapReport } from "./scan.ts";

export const REPORTED_RISKS = ["High", "Medium", "Low"] as const;
export type ReportedRisk = (typeof REPORTED_RISKS)[number];
export const PROFILES = ["passive", "active"] as const;
// How many earlier runs to read looking for each app's last completed scan.
// Eight weekly runs is two months; an app failing longer than that is a
// problem the failed-scans section already shouts about.
export const MAX_LOOKBACK = 8;

export interface Finding {
  readonly app_id: string;
  readonly rule: string;
  readonly risk: ReportedRisk;
  // Display only: a rule renamed between ZAP releases is still the same finding.
  readonly app: string;
  readonly name: string;
}

/** What makes two findings the same one: app, rule and risk, not the display names. */
export function findingKey(f: Finding): string {
  return JSON.stringify([f.app_id, f.rule, f.risk]);
}

/** A set of findings by identity. The first one added under a key is kept. */
export class Findings implements Iterable<Finding> {
  readonly #byKey = new Map<string, Finding>();

  constructor(items: Iterable<Finding> = []) {
    for (const f of items) this.add(f);
  }

  add(f: Finding): void {
    const key = findingKey(f);
    if (!this.#byKey.has(key)) this.#byKey.set(key, f);
  }

  has(f: Finding): boolean {
    return this.#byKey.has(findingKey(f));
  }

  get size(): number {
    return this.#byKey.size;
  }

  /** The findings here that `other` does not have. */
  minus(other: Findings): Finding[] {
    return [...this].filter((f) => !other.has(f));
  }

  [Symbol.iterator](): Iterator<Finding> {
    return this.#byKey.values();
  }
}

/** Accepted findings, by finding identity, each with the entry that accepts it. */
export type AcceptedFindings = Map<string, [Finding, Accepted]>;

export interface Run {
  prefix: string;
  started: string;
  /** Apps whose scan completed, by resource id, with what it found. */
  findings: Map<string, Findings>;
  /** Every app the run attempted, completed or not, by resource id. */
  names: Map<string, string>;
  errored: [name: string, error: string][];
  skipped: [name: string, reason: string][];
  /** Completed apps' findings that accepted.ts accepts, kept out of `findings`. */
  accepted: AcceptedFindings;
}

function counts(findings: Iterable<Finding>): Record<ReportedRisk, number> {
  const result: Record<ReportedRisk, number> = { High: 0, Medium: 0, Low: 0 };
  for (const f of findings) result[f.risk] += 1;
  return result;
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareLists(a: readonly string[], b: readonly string[]): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const c = compareText(a[i] as string, b[i] as string);
    if (c) return c;
  }
  return a.length - b.length;
}

/** Risk first (High down), then app, then the finding's name. */
export function order(a: Finding, b: Finding): number {
  return (
    REPORTED_RISKS.indexOf(a.risk) - REPORTED_RISKS.indexOf(b.risk) ||
    compareText(a.app, b.app) ||
    compareText(a.name, b.name)
  );
}

function sortedText(items: Iterable<string>): string[] {
  return [...items].sort(compareText);
}

export interface DigestFields {
  current: Run;
  /** The run immediately before this one, for the headline comparison. */
  previous: Run | null;
  newFindings: Finding[];
  resolved: Finding[];
  firstScans: string[];
  /** Per app, the run its comparison was made against, when there was one. */
  baseline: Map<string, Run>;
  /** Apps that errored this run, with their last completed scan's findings. */
  carried: Map<string, Findings>;
  /** And those scans' accepted findings, so they stay listed as accepted. */
  carriedAccepted: AcceptedFindings;
  noLongerScanned: string[];
}

export class Digest implements DigestFields {
  readonly current: Run;
  readonly previous: Run | null;
  readonly newFindings: Finding[];
  readonly resolved: Finding[];
  readonly firstScans: string[];
  readonly baseline: Map<string, Run>;
  readonly carried: Map<string, Findings>;
  readonly carriedAccepted: AcceptedFindings;
  readonly noLongerScanned: string[];

  constructor(fields: DigestFields) {
    this.current = fields.current;
    this.previous = fields.previous;
    this.newFindings = fields.newFindings;
    this.resolved = fields.resolved;
    this.firstScans = fields.firstScans;
    this.baseline = fields.baseline;
    this.carried = fields.carried;
    this.carriedAccepted = fields.carriedAccepted;
    this.noLongerScanned = fields.noLongerScanned;
  }

  openFindings(appId: string): Findings {
    const found = this.current.findings.get(appId);
    return found && found.size ? found : (this.carried.get(appId) ?? new Findings());
  }

  openCounts(appId: string): Record<ReportedRisk, number> {
    return counts(this.openFindings(appId));
  }

  previousCounts(appId: string): Record<ReportedRisk, number> | null {
    const run = this.baseline.get(appId);
    if (run === undefined || this.carried.has(appId)) return null;
    return counts(run.findings.get(appId) ?? []);
  }

  get profile(): string {
    return profileOf(this.current.prefix);
  }

  allOpen(): Finding[] {
    const all = new Findings();
    for (const found of [...this.current.findings.values(), ...this.carried.values()]) {
      for (const f of found) all.add(f);
    }
    return [...all].sort(order);
  }

  totalOpen(): Record<ReportedRisk, number> {
    return counts(this.allOpen());
  }

  /** Apps with something to show, by name: completed this run, or carried. */
  appRows(): string[] {
    const ids = new Set([...this.current.findings.keys(), ...this.carried.keys()]);
    const name = (id: string) => this.current.names.get(id) ?? "";
    return [...ids].sort((a, b) => compareText(name(a), name(b)));
  }

  /**
   * Each accepted finding: its entry, its name and the apps raising it.
   *
   * By entry, so each reason names only the apps it covers. An app whose scan
   * failed this run keeps its last scan's accepted findings here, as its open
   * ones are carried into the counts.
   */
  acceptedRows(): [entry: Accepted, label: string, apps: string[]][] {
    const merged = new Map([...this.current.accepted, ...this.carriedAccepted]);
    const rows = new Map<string, [Accepted, string, Set<string>]>();
    for (const [f, entry] of merged.values()) {
      const key = JSON.stringify([entry.rule, entry.risk, entry.reason, entry.app ?? "*"]);
      let row = rows.get(key);
      if (row === undefined) {
        row = [entry, `[${f.risk}] ${f.name}`, new Set()];
        rows.set(key, row);
      }
      row[2].add(f.app);
    }
    return [...rows.values()]
      .map(([entry, label, apps]): [Accepted, string, string[]] => [entry, label, sortedText(apps)])
      .sort((a, b) => compareText(a[1], b[1]) || compareLists(a[2], b[2]));
  }

  rowNote(appId: string): string {
    const run = this.baseline.get(appId);
    if (this.carried.has(appId)) {
      return `scan failed; last result, ${(run?.started ?? "").slice(0, 10)}`;
    }
    if (run !== undefined && this.previous !== null && run.prefix !== this.previous.prefix) {
      return `compared with ${run.started.slice(0, 10)}`;
    }
    return "";
  }
}

/** The non-informational findings in a ZAP traditional-json report. */
export function findingsFromReport(appId: string, app: string, report: ZapReport): Findings {
  const found = new Findings();
  for (const alert of alertsOf(report)) {
    const code = riskcode(alert.riskcode);
    if (code === null) continue;
    const risk = RISK_NAMES[code] ?? "Informational";
    if (risk === "Informational") continue;
    // Python's `str(a or b or c)`: the last value when none is truthy, and
    // None (a missing key) reads as "None".
    const ref = alert.alertRef || alert.pluginid || alert.name;
    const rule = ref === undefined || ref === null ? "None" : String(ref);
    const name = String(alert.name || alert.alert || rule);
    found.add({ app_id: appId, rule, risk, app, name });
  }
  return found;
}

/**
 * The profile a run prefix (`YYYY-MM-DD/HHMMSSZ-<profile>`) belongs to.
 *
 * Passive when it names none, the profile every run had before active existed.
 */
export function profileOf(prefix: string): string {
  const profile = prefix.slice(prefix.lastIndexOf("-") + 1);
  return (PROFILES as readonly string[]).includes(profile) ? profile : "passive";
}

/**
 * The latest run of `current`'s profile before it, from the container's blob
 * names. Run prefixes are `YYYY-MM-DD/HHMMSSZ-<profile>`, so they sort by time.
 */
export function previousPrefix(blobNames: readonly string[], current: string): string | null {
  const suffix = `-${profileOf(current)}/summary.json`;
  const runs = sortedText(
    blobNames.filter((n) => n.endsWith(suffix)).map((n) => n.slice(0, -"/summary.json".length)),
  );
  const earlier = runs.filter((r) => r < current);
  return earlier.at(-1) ?? null;
}

/** A summary.json, as the scanner writes it. */
export interface Summary {
  started?: string;
  results?: {
    target?: { id?: string; name?: string };
    status?: string;
    error?: string | null;
    report_prefix?: string | null;
  }[];
  skipped?: { name?: string; reason?: string }[];
}

/**
 * A Run from a summary.json and the report.json of each completed target.
 *
 * `reports` maps a target's resource id to its parsed report; a completed
 * target with no report is treated as errored, since nothing can be said
 * about it. Findings `entries` accepts go to `accepted`, not `findings`.
 */
export function buildRun(
  prefix: string,
  summary: Summary,
  reports: ReadonlyMap<string, ZapReport>,
  entries: readonly Accepted[] = ACCEPTED,
): Run {
  const run: Run = {
    prefix,
    started: summary.started ?? "",
    findings: new Map(),
    names: new Map(),
    errored: [],
    skipped: [],
    accepted: new Map(),
  };
  for (const result of summary.results ?? []) {
    const appId = result.target?.id ?? "";
    const name = result.target?.name ?? "";
    run.names.set(appId, name);
    const report = reports.get(appId);
    if (result.status === "completed" && report !== undefined) {
      const open = new Findings();
      run.findings.set(appId, open);
      for (const f of findingsFromReport(appId, name, report)) {
        const entry = accepted(f.rule, f.risk, name, entries);
        if (entry) run.accepted.set(findingKey(f), [f, entry]);
        else open.add(f);
      }
    } else if (result.status === "completed") {
      run.errored.push([name, "report missing"]);
    } else {
      run.errored.push([name, result.error || result.status || "unknown"]);
    }
  }
  run.skipped = (summary.skipped ?? []).map((s) => [s.name ?? "", s.reason ?? ""]);
  return run;
}

/** Compare `current` with `earlier` runs, newest first. */
export function compare(current: Run, earlier: readonly Run[]): Digest {
  const added = new Findings();
  const resolved = new Findings();
  const firstScans: string[] = [];
  const baseline = new Map<string, Run>();
  const carried = new Map<string, Findings>();
  const carriedAccepted: AcceptedFindings = new Map();
  for (const [appId, name] of current.names) {
    const before = earlier.find((r) => r.findings.has(appId));
    if (before !== undefined) baseline.set(appId, before);
    const found = current.findings.get(appId);
    const was = before?.findings.get(appId);
    if (found === undefined) {
      if (was !== undefined && before !== undefined) {
        carried.set(appId, was);
        for (const [key, pair] of before.accepted) {
          if (pair[0].app_id === appId) carriedAccepted.set(key, pair);
        }
      }
    } else if (was === undefined) {
      firstScans.push(name);
    } else {
      for (const f of found.minus(was)) added.add(f);
      for (const f of was.minus(found)) resolved.add(f);
    }
  }

  const previous = earlier[0] ?? null;
  let gone: string[] = [];
  if (previous !== null) {
    const skipped = new Set(current.skipped.map(([name]) => name));
    gone = sortedText(
      [...previous.names]
        .filter(([id, name]) => !current.names.has(id) && !skipped.has(name))
        .map(([, name]) => name),
    );
  }
  return new Digest({
    current,
    previous,
    newFindings: [...added].sort(order),
    resolved: [...resolved].sort(order),
    firstScans: sortedText(firstScans),
    baseline,
    carried,
    carriedAccepted,
    noLongerScanned: gone,
  });
}

export function subject(d: Digest): string {
  const openPart =
    Object.entries(d.totalOpen())
      .filter(([, n]) => n)
      .map(([risk, n]) => `${n} ${risk}`)
      .join(", ") || "nothing";
  let head = d.profile === "active" ? "Active security scan" : "Security scan";
  if (d.current.errored.length) head += ` (${d.current.errored.length} failed)`;
  if (d.previous === null) return `${head}: first digest, ${openPart} open`;
  return `${head}: ${d.newFindings.length} new, ${d.resolved.length} resolved, ${openPart} open`;
}

function delta(now: number, before: number | null): string {
  if (before === null || now === before) return "";
  return ` (${now > before ? "+" : "-"}${Math.abs(now - before)})`;
}

/** Each risk's cell: the open count, and its change when there is one to show. */
function cells(d: Digest, appId: string): string[] {
  const now = d.openCounts(appId);
  const before = d.previousCounts(appId);
  return REPORTED_RISKS.map((r) => `${now[r]}${delta(now[r], before ? before[r] : null)}`);
}

function failureNote(d: Digest, name: string): string {
  const appId = [...d.current.names].find(([, n]) => n === name)?.[0];
  return appId !== undefined && d.carried.has(appId) ? " (last result carried over)" : " (no earlier result)";
}

function since(d: Digest, escape: (s: string) => string = (s) => s): string {
  return d.previous
    ? `with the run on ${escape(d.previous.started.slice(0, 10))}`
    : "(no earlier run to compare with)";
}

export function renderText(d: Digest): string {
  const lines = [subject(d), ""];
  lines.push(`Run ${d.current.prefix}, compared ${since(d)}.`);
  lines.push("");
  lines.push("Open by app (High / Medium / Low):");
  for (const appId of d.appRows()) {
    const note = d.rowNote(appId);
    lines.push(
      `  ${d.current.names.get(appId)}: ${cells(d, appId).join(" / ")}` + (note ? `  [${note}]` : ""),
    );
  }
  const listed = (items: Finding[]) =>
    items.length ? items.map((f) => `  [${f.risk}] ${f.app}: ${f.name}`) : ["  none"];
  if (d.profile === "active") {
    const found = d.allOpen();
    lines.push("", `Open findings (${found.length}):`, ...listed(found));
  }
  lines.push("", `New (${d.newFindings.length}):`, ...listed(d.newFindings));
  lines.push("", `Resolved (${d.resolved.length}):`, ...listed(d.resolved));
  const rows = d.acceptedRows();
  if (rows.length) {
    lines.push("", `Accepted, not counted (${rows.length}):`);
    for (const [entry, label, apps] of rows) {
      lines.push(`  ${label}: ${apps.join(", ")}\n    ${entry.reason}`);
    }
  }
  if (d.firstScans.length) {
    lines.push("", "First scan, not compared: " + d.firstScans.join(", "));
  }
  if (d.noLongerScanned.length) {
    lines.push("", "No longer scanned (findings dropped, not resolved): " + d.noLongerScanned.join(", "));
  }
  if (d.current.errored.length) {
    lines.push("", "Scans that failed (nothing marked resolved):");
    for (const [name, error] of d.current.errored) {
      lines.push(`  ${name}: ${error}${failureNote(d, name)}`);
    }
  }
  if (d.current.skipped.length) {
    lines.push("", "Skipped: " + d.current.skipped.map(([n, r]) => `${n} (${r})`).join(", "));
  }
  lines.push("", `Reports: the \`reports\` container, under ${d.current.prefix}/.`);
  return lines.join("\n") + "\n";
}

const RISK_COLOURS: Record<ReportedRisk, string> = {
  High: "#b42318",
  Medium: "#b54708",
  Low: "#475467",
};

/** Python's html.escape: &, <, >, and both quotes. */
export function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#x27;");
}

export function renderHtml(d: Digest): string {
  const e = escapeHtml;
  const cell = (align: string) =>
    `style="padding:4px 10px;border-bottom:1px solid #eaecf0;text-align:${align}"`;
  const rows = d.appRows().map((appId) => {
    const nums = cells(d, appId)
      .map((c) => `<td ${cell("right")}>${e(c)}</td>`)
      .join("");
    const note = d.rowNote(appId);
    const label =
      e(d.current.names.get(appId) ?? "") + (note ? ` <span style="color:#667085">(${e(note)})</span>` : "");
    return `<tr><td ${cell("left")}>${label}</td>${nums}</tr>`;
  });
  const head = REPORTED_RISKS.map((r) => `<th ${cell("right")}>${r}</th>`).join("");

  const findingList = (items: Finding[]): string => {
    if (!items.length) return "<p>None.</p>";
    const lis = items
      .map(
        (f) =>
          `<li><span style="color:${RISK_COLOURS[f.risk]};font-weight:600">${e(f.risk)}</span> ` +
          `${e(f.app)}: ${e(f.name)}</li>`,
      )
      .join("");
    return `<ul>${lis}</ul>`;
  };

  const parts = [
    '<div style="font-family:system-ui,sans-serif;font-size:14px;color:#101828">',
    `<h2 style="font-size:18px">${e(subject(d))}</h2>`,
    `<p>Run <code>${e(d.current.prefix)}</code>, compared ${since(d, e)}.</p>`,
    `<table style="border-collapse:collapse"><tr><th ${cell("left")}>App</th>${head}</tr>`,
    ...rows,
    "</table>",
    ...(d.profile === "active"
      ? [`<h3>Open findings (${d.allOpen().length})</h3>`, findingList(d.allOpen())]
      : []),
    `<h3>New (${d.newFindings.length})</h3>`,
    findingList(d.newFindings),
    `<h3>Resolved (${d.resolved.length})</h3>`,
    findingList(d.resolved),
  ];
  const acceptedRows = d.acceptedRows();
  if (acceptedRows.length) {
    const lis = acceptedRows
      .map(
        ([entry, label, apps]) =>
          `<li>${e(label)}: ${e(apps.join(", "))}<br>` +
          `<span style="color:#667085">${e(entry.reason)}</span></li>`,
      )
      .join("");
    parts.push(`<h3>Accepted, not counted (${acceptedRows.length})</h3><ul>${lis}</ul>`);
  }
  if (d.firstScans.length) {
    parts.push(`<p>First scan, not compared: ${e(d.firstScans.join(", "))}</p>`);
  }
  if (d.noLongerScanned.length) {
    parts.push(
      `<p>No longer scanned (findings dropped, not resolved): ${e(d.noLongerScanned.join(", "))}</p>`,
    );
  }
  if (d.current.errored.length) {
    const items = d.current.errored
      .map(([n, err]) => `<li>${e(n)}: ${e(err)}${e(failureNote(d, n))}</li>`)
      .join("");
    parts.push(`<h3>Scans that failed</h3><p>Nothing is marked resolved for these.</p><ul>${items}</ul>`);
  }
  if (d.current.skipped.length) {
    parts.push(`<p>Skipped: ${e(d.current.skipped.map(([n, r]) => `${n} (${r})`).join(", "))}</p>`);
  }
  parts.push(
    `<p>Reports: the <code>reports</code> container, under <code>${e(d.current.prefix)}/</code>.</p>`,
  );
  parts.push("</div>");
  return parts.join("\n");
}

function isNotFound(error: unknown): boolean {
  return (error as { statusCode?: number }).statusCode === 404;
}

async function downloadJson<T>(container: Container, name: string): Promise<T> {
  return JSON.parse((await container.getBlobClient(name).downloadToBuffer()).toString("utf8"));
}

export async function loadRun(container: Container, prefix: string): Promise<Run> {
  const summary = await downloadJson<Summary>(container, `${prefix}/summary.json`);
  const reports = new Map<string, ZapReport>();
  for (const result of summary.results ?? []) {
    if (result.status === "completed" && result.report_prefix) {
      try {
        reports.set(
          result.target?.id ?? "",
          await downloadJson<ZapReport>(container, `${result.report_prefix}/report.json`),
        );
      } catch (error) {
        // buildRun records it as errored, "report missing".
        if (!isNotFound(error)) throw error;
      }
    }
  }
  return buildRun(prefix, summary, reports);
}

/**
 * Earlier runs of the same profile, newest first, until every app has a
 * baseline. Stops at MAX_LOOKBACK, or as soon as each app in `current` has a
 * completed scan somewhere in what has been read.
 */
export async function earlierRuns(container: Container, current: Run): Promise<Run[]> {
  const names: string[] = [];
  for await (const blob of container.listBlobsFlat()) names.push(blob.name);
  const runs: Run[] = [];
  let cursor = current.prefix;
  while (runs.length < MAX_LOOKBACK) {
    const before = previousPrefix(names, cursor);
    if (before === null) break;
    runs.push(await loadRun(container, before));
    cursor = before;
    if ([...current.names.keys()].every((a) => runs.some((r) => r.findings.has(a)))) break;
  }
  return runs;
}

export type Mail = (subject: string, html: string, text: string, sender: string) => Promise<MailResult>;

function describe(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

/**
 * Compare this run with earlier ones of its profile and email the result.
 * Never throws; see the module comment.
 */
export async function sendDigest(
  container: Container,
  runPrefix: string,
  sender: string,
  mail: Mail,
): Promise<void> {
  try {
    const current = await loadRun(container, runPrefix);
    const earlier = await earlierRuns(container, current);
    const digest = compare(current, earlier);
    const result = await mail(subject(digest), renderHtml(digest), renderText(digest), sender);
    log("digest", {
      profile: digest.profile,
      status: result.status,
      error: result.error,
      provider_id: result.provider_id,
      previous: earlier[0]?.prefix ?? null,
      runs_read: earlier.length,
      new: digest.newFindings.length,
      resolved: digest.resolved.length,
      open: digest.totalOpen(),
      accepted: current.accepted.size + digest.carriedAccepted.size,
      errored: current.errored.length,
    });
  } catch (error) {
    log("digest", { status: "failed", error: describe(error) });
  }
}
