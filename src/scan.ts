/**
 * DAST scanner for Azure Container Apps.
 *
 * Discovers Container Apps with external ingress via Azure Resource Graph,
 * runs an OWASP ZAP scan against each one, and uploads the reports to Blob
 * Storage.
 *
 * Two profiles run the same image, selected by SCAN_PROFILE:
 *
 *   passive   weekly. Every app; spider + passive rules only, nothing is
 *             attacked. Ends by emailing a digest of what changed (digest.ts).
 *   active    on demand only (no schedule). Every app that has not opted out;
 *             sends attack payloads. Ends by emailing its findings (digest.ts).
 *
 * Active scanning is **opt-out**. Per-app behaviour is controlled by tags on
 * the target Container App:
 *
 *   security-scan = "false"                  skip this app in both profiles
 *   security-scan-mode = "passive"           opt out of the active profile only
 *   security-scan-openapi = "/openapi.json"  scan the API in this spec instead of spidering
 *
 * zap-api-scan.py is active by default, so the passive profile passes it -S
 * (safe mode): an openapi tag never turns a passive run into an attack.
 *
 * Configuration comes from environment variables (set by the Terraform module):
 *
 *   TARGET_SUBSCRIPTION_IDS  comma-separated subscription IDs to discover apps in
 *   REPORT_CONTAINER_URL     blob container for reports, e.g. https://acct.blob.core.windows.net/reports
 *   SCAN_FAIL_ON             lowest risk flagged as over_threshold: Low|Medium|High (default High)
 *   SCAN_SPIDER_MINUTES      spider time cap per target (default 5)
 *   SCAN_TARGET_TIMEOUT      hard timeout per target in seconds (default 1800)
 *   SCAN_PROFILE             passive | active (default passive, the safe one)
 *   ENVIRONMENT              recorded in the run summary
 *   LOG_SOURCE               stamped on every log line; the findings alert filters on it
 *   KEY_VAULT_URI            vault holding RESEND-API-KEY and DIGEST-EMAIL-TO (see mailer.ts)
 *   DIGEST_EMAIL_FROM        sender of the digest, on a domain verified in Resend
 *   AZURE_CLIENT_ID          user-assigned managed identity (read by DefaultAzureCredential)
 *
 * Exit status is 0 whenever every scan ran, **even if it found something**. A
 * non-zero exit fails the job execution, which the shared platform's
 * workload-crashed alert reads as "this workload is broken". Findings are
 * reported as `scan_finished` lines with `over_threshold: true` instead. A
 * passive run's are alerted on by terraform/main.alerts.tf; an active run's
 * arrive by email.
 *
 * The run summary (summary.json) keeps the Python scanner's snake_case keys,
 * because the digest reads earlier runs' summaries, whichever scanner wrote
 * them.
 */

import { spawn as nodeSpawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { constants } from "node:os";

export const ZAP_WORK_DIR = "/zap/wrk";

/** Wait `ms` milliseconds, on the global timer (which tests can fake). */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Sent on every request, so the scan is identifiable in ContainerAppHTTPLogs
// and the platform's app-error alert can exclude it rather than fire on it.
export const USER_AGENT =
  "sectest-dast-scanner (OWASP ZAP; +https://github.com/jay-withers/security-testing)";

// Apps on the platform scale to zero, so the first request to one waits for a
// replica to cold-start: longer than ZAP's default read timeout, which made
// every cold app's scan fail with "Read timed out" and no report. warmUp()
// wakes each app before ZAP starts; the longer ZAP timeout is the backstop for
// an app that scales back down mid-scan.
export const WARM_UP_DEADLINE_SECONDS = 180;
export const WARM_UP_REQUEST_TIMEOUT_SECONDS = 60;
export const WARM_UP_RETRY_SECONDS = 10;
// What Envoy returns while no replica is ready yet; anything else (a 401, a
// 404) means the app itself answered, so it is awake.
export const COLD_START_STATUSES = new Set([502, 503, 504]);
// An app is woken one ahead of its scan (warmAhead). A warm-up older than this
// by the time its scan starts is redone: the scan before it ran long (an
// active scan can take an hour), and the app may have scaled back to zero
// since. Well under the ~300s idle period after which Container Apps scales an
// app to zero.
export const WARM_UP_STALE_SECONDS = 120;
export const ZAP_READ_TIMEOUT_SECONDS = 120;
// The packaged scans end by asking ZAP to shut down and exit without waiting
// for the JVM. Until it has gone it holds the lock on ZAP's home directory,
// and the next scan's ZAP refuses to start ("The home directory is already in
// use"), so the wrapper waits 600s for it and fails with no report. After an
// active scan the JVM takes long enough to exit that every other app failed.
// runScan waits this long for the JVM to exit, then kills it.
export const ZAP_SHUTDOWN_GRACE_SECONDS = 120;
export const ZAP_SHUTDOWN_POLL_SECONDS = 1.0;

export const RESOURCE_GRAPH_QUERY = `
resources
| where type =~ 'microsoft.app/containerapps'
| where tobool(properties.configuration.ingress.external) == true
| project id, name, resourceGroup, subscriptionId,
          fqdn = tostring(properties.configuration.ingress.fqdn),
          runningStatus = tostring(properties.runningStatus),
          tags
`;

export const TAG_ENABLED = "security-scan";
export const TAG_OPENAPI = "security-scan-openapi";
export const TAG_MODE = "security-scan-mode";

export const PROFILES = ["passive", "active"] as const;
export type Profile = (typeof PROFILES)[number];

/** Only the *full modes are active. */
export type Mode = "baseline" | "full" | "api" | "api-full";

// ZAP traditional-json riskcode values.
export const RISK_LEVELS = {
  Informational: 0,
  Low: 1,
  Medium: 2,
  High: 3,
} as const;
export type Risk = keyof typeof RISK_LEVELS;
export const RISK_NAMES: Record<number, Risk> = {
  0: "Informational",
  1: "Low",
  2: "Medium",
  3: "High",
};

export function isProfile(value: string): value is Profile {
  return (PROFILES as readonly string[]).includes(value);
}

export function isRisk(value: string): value is Risk {
  return Object.hasOwn(RISK_LEVELS, value);
}

export interface Target {
  readonly id: string;
  readonly name: string;
  readonly resource_group: string;
  readonly subscription_id: string;
  readonly fqdn: string;
  readonly mode: Mode;
  readonly openapi_path: string | null;
}

export function targetUrl(target: Target): string {
  return `https://${target.fqdn}`;
}

export function targetSlug(target: Target): string {
  return `${target.resource_group}-${target.name}`.toLowerCase().replace(/[^a-z0-9-]/g, "-");
}

export type ScanStatus = "completed" | "error" | "timeout";

export interface ScanResult {
  target: Target;
  status: ScanStatus;
  exit_code: number | null;
  risk_counts: Partial<Record<Risk, number>>;
  report_prefix: string | null;
  error: string | null;
}

export function scanResult(
  target: Target,
  status: ScanStatus,
  fields: Partial<Omit<ScanResult, "target" | "status">> = {},
): ScanResult {
  return {
    target,
    status,
    exit_code: null,
    risk_counts: {},
    report_prefix: null,
    error: null,
    ...fields,
  };
}

/** One JSON line per event, so it can be queried in Log Analytics. */
export function log(event: string, fields: Record<string, unknown> = {}): void {
  const source = process.env.LOG_SOURCE ?? "sectest";
  console.log(JSON.stringify({ source, event, ...fields }));
}

/** A Resource Graph row, as the discovery query projects it. */
export interface Row {
  id?: string;
  name?: string;
  resourceGroup?: string;
  subscriptionId?: string;
  fqdn?: string | null;
  runningStatus?: string | null;
  tags?: Record<string, unknown> | null;
}

export interface Skipped {
  id: string | null;
  name: string;
  reason: string;
}

const SCAN_MODES: Record<Profile, { plain: Mode; api: Mode }> = {
  passive: { plain: "baseline", api: "api" },
  active: { plain: "full", api: "api-full" },
};

/**
 * Turn Resource Graph rows into scan targets for a profile, applying the tag
 * filters. Returns the targets, and the skipped rows with why.
 */
export function selectTargets(
  rows: readonly Row[],
  profile: string = "passive",
): { targets: Target[]; skipped: Skipped[] } {
  if (!isProfile(profile)) {
    throw new RangeError(`profile must be one of ${PROFILES.join(", ")}, not '${profile}'`);
  }
  const targets: Target[] = [];
  const skipped: Skipped[] = [];
  for (const row of rows) {
    const tags = new Map(
      Object.entries(row.tags ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)] as const),
    );
    const name = row.name ?? "";
    const fqdn = (row.fqdn ?? "").trim();
    const openapiPath = tags.get(TAG_OPENAPI);

    let reason: string | null = null;
    if ((tags.get(TAG_ENABLED) ?? "").toLowerCase() === "false") {
      reason = "opted out via tag";
    } else if (!fqdn) {
      reason = "no ingress FQDN";
    } else if ((row.runningStatus ?? "").toLowerCase() === "stopped") {
      reason = "app is stopped";
    } else if (openapiPath !== undefined && !openapiPath.startsWith("/")) {
      reason = `${TAG_OPENAPI} must be a path starting with '/'`;
    } else if (profile === "active" && (tags.get(TAG_MODE) ?? "").toLowerCase() === "passive") {
      reason = "opted out of active scans via tag";
    }
    if (reason) {
      skipped.push({ id: row.id ?? null, name, reason });
      continue;
    }

    const modes = SCAN_MODES[profile];
    targets.push({
      id: row.id ?? "",
      name,
      resource_group: row.resourceGroup ?? "",
      subscription_id: row.subscriptionId ?? "",
      fqdn,
      mode: openapiPath ? modes.api : modes.plain,
      openapi_path: openapiPath ?? null,
    });
  }
  return { targets, skipped };
}

/** ZAP packaged-scan command line for a target. Reports land in the work dir. */
export function buildCommand(target: Target, spiderMinutes: number): string[] {
  const slug = targetSlug(target);
  const reports = ["-J", `${slug}.json`, "-r", `${slug}.html`, "-w", `${slug}.md`];
  // -I: don't fail on warnings; severity is judged from the JSON report.
  const zapOptions =
    `-config connection.defaultUserAgent='${USER_AGENT}' ` +
    `-config connection.timeoutInSecs=${ZAP_READ_TIMEOUT_SECONDS}`;
  const common = ["-I", "-z", zapOptions, ...reports];
  const url = targetUrl(target);
  if (target.mode === "api" || target.mode === "api-full") {
    return [
      "zap-api-scan.py",
      "-t",
      `${url}${target.openapi_path ?? ""}`,
      "-f",
      "openapi",
      // -S: safe mode, skipping the active scan. zap-api-scan.py attacks by
      // default, so passive has to be asked for explicitly here.
      ...(target.mode === "api" ? ["-S"] : []),
      ...common,
    ];
  }
  const script = target.mode === "full" ? "zap-full-scan.py" : "zap-baseline.py";
  return [script, "-t", url, "-m", String(spiderMinutes), ...common];
}

/** A ZAP riskcode as an integer, or null for one Python's int() would refuse. */
export function riskcode(value: unknown): number | null {
  if (value === undefined) return 0;
  if (typeof value === "number") return Number.isFinite(value) ? Math.trunc(value) : null;
  if (typeof value === "string" && /^\s*[+-]?\d+\s*$/.test(value)) return Number.parseInt(value, 10);
  return null;
}

interface ZapAlert {
  riskcode?: unknown;
  alertRef?: unknown;
  pluginid?: unknown;
  name?: unknown;
  alert?: unknown;
}

/** A ZAP traditional-json report: sites, each with its alerts. */
export interface ZapReport {
  site?: { alerts?: ZapAlert[] }[];
}

/** Every alert in a report, site by site. */
export function* alertsOf(report: ZapReport): Generator<ZapAlert> {
  for (const site of report.site ?? []) {
    yield* site.alerts ?? [];
  }
}

/** Count alerts by risk level from a ZAP traditional-json report. */
export function countRisks(report: ZapReport): Record<Risk, number> {
  const counts: Record<Risk, number> = {
    Informational: 0,
    Low: 0,
    Medium: 0,
    High: 0,
  };
  for (const alert of alertsOf(report)) {
    const code = riskcode(alert.riskcode);
    if (code === null) continue;
    counts[RISK_NAMES[code] ?? "Informational"] += 1;
  }
  return counts;
}

export function exceedsThreshold(counts: Partial<Record<Risk, number>>, failOn: Risk): boolean {
  const threshold = RISK_LEVELS[failOn];
  return Object.entries(counts).some(
    ([risk, n]) => (n ?? 0) > 0 && isRisk(risk) && RISK_LEVELS[risk] >= threshold,
  );
}

/** HTTP status of a GET, error statuses included rather than thrown. */
export async function fetchStatus(url: string, timeoutSeconds: number): Promise<number> {
  const response = await fetch(url, {
    headers: { "User-Agent": USER_AGENT },
    signal: AbortSignal.timeout(timeoutSeconds * 1000),
  });
  // Only the status matters; the body is released rather than left to the
  // garbage collector, which holds the connection open until it runs.
  await response.body?.cancel();
  return response.status;
}

/** Monotonic seconds, the counterpart of Python's time.monotonic(). */
export function monotonic(): number {
  return performance.now() / 1000;
}

function describe(error: unknown): string {
  if (error instanceof Error) {
    const cause = error.cause instanceof Error ? ` (${error.cause.message})` : "";
    return `${error.name}: ${error.message}${cause}`;
  }
  return String(error);
}

/** A failure fetch() reports for the network, not for its input: a refused or
 * reset connection, DNS, TLS ("fetch failed", with the cause), or a timeout. */
export function isNetworkError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (error.name === "TimeoutError" || error.name === "AbortError") return true;
  return error instanceof TypeError && error.message === "fetch failed";
}

export interface WarmUpOptions {
  fetch?: (url: string, timeoutSeconds: number) => Promise<number>;
  sleep?: (seconds: number) => Promise<void>;
  clock?: () => number;
  deadline?: number;
}

export type WarmUp = [awake: boolean, detail: string];

/**
 * Wake a scale-to-zero app before scanning it.
 *
 * Retries until the app itself answers (any status but a cold-start 5xx) or
 * the deadline passes. Returns [awake, detail]; detail is the last status or
 * error, for the log line.
 */
export async function warmUp(url: string, options: WarmUpOptions = {}): Promise<WarmUp> {
  const {
    fetch = fetchStatus,
    sleep = (seconds: number) => delay(seconds * 1000),
    clock = monotonic,
    deadline = WARM_UP_DEADLINE_SECONDS,
  } = options;
  const giveUpAt = clock() + deadline;
  for (;;) {
    let detail: string;
    try {
      const status = await fetch(url, WARM_UP_REQUEST_TIMEOUT_SECONDS);
      if (!COLD_START_STATUSES.has(status)) return [true, `HTTP ${status}`];
      detail = `HTTP ${status}`;
    } catch (error) {
      // Only what a cold or unreachable app causes is retried, as Python's
      // URLError/TimeoutError/OSError were. Anything else is a bug or a bad
      // URL, and fails the scan now rather than after three minutes.
      if (!isNetworkError(error)) throw error;
      detail = describe(error);
    }
    if (clock() + WARM_UP_RETRY_SECONDS >= giveUpAt) return [false, detail];
    await sleep(WARM_UP_RETRY_SECONDS);
  }
}

/**
 * Yield each target with its warm-up, starting the next one's early.
 *
 * Scans stay one at a time, but each app's cold start (~25s measured) happens
 * while the previous app is being scanned rather than before its own scan.
 * Only one app ahead, not all of them at the start: Container Apps scales an
 * idle app back to zero after about five minutes, so with enough apps the
 * later ones would fall asleep again before their turn. Warm-ups run one at a
 * time, in order, as Python's single-worker pool ran them.
 */
export async function* warmAhead<R>(
  targets: readonly Target[],
  warm: (target: Target) => Promise<R>,
): AsyncGenerator<[Target, Promise<R>]> {
  let closed = false;
  // Never left unhandled: a warm-up that fails after the walk is abandoned
  // would otherwise crash the process with an unhandled rejection.
  const start = (after: Promise<unknown>, target: Target): Promise<R> => {
    const next = after.then(
      () => (closed ? new Promise<R>(() => {}) : warm(target)),
      () => (closed ? new Promise<R>(() => {}) : warm(target)),
    );
    next.catch(() => {});
    return next;
  };
  try {
    const first = targets[0];
    if (first === undefined) return;
    let upcoming = start(Promise.resolve(), first);
    for (const [i, target] of targets.entries()) {
      const current = upcoming;
      const next = targets[i + 1];
      if (next !== undefined) upcoming = start(current, next);
      yield [target, current];
    }
  } finally {
    // The counterpart of cancel_futures: a warm-up not yet started never is.
    closed = true;
  }
}

export type TimedWarmUp = [awake: boolean, detail: string, finishedAt: number];

/** An early warm-up's result, or a new one if it has gone stale. */
export async function freshWarmUp(
  target: Target,
  warmed: TimedWarmUp,
  clock: () => number = monotonic,
  rewarm: (url: string) => Promise<WarmUp> = (url) => warmUp(url),
): Promise<WarmUp> {
  const [awake, detail, finishedAt] = warmed;
  if (clock() - finishedAt > WARM_UP_STALE_SECONDS) return rewarm(targetUrl(target));
  return [awake, detail];
}

export async function timedWarmUp(
  target: Target,
  warm: (url: string) => Promise<WarmUp> = (url) => warmUp(url),
  clock: () => number = monotonic,
): Promise<TimedWarmUp> {
  const [awake, detail] = await warm(targetUrl(target));
  return [awake, detail, clock()];
}

export type Scan = (
  target: Target,
  spiderMinutes: number,
  timeoutSeconds: number,
  warmed?: WarmUp,
) => Promise<ScanResult>;

/** Scan one target with its early warm-up, re-waking it first if stale. */
export async function scanTarget(
  target: Target,
  warming: Promise<TimedWarmUp>,
  spiderMinutes: number,
  timeoutSeconds: number,
  scan: Scan = (t, s, timeout, w) => runScan(t, s, timeout, w),
  fresh: (target: Target, warmed: TimedWarmUp) => Promise<WarmUp> = freshWarmUp,
): Promise<ScanResult> {
  const warmed = await fresh(target, await warming);
  return scan(target, spiderMinutes, timeoutSeconds, warmed);
}

/**
 * Whether any process is left in a process group.
 *
 * Signal 0 tests without sending anything. A zombie still answers it, so this
 * relies on exited members being reaped: Node reaps its own children, and the
 * JVM the wrapper orphans is re-parented to PID 1, which in the image is an
 * init (tini) that reaps it.
 */
export function processGroupAlive(pgid: number): boolean {
  try {
    process.kill(-pgid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw error;
  }
}

/**
 * Wait up to `grace` seconds for a process group to exit, then SIGKILL it.
 * Resolves true if it had to be killed.
 */
export async function stopProcessGroup(
  pgid: number,
  grace: number = ZAP_SHUTDOWN_GRACE_SECONDS,
  poll: number = ZAP_SHUTDOWN_POLL_SECONDS,
): Promise<boolean> {
  const deadline = monotonic() + grace;
  while (processGroupAlive(pgid)) {
    if (monotonic() >= deadline) {
      try {
        process.kill(-pgid, "SIGKILL");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
        throw error;
      }
      const killDeadline = monotonic() + 10;
      while (processGroupAlive(pgid) && monotonic() < killDeadline) await delay(100);
      return true;
    }
    await delay(poll * 1000);
  }
  return false;
}

export type Spawn = (command: string, args: string[], options: { cwd: string }) => ChildProcess;

/**
 * Start a ZAP wrapper in a session of its own, so a timeout can kill the
 * whole process group: the wrapper scripts start a JVM daemon that would
 * otherwise outlive them. No shell; the script names are fixed and the target
 * URL is one this module built.
 */
const spawnZap: Spawn = (command, args, { cwd }) =>
  nodeSpawn(command, args, { cwd, detached: true, stdio: "inherit" });

/** The child's exit code, Python-style: a signal reads as minus its number. */
function exited(child: ChildProcess): Promise<number> {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code !== null) resolve(code);
      else resolve(-(signal ? (constants.signals[signal] ?? 1) : 1));
    });
  });
}

export interface RunScanOptions {
  spawn?: Spawn;
  stop?: (pgid: number, grace?: number) => Promise<boolean>;
  workDir?: string;
  warmUp?: (url: string) => Promise<WarmUp>;
}

export async function runScan(
  target: Target,
  spiderMinutes: number,
  timeoutSeconds: number,
  warmed?: WarmUp,
  options: RunScanOptions = {},
): Promise<ScanResult> {
  const {
    spawn = spawnZap,
    stop = stopProcessGroup,
    workDir = ZAP_WORK_DIR,
    warmUp: warm = (url: string) => warmUp(url),
  } = options;
  const url = targetUrl(target);
  const [awake, detail] = warmed ?? (await warm(url));
  // Scanned either way: ZAP's own, longer timeout may still get through, and
  // a failed scan is reported as an error rather than silently skipped.
  log("warm_up", { target: target.name, url, awake, detail });
  const [command, ...args] = buildCommand(target, spiderMinutes);
  log("scan_started", { target: target.name, url, mode: target.mode });
  const child = spawn(command as string, args, { cwd: workDir });
  const exit = exited(child);
  let timer: NodeJS.Timeout | undefined;
  const timedOut = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => resolve("timeout"), timeoutSeconds * 1000);
  });
  let exitCode: number | "timeout";
  try {
    exitCode = await Promise.race([exit, timedOut]);
  } finally {
    clearTimeout(timer);
  }
  const pgid = child.pid as number;
  if (exitCode === "timeout") {
    await stop(pgid, 0);
    await exit.catch(() => undefined);
    return scanResult(target, "timeout", {
      error: `exceeded ${timeoutSeconds}s`,
    });
  }
  // The wrapper has exited, but ZAP's JVM (same process group) may not have.
  if (await stop(pgid)) {
    log("zap_killed", {
      target: target.name,
      grace_seconds: ZAP_SHUTDOWN_GRACE_SECONDS,
    });
  }

  // ZAP exit codes: 0 pass, 1 FAIL rules hit, 2 WARN only, 3 other failure.
  const reportPath = join(workDir, `${targetSlug(target)}.json`);
  if (exitCode === 3 || !existsSync(reportPath)) {
    return scanResult(target, "error", {
      exit_code: exitCode,
      error: "ZAP did not produce a report",
    });
  }
  const counts = countRisks(JSON.parse(readFileSync(reportPath, "utf8")) as ZapReport);
  return scanResult(target, "completed", {
    exit_code: exitCode,
    risk_counts: counts,
  });
}

/** The part of ResourceGraphClient discovery uses. */
export interface ResourceGraph {
  resources(query: {
    subscriptions: string[];
    query: string;
    options: { skipToken?: string; resultFormat: "objectArray" };
  }): Promise<{ data: unknown; skipToken?: string }>;
}

export async function discoverTargets(client: ResourceGraph, subscriptionIds: string[]): Promise<Row[]> {
  const rows: Row[] = [];
  let skipToken: string | undefined;
  for (;;) {
    const response = await client.resources({
      subscriptions: subscriptionIds,
      query: RESOURCE_GRAPH_QUERY,
      options: { skipToken, resultFormat: "objectArray" },
    });
    // objectArray: a list of row objects, though the SDK types it as any.
    rows.push(...(response.data as Row[]));
    skipToken = response.skipToken;
    if (!skipToken) return rows;
  }
}

/** The part of a blob ContainerClient the scanner and the digest use. */
export interface Container {
  getBlockBlobClient(name: string): {
    uploadData(data: Buffer, options?: { blobHTTPHeaders?: { blobContentType?: string } }): Promise<unknown>;
  };
  getBlobClient(name: string): { downloadToBuffer(): Promise<Buffer> };
  listBlobsFlat(): AsyncIterable<{ name: string }>;
}

export async function upload(
  container: Container,
  name: string,
  data: Buffer,
  contentType: string,
): Promise<void> {
  // uploadData overwrites, as upload_blob(overwrite=True) did.
  await container
    .getBlockBlobClient(name)
    .uploadData(data, { blobHTTPHeaders: { blobContentType: contentType } });
}

const REPORT_TYPES = {
  json: "application/json",
  html: "text/html",
  md: "text/markdown",
};

export async function uploadReports(
  container: Container,
  runPrefix: string,
  result: ScanResult,
  workDir: string = ZAP_WORK_DIR,
): Promise<void> {
  const t = result.target;
  const prefix = `${runPrefix}/${t.subscription_id}/${t.resource_group}/${t.name}`;
  let uploaded = false;
  for (const [ext, contentType] of Object.entries(REPORT_TYPES)) {
    const path = join(workDir, `${targetSlug(t)}.${ext}`);
    if (existsSync(path)) {
      await upload(container, `${prefix}/report.${ext}`, readFileSync(path), contentType);
      uploaded = true;
    }
  }
  // Only set when something is actually there, so a failed scan's log line
  // and summary entry don't point at an empty path.
  if (uploaded) result.report_prefix = prefix;
}

/** `YYYY-MM-DD/HHMMSSZ-<profile>`: the profile is in the path, so a passive and an
 * active run on the same day are told apart at a glance in `make reports`. */
export function runPrefix(started: Date, profile: Profile): string {
  const iso = started.toISOString();
  const time = iso.slice(11, 19).replaceAll(":", "");
  return `${iso.slice(0, 10)}/${time}Z-${profile}`;
}

/** A summary.json result entry, in the Python scanner's shape. */
export function summaryEntry(result: ScanResult): Record<string, unknown> {
  return {
    ...result,
    target: { ...result.target, url: targetUrl(result.target) },
  };
}

export interface Config {
  subscriptionIds: string[];
  containerUrl: string;
  failOn: Risk;
  profile: Profile;
  spiderMinutes: number;
  timeoutSeconds: number;
}

// The longest timer Node keeps: setTimeout clamps a longer delay to 1ms,
// which would time every scan out at once.
const MAX_TIMEOUT_SECONDS = Math.floor((2 ** 31 - 1) / 1000);

function wholeNumber(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: string,
  min: number,
  max: number = Number.MAX_SAFE_INTEGER,
): number {
  const value = env[name] ?? fallback;
  const n = /^\s*\d+\s*$/.test(value) ? Number.parseInt(value, 10) : Number.NaN;
  if (!(n >= min && n <= max)) {
    throw new RangeError(`${name} must be a whole number from ${min} to ${max}, not '${value}'`);
  }
  return n;
}

/** The scan's configuration, or the error that makes it a config_error. */
export function readConfig(env: NodeJS.ProcessEnv = process.env): Config | { error: string } {
  for (const name of ["TARGET_SUBSCRIPTION_IDS", "REPORT_CONTAINER_URL"]) {
    if (!env[name]?.trim()) return { error: `${name} is not set` };
  }
  const failOn = env.SCAN_FAIL_ON ?? "High";
  if (!isRisk(failOn)) {
    return {
      error: `SCAN_FAIL_ON must be one of ${Object.keys(RISK_LEVELS).join(", ")}`,
    };
  }
  const profile = env.SCAN_PROFILE ?? "passive";
  if (!isProfile(profile)) return { error: `SCAN_PROFILE must be one of ${PROFILES.join(", ")}` };
  let spiderMinutes: number, timeoutSeconds: number;
  try {
    // 0 minutes passes ZAP's -m 0 through, as the Python did.
    spiderMinutes = wholeNumber(env, "SCAN_SPIDER_MINUTES", "5", 0);
    timeoutSeconds = wholeNumber(env, "SCAN_TARGET_TIMEOUT", "1800", 1, MAX_TIMEOUT_SECONDS);
  } catch (error) {
    return { error: (error as Error).message };
  }
  return {
    subscriptionIds: (env.TARGET_SUBSCRIPTION_IDS as string)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    containerUrl: env.REPORT_CONTAINER_URL as string,
    failOn,
    profile,
    spiderMinutes,
    timeoutSeconds,
  };
}

/** What a run needs from Azure, so the wiring can be tested without it. */
export interface Services {
  resourceGraph: ResourceGraph;
  container: Container;
  sendDigest: (container: Container, runPrefix: string, sender: string) => Promise<void>;
  scan?: (target: Target, warming: Promise<TimedWarmUp>) => Promise<ScanResult>;
  warm?: (target: Target) => Promise<TimedWarmUp>;
  workDir?: string;
  now?: () => Date;
}

/** One run: discover, scan each target, upload, summarise, digest. Resolves the exit code. */
export async function main(
  config: Config,
  services: Services,
  env: NodeJS.ProcessEnv = process.env,
): Promise<number> {
  const { resourceGraph, container, sendDigest, workDir = ZAP_WORK_DIR, now = () => new Date() } = services;
  const scan =
    services.scan ??
    ((target: Target, warming: Promise<TimedWarmUp>) =>
      scanTarget(target, warming, config.spiderMinutes, config.timeoutSeconds, (t, s, timeout, w) =>
        runScan(t, s, timeout, w, { workDir }),
      ));
  const warm = services.warm ?? ((target: Target) => timedWarmUp(target));
  const { profile, failOn } = config;

  const started = now();
  const prefix = runPrefix(started, profile);

  const { targets, skipped } = selectTargets(
    await discoverTargets(resourceGraph, config.subscriptionIds),
    profile,
  );
  for (const s of skipped) log("target_skipped", { ...s });
  log("discovery_complete", {
    profile,
    targets: targets.length,
    skipped: skipped.length,
  });

  const results: ScanResult[] = [];
  for await (const [target, warming] of warmAhead(targets, warm)) {
    let result: ScanResult;
    try {
      result = await scan(target, warming);
      await uploadReports(container, prefix, result, workDir);
    } catch (error) {
      // One bad target must not stop the run.
      result = scanResult(target, "error", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
    results.push(result);
    log("scan_finished", {
      target: target.name,
      url: targetUrl(target),
      profile,
      mode: target.mode,
      status: result.status,
      risks: result.risk_counts,
      report: result.report_prefix,
      error: result.error,
      over_threshold: exceedsThreshold(result.risk_counts, failOn),
    });
  }

  const failing = results.filter((r) => exceedsThreshold(r.risk_counts, failOn));
  const errored = results.filter((r) => r.status !== "completed");
  const summary = {
    environment: env.ENVIRONMENT ?? null,
    profile,
    started: started.toISOString(),
    finished: now().toISOString(),
    fail_on: failOn,
    results: results.map(summaryEntry),
    skipped,
  };
  await upload(
    container,
    `${prefix}/summary.json`,
    Buffer.from(JSON.stringify(summary, null, 2)),
    "application/json",
  );
  log("run_complete", {
    scanned: results.length,
    failing: failing.length,
    errored: errored.length,
    summary: `${prefix}/summary.json`,
  });

  // After the summary is uploaded, because the digest reads it back. It never
  // throws, so it cannot change the exit code.
  await sendDigest(container, prefix, env.DIGEST_EMAIL_FROM ?? "");

  // Findings alone never fail the run; see the module comment.
  return errored.length ? 1 : 0;
}

/**
 * A scheduled run from the environment: a bad configuration is logged as
 * `config_error` and exits 2, before anything touches Azure; otherwise the
 * run's own exit code. `services` builds the Azure clients for a good one.
 */
export async function runFromEnv(
  services: (config: Config) => Services,
  env: NodeJS.ProcessEnv = process.env,
): Promise<number> {
  const config = readConfig(env);
  if ("error" in config) {
    log("config_error", { error: config.error });
    return 2;
  }
  return main(config, services(config), env);
}
