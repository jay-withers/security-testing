// The digest: no Azure, no Resend. A port of tests/test_digest.py's digest
// cases, case for case; the mailer's are in mailer.test.ts.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { accepted, type Accepted } from "../src/accepted.ts";
import * as digest from "../src/digest.ts";
import type { Summary } from "../src/digest.ts";
import type { MailResult } from "../src/mailer.ts";
import type { ZapReport } from "../src/scan.ts";
import { FakeContainer } from "./helpers.ts";

interface Alert {
  alertRef: string;
  pluginid: string;
  name: string;
  riskcode: string;
}

function alert(ref: string, name: string, riskcode: number): Alert {
  return {
    alertRef: ref,
    pluginid: ref.split("-")[0] as string,
    name,
    riskcode: String(riskcode),
  };
}

function report(...alerts: Alert[]): ZapReport {
  return { site: [{ alerts }] };
}

const CSP = alert("10038", "Content Security Policy (CSP) Header Not Set", 2);
const CLICKJACK = alert("10020-1", "Missing Anti-clickjacking Header", 2);
const HSTS = alert("10035-1", "Strict-Transport-Security Header Not Set", 1);
const INFO = alert("10049-1", "Storable and Cacheable Content", 0);

type Result = NonNullable<Summary["results"]>[number];

function summary(
  results: Result[],
  { started = "2026-10-19T06:00:00+00:00", skipped = [] as { name: string; reason: string }[] } = {},
): Summary {
  return { started, results, skipped };
}

function result(name: string, status = "completed", error: string | null = null): Result {
  return {
    target: { id: `/sub/rg/${name}`, name },
    status,
    report_prefix: status === "completed" ? `run/${name}` : null,
    error,
  };
}

function run(
  prefix: string,
  reports: Record<string, ZapReport>,
  statuses: Record<string, string> = {},
  options: Parameters<typeof summary>[1] = {},
): digest.Run {
  const results = Object.keys(reports).map((n) =>
    result(n, statuses[n] ?? "completed", n in statuses ? "boom" : null),
  );
  const parsed = new Map(
    Object.entries(reports)
      .filter(([n]) => (statuses[n] ?? "completed") === "completed")
      .map(([n, r]) => [`/sub/rg/${n}`, r]),
  );
  return digest.buildRun(prefix, summary(results, options), parsed);
}

let lines: Record<string, unknown>[];

beforeEach(() => {
  lines = [];
  vi.spyOn(console, "log").mockImplementation((line: string) => {
    lines.push(JSON.parse(line));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

const names = (findings: digest.Finding[]) => findings.map((f) => f.name);

describe("findings", () => {
  it("leaves informational alerts out", () => {
    const found = digest.findingsFromReport("/sub/rg/a", "a", report(CSP, HSTS, INFO));
    expect([...found].map((f) => f.risk).sort()).toEqual(["Low", "Medium"]);
  });

  it("counts a rule once however many instances", () => {
    expect(digest.findingsFromReport("a", "a", report(CSP, CSP, CSP)).size).toBe(1);
  });

  it("falls back from alertRef to pluginid to name, and skips unreadable riskcodes", () => {
    const found = digest.findingsFromReport("a", "a", {
      site: [
        {
          alerts: [
            { pluginid: "10096", alert: "Timestamp Disclosure", riskcode: "1" },
            { name: "Only a name", riskcode: 2 },
            { alertRef: "x", riskcode: "bogus" },
          ],
        },
      ],
    });
    expect([...found].map((f) => [f.rule, f.name])).toEqual([
      ["10096", "Timestamp Disclosure"],
      ["Only a name", "Only a name"],
    ]);
  });
});

describe("previousPrefix", () => {
  it("is the latest earlier passive run", () => {
    const blobs = [
      "2026-10-12/060101Z-passive/summary.json",
      "2026-10-14/120000Z-active/summary.json",
      "2026-10-15/093000Z-passive/summary.json",
      "2026-10-15/093000Z-passive/sub/rg/app/report.json",
      "2026-10-19/060101Z-passive/summary.json",
    ];
    expect(digest.previousPrefix(blobs, "2026-10-19/060101Z-passive")).toBe("2026-10-15/093000Z-passive");
    expect(digest.previousPrefix(blobs, "2026-10-12/060101Z-passive")).toBeNull();
  });

  it("compares an active run only with earlier active runs", () => {
    const blobs = ["2026-10-12/060101Z-active/summary.json", "2026-10-14/120000Z-passive/summary.json"];
    expect(digest.previousPrefix(blobs, "2026-10-19/060101Z-active")).toBe("2026-10-12/060101Z-active");
    expect(digest.previousPrefix(blobs, "2026-10-19/060101Z-passive")).toBe("2026-10-14/120000Z-passive");
  });

  it("reads a prefix naming no profile as passive", () => {
    expect(digest.profileOf("2026-10-12/060101Z")).toBe("passive");
  });
});

describe("compare", () => {
  it("finds new and resolved per app and rule", () => {
    const before = run("old", { career: report(CSP, CLICKJACK, HSTS) });
    const now = run("new", {
      career: report(HSTS, alert("10063-1", "Permissions Policy Header Not Set", 1)),
    });

    const d = digest.compare(now, [before]);

    expect(names(d.newFindings)).toEqual(["Permissions Policy Header Not Set"]);
    expect(names(d.resolved)).toEqual([
      "Content Security Policy (CSP) Header Not Set",
      "Missing Anti-clickjacking Header",
    ]);
  });

  it("resolves nothing for a failed scan", () => {
    // An app that errored has not been fixed; its findings must not read as resolved.
    const before = run("old", { career: report(CSP) });
    const now = run("new", { career: report() }, { career: "error" });

    const d = digest.compare(now, [before]);

    expect(d.resolved).toEqual([]);
    expect(d.current.errored).toEqual([["career", "boom"]]);
    expect(digest.subject(d)).toContain("(1 failed)");
  });

  it("calls an app new to the scan a first scan, not new findings", () => {
    const before = run("old", { career: report(CSP) });
    const now = run("new", { career: report(CSP), gymlog: report(CSP, HSTS) });

    const d = digest.compare(now, [before]);

    expect(d.newFindings).toEqual([]);
    expect(d.firstScans).toEqual(["gymlog"]);
  });

  it("reads a risk change as resolved and new", () => {
    const before = run("old", { career: report(CSP) });
    const now = run("new", { career: report({ ...CSP, riskcode: "3" }) });

    const d = digest.compare(now, [before]);

    expect(d.newFindings.map((f) => f.risk)).toEqual(["High"]);
    expect(d.resolved.map((f) => f.risk)).toEqual(["Medium"]);
  });

  it("has nothing to compare the first digest with", () => {
    const d = digest.compare(run("new", { career: report(CSP, HSTS) }), []);

    expect(digest.subject(d)).toBe("Security scan: first digest, 1 Medium, 1 Low open");
    expect(d.firstScans).toEqual(["career"]);
  });

  it("counts open findings across apps in the subject", () => {
    const before = run("old", { a: report(CSP), b: report(CSP) });
    const now = run("new", { a: report(CSP, HSTS), b: report() });

    expect(digest.subject(digest.compare(now, [before]))).toBe(
      "Security scan: 1 new, 1 resolved, 1 Medium, 1 Low open",
    );
  });

  it("says nothing is open when nothing is", () => {
    const d = digest.compare(run("new", { a: report() }), [run("old", { a: report() })]);
    expect(digest.subject(d)).toBe("Security scan: 0 new, 0 resolved, nothing open");
  });

  it("carries a failed scan's last findings into the open counts", () => {
    const before = run("old", { career: report(CSP, HSTS) });
    const now = run("new", { career: report() }, { career: "error" });

    const d = digest.compare(now, [before]);

    expect(d.totalOpen()).toEqual({ High: 0, Medium: 1, Low: 1 });
    expect(digest.renderText(d)).toContain("career: 0 / 1 / 1  [scan failed; last result");
    expect(digest.renderText(d)).toContain("boom (last result carried over)");
  });

  it("still renders when every app failed", () => {
    const d = digest.compare(run("new", { career: report() }, { career: "error" }), []);

    expect(d.totalOpen()).toEqual({ High: 0, Medium: 0, Low: 0 });
    expect(digest.renderText(d)).toContain("boom (no earlier result)");
  });

  it("compares an app that failed last time with its last completed scan", () => {
    // Not a first scan: two runs back it completed, and that is the baseline.
    const r0 = run("r0", { career: report() }, {}, { started: "2026-10-05T06:00:00" });
    const r1 = run("r1", { career: report() }, { career: "timeout" });
    const r2 = run("r2", { career: report({ ...CSP, riskcode: "3" }) });

    const d = digest.compare(r2, [r1, r0]);

    expect(d.newFindings.map((f) => f.risk)).toEqual(["High"]);
    expect(d.firstScans).toEqual([]);
    expect(digest.renderText(d)).toContain("[compared with 2026-10-05]");
  });

  it("names an app gone from the scan, not resolving it", () => {
    const before = run("old", { a: report(CSP), b: report(CSP) });
    const now = run("new", { a: report(CSP) });

    const d = digest.compare(now, [before]);

    expect(d.noLongerScanned).toEqual(["b"]);
    expect(d.resolved).toEqual([]);
    expect(digest.renderText(d)).toContain("No longer scanned (findings dropped, not resolved): b");
  });

  it("does not also call an app skipped by tag no longer scanned", () => {
    const before = run("old", { a: report(CSP), b: report(CSP) });
    const now = run("new", { a: report(CSP) }, {}, { skipped: [{ name: "b", reason: "opted out via tag" }] });

    expect(digest.compare(now, [before]).noLongerScanned).toEqual([]);
  });

  it("says when a completed target has no report", () => {
    const r = digest.buildRun("p", summary([result("career")]), new Map());
    expect(r.errored).toEqual([["career", "report missing"]]);
  });

  it("names an error by its status, or as unknown, when it has no message", () => {
    const r = digest.buildRun(
      "p",
      {
        results: [{ target: {}, status: "timeout" }, { status: "" }],
        skipped: [{}],
      },
      new Map(),
    );
    expect(r.errored).toEqual([
      ["", "timeout"],
      ["", "unknown"],
    ]);
    expect(r.skipped).toEqual([["", ""]]);
    expect(digest.buildRun("p", {}, new Map()).started).toBe("");
  });
});

describe("rendering", () => {
  it("shows deltas against the previous run", () => {
    const before = run("old", { career: report(CSP, CLICKJACK) });
    const now = run("new", { career: report(CSP, HSTS) });

    expect(digest.renderText(digest.compare(now, [before]))).toContain("career: 0 / 1 (-1) / 1 (+1)");
  });

  it("escapes everything from a report in the HTML", () => {
    // Alert names come from ZAP, and app names from tags anyone can set.
    const evil = alert("99999", "<script>alert(1)</script>", 2);
    const d = digest.compare(run("new", { "<b>app</b>": report(evil) }), [
      run("old", { "<b>app</b>": report() }),
    ]);

    const rendered = digest.renderHtml(d);

    expect(rendered).not.toContain("<script>");
    expect(rendered).not.toContain("<b>app</b>");
    expect(rendered).toContain("&lt;script&gt;");
  });

  it("escapes as Python's html.escape does", () => {
    expect(digest.escapeHtml(`<a href="x">'&'</a>`)).toBe(
      "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;&#x27;&lt;/a&gt;",
    );
  });

  it("renders every section, in both forms", () => {
    const before = run("old", { a: report(CSP), b: report(HSTS), c: report() });
    const now = run(
      "new",
      { a: report(CLICKJACK), b: report(), d: report(CSP) },
      { b: "error" },
      { skipped: [{ name: "e", reason: "app is stopped" }] },
    );
    const d = digest.compare(now, [before]);

    const text = digest.renderText(d);
    for (const piece of [
      "Security scan (1 failed): 1 new, 1 resolved",
      "Run new, compared with the run on 2026-10-19.",
      "  a: 0 / 1 / 0",
      "New (1):\n  [Medium] a: Missing Anti-clickjacking Header",
      "Resolved (1):\n  [Medium] a: Content Security Policy (CSP) Header Not Set",
      "First scan, not compared: d",
      "No longer scanned (findings dropped, not resolved): c",
      "Scans that failed (nothing marked resolved):\n  b: boom (last result carried over)",
      "Skipped: e (app is stopped)",
      "Reports: the `reports` container, under new/.",
    ]) {
      expect(text).toContain(piece);
    }
    const html = digest.renderHtml(d);
    for (const piece of [
      "<h3>New (1)</h3>",
      '<span style="color:#b54708;font-weight:600">Medium</span> a: Missing Anti-clickjacking Header',
      "<p>First scan, not compared: d</p>",
      "<p>No longer scanned (findings dropped, not resolved): c</p>",
      "<li>b: boom (last result carried over)</li>",
      "<p>Skipped: e (app is stopped)</p>",
      "(scan failed; last result, 2026-10-19)",
    ]) {
      expect(html).toContain(piece);
    }
    const empty = digest.renderHtml(digest.compare(run("x", { a: report() }), []));
    expect(empty).toContain("(no earlier run to compare with)");
    expect(empty).toContain("<p>None.</p>");
  });

  it("lists every open finding in an active digest", () => {
    const d = digest.compare(
      run("2026-10-15/202812Z-active", {
        career: report(CSP, HSTS),
        gymlog: report(CLICKJACK),
      }),
      [],
    );

    expect(digest.subject(d)).toBe("Active security scan: first digest, 2 Medium, 1 Low open");
    const text = digest.renderText(d);
    expect(text).toContain("Open findings (3):");
    expect(text).toContain("[Medium] career: Content Security Policy (CSP) Header Not Set");
    expect(text).toContain("[Low] career: Strict-Transport-Security Header Not Set");
    expect(digest.renderHtml(d)).toContain("<h3>Open findings (3)</h3>");
    const none = digest.compare(run("2026-10-15/202812Z-active", { career: report() }), []);
    expect(digest.renderText(none)).toContain("Open findings (0):\n  none");
  });

  it("does not list every open finding in a passive digest", () => {
    const d = digest.compare(run("2026-10-19/060000Z-passive", { career: report(CSP) }), []);

    expect(digest.renderText(d)).not.toContain("Open findings");
    expect(digest.renderHtml(d)).not.toContain("Open findings");
  });
});

describe("sendDigest", () => {
  const sent: Record<string, string> = {};
  const mail = async (subject: string, _html: string, text: string, sender: string): Promise<MailResult> => {
    Object.assign(sent, { subject, text, sender });
    return { status: "sent", provider_id: null, error: null };
  };

  it("compares with the previous run and logs", async () => {
    const blobs = new FakeContainer({
      "2026-10-12/060000Z-passive/summary.json": summary([result("career")], {
        started: "2026-10-12T06:00:00",
      }),
      "run/career/report.json": report(CSP),
      "2026-10-19/060000Z-passive/summary.json": summary([result("career")]),
    });

    await digest.sendDigest(blobs, "2026-10-19/060000Z-passive", "Scans <s@example.com>", mail);

    const line = lines.at(-1);
    expect(line).toMatchObject({
      event: "digest",
      status: "sent",
      previous: "2026-10-12/060000Z-passive",
      accepted: 0,
    });
    expect(sent.sender).toBe("Scans <s@example.com>");
  });

  it("never throws", async () => {
    await digest.sendDigest(new FakeContainer(), "2026-10-19/060000Z-passive", "x", mail);

    expect(lines).toHaveLength(1);
    expect(lines[0]?.status).toBe("failed");
    expect(lines[0]?.error).toContain("RestError");
  });

  it("logs a failure that is not an Error as itself", async () => {
    const throwing = new FakeContainer();
    throwing.getBlobClient = () => ({
      downloadToBuffer: () => Promise.reject("broken"),
    });
    await digest.sendDigest(throwing, "p", "x", mail);
    expect(lines[0]).toMatchObject({ status: "failed", error: "broken" });
  });

  it("does not stop at a missing report in an earlier run", async () => {
    const blobs = new FakeContainer({
      "2026-10-12/060000Z-passive/summary.json": summary([result("career")], {
        started: "2026-10-12T06:00:00",
      }),
      // run/career/report.json is missing: lifecycle-expired, or never uploaded.
      "now/career/report.json": report(CSP),
      "2026-10-19/060000Z-passive/summary.json": summary([
        { ...result("career"), report_prefix: "now/career" },
      ]),
    });

    await digest.sendDigest(blobs, "2026-10-19/060000Z-passive", "x", mail);

    expect(lines.at(-1)).toMatchObject({ status: "sent", resolved: 0 });
  });

  it("fails on a report that cannot be read for another reason", async () => {
    const blobs = new FakeContainer({
      "2026-10-19/060000Z-passive/summary.json": summary([result("career")]),
    });
    const real = blobs.getBlobClient.bind(blobs);
    blobs.getBlobClient = (name: string) =>
      name.endsWith("report.json")
        ? {
            downloadToBuffer: () =>
              Promise.reject(Object.assign(new Error("throttled"), { statusCode: 503 })),
          }
        : real(name);

    await digest.sendDigest(blobs, "2026-10-19/060000Z-passive", "x", mail);

    expect(lines.at(-1)).toMatchObject({
      status: "failed",
      error: "Error: throttled",
    });
  });

  it("ignores passive runs for an active run", async () => {
    const blobs = new FakeContainer({
      "2026-10-12/060000Z-passive/summary.json": summary([result("career")], {
        started: "2026-10-12T06:00:00",
      }),
      "run/career/report.json": report(CSP),
      "2026-10-15/202812Z-active/summary.json": summary([result("career")]),
    });

    await digest.sendDigest(blobs, "2026-10-15/202812Z-active", "x", mail);

    expect(lines.at(-1)).toMatchObject({ profile: "active", previous: null });
    expect(sent.subject?.startsWith("Active security scan: first digest")).toBe(true);
    expect(sent.text).toContain("[Medium] career: Content Security Policy (CSP) Header Not Set");
  });

  it("reads back until every app has a baseline, and no further than MAX_LOOKBACK", async () => {
    // a completed only in the oldest of many runs; b never completed at all.
    const json: Record<string, unknown> = {};
    for (let day = 1; day <= 12; day++) {
      const prefix = `2026-10-${String(day).padStart(2, "0")}/060000Z-passive`;
      const a = day === 1 ? result("a") : result("a", "error", "down");
      json[`${prefix}/summary.json`] = summary([a, result("b", "error", "down")], {
        started: `2026-10-${String(day).padStart(2, "0")}T06:00:00`,
      });
    }
    json["run/a/report.json"] = report(CSP);
    const blobs = new FakeContainer(json);

    await digest.sendDigest(blobs, "2026-10-12/060000Z-passive", "x", mail);

    expect(lines.at(-1)).toMatchObject({
      status: "sent",
      runs_read: digest.MAX_LOOKBACK,
    });

    // With every app's baseline found in the previous run, it stops there.
    lines.length = 0;
    const quick = new FakeContainer({
      "2026-10-01/060000Z-passive/summary.json": summary([result("a")]),
      "2026-10-02/060000Z-passive/summary.json": summary([result("a")]),
      "run/a/report.json": report(CSP),
      "2026-10-03/060000Z-passive/summary.json": summary([result("a")]),
    });
    await digest.sendDigest(quick, "2026-10-03/060000Z-passive", "x", mail);
    expect(lines.at(-1)).toMatchObject({
      runs_read: 1,
      previous: "2026-10-02/060000Z-passive",
    });
  });
});

// --- accepted findings -------------------------------------------------------

const STYLE = alert("10055-6", "CSP: style-src unsafe-inline", 2);
const ACCEPT_STYLE: Accepted[] = [{ rule: "10055-6", risk: "Medium", reason: "Deliberate, see health#70" }];

function accepting(prefix: string, reports: Record<string, ZapReport>, entries: Accepted[] = ACCEPT_STYLE) {
  const results = Object.keys(reports).map((n) => result(n));
  const parsed = new Map(Object.entries(reports).map(([n, r]) => [`/sub/rg/${n}`, r]));
  return digest.buildRun(prefix, summary(results), parsed, entries);
}

describe("accepted findings", () => {
  it("are never open, new or resolved", () => {
    const before = accepting("old", { health: report(CSP), career: report() });
    const now = accepting("new", {
      health: report(STYLE),
      career: report(STYLE, HSTS),
    });

    const d = digest.compare(now, [before]);

    expect(new Set(names(d.allOpen()))).toEqual(new Set([HSTS.name]));
    expect(names(d.newFindings)).toEqual([HSTS.name]);
    expect(names(d.resolved)).toEqual([CSP.name]);
  });

  it("do not read as resolved once accepted", () => {
    // Both runs are read through the same list, so last week's copy is set aside too.
    const before = accepting("old", { health: report(STYLE, CSP) });
    const now = accepting("new", { health: report(STYLE, CSP) });

    const d = digest.compare(now, [before]);

    expect(d.newFindings).toEqual([]);
    expect(d.resolved).toEqual([]);
  });

  it("are listed with their reason and apps", () => {
    const d = digest.compare(accepting("new", { health: report(STYLE), career: report(STYLE) }), []);

    const text = digest.renderText(d);
    expect(text).toContain("Accepted, not counted (1):");
    expect(text).toContain("[Medium] CSP: style-src unsafe-inline: career, health");
    expect(text).toContain("Deliberate, see health#70");
    const page = digest.renderHtml(d);
    expect(page).toContain("Accepted, not counted (1)");
    expect(page).toContain("Deliberate, see health#70");
  });

  it("leave no section when nothing is accepted", () => {
    const d = digest.compare(accepting("new", { health: report(CSP) }), []);
    expect(digest.renderText(d)).not.toContain("Accepted");
    expect(digest.renderHtml(d)).not.toContain("Accepted");
  });

  it("leave the other apps open when the entry names one", () => {
    const onlyHealth: Accepted[] = [{ rule: "10055-6", risk: "Medium", reason: "r", app: "ca-health-dev" }];
    const now = accepting(
      "new",
      { "ca-health-dev": report(STYLE), "ca-career-dev": report(STYLE) },
      onlyHealth,
    );

    const openApps = new Set(
      digest
        .compare(now, [])
        .allOpen()
        .map((f) => f.app),
    );

    expect(openApps).toEqual(new Set(["ca-career-dev"]));
  });

  it("include style-src unsafe-inline everywhere in the shipped list", () => {
    expect(accepted("10055-6", "Medium", "ca-observability-dev")).toBeDefined();
    // The anti-CSRF finding is fixed, not accepted.
    expect(accepted("10202", "Medium", "ca-observability-dev")).toBeUndefined();
  });

  it("still report the same rule at another risk", () => {
    const highStyle = alert("10055-6", "CSP: style-src unsafe-inline", 3);
    const d = digest.compare(accepting("new", { health: report(highStyle) }), []);

    expect(d.allOpen().map((f) => [f.risk, f.name])).toEqual([["High", "CSP: style-src unsafe-inline"]]);
    expect(digest.renderText(d)).not.toContain("Accepted");
  });

  it("name only the apps each reason covers", () => {
    const entries: Accepted[] = [
      {
        rule: "10055-6",
        risk: "Medium",
        reason: "health's reason",
        app: "ca-health-dev",
      },
      { rule: "10055-6", risk: "Medium", reason: "everyone else's reason" },
    ];
    const now = accepting("new", { "ca-health-dev": report(STYLE), "ca-career-dev": report(STYLE) }, entries);

    const text = digest.renderText(digest.compare(now, []));

    expect(text).toContain("CSP: style-src unsafe-inline: ca-health-dev\n    health's reason");
    expect(text).toContain("CSP: style-src unsafe-inline: ca-career-dev\n    everyone else's reason");
  });

  it("stay listed for a failed scan", () => {
    const before = accepting("old", { health: report(STYLE, HSTS) });
    const now = digest.buildRun("new", summary([result("health", "error", "boom")]), new Map(), ACCEPT_STYLE);

    const d = digest.compare(now, [before]);

    expect(new Set(names(d.allOpen()))).toEqual(new Set([HSTS.name]));
    expect(digest.renderText(d)).toContain("[Medium] CSP: style-src unsafe-inline: health");
  });

  it("sort by label, then by the apps raising them", () => {
    const entries: Accepted[] = [
      { rule: "10055-6", risk: "Medium", reason: "one", app: "b" },
      { rule: "10055-6", risk: "Medium", reason: "two", app: "a" },
    ];
    const d = digest.compare(accepting("new", { a: report(STYLE), b: report(STYLE) }, entries), []);
    expect(d.acceptedRows().map(([entry]) => entry.reason)).toEqual(["two", "one"]);
  });
});
