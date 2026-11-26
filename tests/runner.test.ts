// The glue around ZAP: how a run is classified, killed, discovered and stored.
// A port of tests/test_runner.py, plus main(), which the Python left untested.
//
// scan.test.ts covers the pure functions. This covers what decides whether a
// scan *counts*: a ZAP that crashed or hung must come out as `error` or
// `timeout`, never as a clean `completed`, and an app on a second page of
// Resource Graph results must still be scanned. ZAP and Azure are faked at
// the module's seams (spawn, the Resource Graph client, the container), and
// process-group handling runs against real processes.

import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import * as scan from "../src/scan.ts";
import type { ResourceGraph, Spawn, Target } from "../src/scan.ts";
import { FakeContainer, row } from "./helpers.ts";

let workDir: string;
let lines: Record<string, unknown>[];

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), "sectest-"));
  lines = [];
  vi.spyOn(console, "log").mockImplementation((line: string) => {
    lines.push(JSON.parse(line));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

function target(): Target {
  const t = scan.selectTargets([row("app", undefined, null, { resourceGroup: "rg-app" })]).targets[0];
  if (!t) throw new Error("no target");
  return t;
}

/** A fake ZAP wrapper. Set `exitCode`, `report` (written on start), `hangs` or `fails`. */
function fakeZap() {
  const fake = {
    exitCode: 0 as number | null,
    signal: null as NodeJS.Signals | null,
    report: null as unknown,
    hangs: false,
    fails: null as Error | null,
    command: [] as string[],
    cwd: "",
    stopped: [] as [number, number | undefined][],
    child: null as ChildProcess | null,
  };
  const spawnFake: Spawn = (command, args, { cwd }) => {
    fake.command = [command, ...args];
    fake.cwd = cwd;
    if (fake.report !== null) {
      const slug = (args[args.indexOf("-J") + 1] as string).replace(/\.json$/, "");
      writeFileSync(join(cwd, `${slug}.json`), JSON.stringify(fake.report));
    }
    const child = Object.assign(new EventEmitter(), {
      pid: 4242,
    }) as unknown as ChildProcess;
    fake.child = child;
    setImmediate(() => {
      if (fake.fails) child.emit("error", fake.fails);
      else if (!fake.hangs) child.emit("exit", fake.exitCode, fake.signal);
    });
    return child;
  };
  const stop = async (pgid: number, grace?: number) => {
    fake.stopped.push([pgid, grace]);
    // A hung wrapper only exits once its group is killed.
    if (fake.hangs) setImmediate(() => fake.child?.emit("exit", null, "SIGKILL"));
    return false;
  };
  const run = (timeout = 60, warmed: scan.WarmUp = [true, "200"]) =>
    scan.runScan(target(), 1, timeout, warmed, {
      spawn: spawnFake,
      stop,
      workDir,
    });
  return { fake, run };
}

describe("runScan", () => {
  it("completes a scan with a report, with its counts", async () => {
    const { fake, run } = fakeZap();
    fake.exitCode = 2;
    fake.report = {
      site: [{ alerts: [{ riskcode: "2" }, { riskcode: "1" }] }],
    };

    const result = await run();

    expect(result.status).toBe("completed");
    expect(result.exit_code).toBe(2);
    expect(result.risk_counts).toEqual({
      Informational: 0,
      Low: 1,
      Medium: 1,
      High: 0,
    });
    expect(fake.cwd).toBe(workDir);
    // ZAP's JVM is reaped after every scan.
    expect(fake.stopped.map(([pgid]) => pgid)).toEqual([4242]);
  });

  it("calls exit code 3 an error even with a report", async () => {
    // 3 is ZAP's "other failure": a partial report from it is not a clean scan.
    const { fake, run } = fakeZap();
    fake.exitCode = 3;
    fake.report = { site: [] };

    const result = await run();

    expect(result.status).toBe("error");
    expect(result.risk_counts).toEqual({});
  });

  it("calls no report an error, not a pass", async () => {
    // The failure that would read as a clean bill of health if counted as zero alerts.
    const { run } = fakeZap();

    const result = await run();

    expect(result.status).toBe("error");
    expect(result.error).toBe("ZAP did not produce a report");
  });

  it("reads a wrapper killed by a signal as minus the signal's number", async () => {
    const { fake, run } = fakeZap();
    fake.exitCode = null;
    fake.signal = "SIGKILL";

    expect((await run()).exit_code).toBe(-9);
  });

  it("times a hung scan out and kills the group at once", async () => {
    const { fake, run } = fakeZap();
    fake.hangs = true;

    const result = await run(0.05);

    expect(result.status).toBe("timeout");
    expect(result.error).toBe("exceeded 0.05s");
    expect(fake.stopped).toEqual([[4242, 0]]);
  });

  it("still scans a cold app", async () => {
    // warmUp failing is logged, not a skip: ZAP's longer timeout may still get through.
    const { fake, run } = fakeZap();
    fake.report = { site: [] };

    const result = await run(60, [false, "timed out"]);

    expect(result.status).toBe("completed");
    expect(lines.find((l) => l.event === "warm_up")).toMatchObject({
      awake: false,
      detail: "timed out",
    });
  });

  it("warms the app itself when no early warm-up is passed", async () => {
    const { fake } = fakeZap();
    const warmed: string[] = [];
    fake.report = { site: [] };
    const spawnFake: Spawn = () => {
      const child = Object.assign(new EventEmitter(), {
        pid: 1,
      }) as unknown as ChildProcess;
      setImmediate(() => child.emit("exit", 0, null));
      return child;
    };
    writeFileSync(join(workDir, `${scan.targetSlug(target())}.json`), "{}");

    const result = await scan.runScan(target(), 1, 60, undefined, {
      spawn: spawnFake,
      stop: async () => true,
      workDir,
      warmUp: async (url) => {
        warmed.push(url);
        return [true, "HTTP 200"];
      },
    });

    expect(result.status).toBe("completed");
    expect(warmed).toEqual(["https://app.example.azurecontainerapps.io"]);
    // stop said it had to kill ZAP's JVM, and that is logged.
    expect(lines.some((l) => l.event === "zap_killed")).toBe(true);
  });

  it("lets a wrapper that cannot start reject, for main to record as an error", async () => {
    const { fake, run } = fakeZap();
    fake.fails = new Error("spawn zap-baseline.py ENOENT");

    await expect(run()).rejects.toThrow("ENOENT");
  });
});

// --- stopProcessGroup, against real processes --------------------------------

/** A wrapper that exits at once, leaving a child running in its process group,
 * like zap-full-scan.py leaving ZAP's JVM behind. */
async function orphanedGroup(seconds: number): Promise<number> {
  const wrapper = spawn("sh", ["-c", `sleep ${seconds} & exit 0`], {
    detached: true,
    stdio: "ignore",
  });
  await new Promise((resolve) => wrapper.once("exit", resolve));
  return wrapper.pid as number;
}

describe("stopProcessGroup", () => {
  it("waits for a leftover child to exit", async () => {
    const pgid = await orphanedGroup(0.5);
    expect(scan.processGroupAlive(pgid)).toBe(true);

    expect(await scan.stopProcessGroup(pgid, 10, 0.05)).toBe(false);
    expect(scan.processGroupAlive(pgid)).toBe(false);
  });

  it("kills a child that outlives the grace", async () => {
    const pgid = await orphanedGroup(60);
    const started = performance.now();

    expect(await scan.stopProcessGroup(pgid, 0.2, 0.05)).toBe(true);
    expect(performance.now() - started).toBeLessThan(10_000);
    expect(scan.processGroupAlive(pgid)).toBe(false);
  });

  it("returns at once for a group that has already gone", async () => {
    const pgid = await orphanedGroup(0);
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(await scan.stopProcessGroup(pgid, 0)).toBe(false);
  });

  it("rethrows anything but a missing group", () => {
    vi.spyOn(process, "kill").mockImplementation(() => {
      throw Object.assign(new Error("not permitted"), { code: "EPERM" });
    });
    expect(() => scan.processGroupAlive(1)).toThrow("not permitted");
  });

  it("treats a group that goes just before the kill as not killed", async () => {
    let calls = 0;
    vi.spyOn(process, "kill").mockImplementation(() => {
      calls += 1;
      // Alive when checked, gone by the time SIGKILL is sent.
      if (calls > 1) throw Object.assign(new Error("no such process"), { code: "ESRCH" });
      return true;
    });
    expect(await scan.stopProcessGroup(1, 0)).toBe(false);
  });

  it("rethrows a failed kill that is not a missing group", async () => {
    let calls = 0;
    vi.spyOn(process, "kill").mockImplementation(() => {
      calls += 1;
      if (calls > 1) throw Object.assign(new Error("not permitted"), { code: "EPERM" });
      return true;
    });
    await expect(scan.stopProcessGroup(1, 0)).rejects.toThrow("not permitted");
  });
});

// --- discoverTargets ---------------------------------------------------------

describe("discoverTargets", () => {
  it("follows every page", async () => {
    // An app on page two that went unread would simply never be scanned.
    const pages: Record<string, { data: unknown; skipToken?: string }> = {
      "": { data: [{ name: "a" }], skipToken: "page-2" },
      "page-2": { data: [{ name: "b" }], skipToken: "page-3" },
      "page-3": { data: [{ name: "c" }] },
    };
    const requests: Parameters<ResourceGraph["resources"]>[0][] = [];
    const client: ResourceGraph = {
      async resources(request) {
        requests.push(request);
        return pages[request.options.skipToken ?? ""] as { data: unknown };
      },
    };

    const rows = await scan.discoverTargets(client, ["sub-1", "sub-2"]);

    expect(rows.map((r) => r.name)).toEqual(["a", "b", "c"]);
    expect(requests.every((r) => r.subscriptions.join() === "sub-1,sub-2")).toBe(true);
    expect(requests[0]?.query).toBe(scan.RESOURCE_GRAPH_QUERY);
    expect(requests[0]?.options.resultFormat).toBe("objectArray");
  });
});

// --- uploadReports -----------------------------------------------------------

describe("uploadReports", () => {
  it("lands reports under the run, subscription, group and app", async () => {
    const t = target();
    writeFileSync(join(workDir, `${scan.targetSlug(t)}.json`), "{}");
    writeFileSync(join(workDir, `${scan.targetSlug(t)}.html`), "<html/>");
    const result = scan.scanResult(t, "completed");
    const container = new FakeContainer();

    await scan.uploadReports(container, "2026-11-05/060000Z-passive", result, workDir);

    const prefix = "2026-11-05/060000Z-passive/sub/rg-app/app";
    expect(Object.fromEntries([...container.blobs].map(([k, [d, t]]) => [k, [d.toString(), t]]))).toEqual({
      [`${prefix}/report.json`]: ["{}", "application/json"],
      [`${prefix}/report.html`]: ["<html/>", "text/html"],
    });
    expect(result.report_prefix).toBe(prefix);
  });

  it("leaves no prefix to point at when there are no reports", async () => {
    // A failed scan's summary must not link to an empty path.
    const result = scan.scanResult(target(), "error");
    const container = new FakeContainer();

    await scan.uploadReports(container, "2026-11-05/060000Z-passive", result, workDir);

    expect(container.blobs.size).toBe(0);
    expect(result.report_prefix).toBeNull();
  });
});

// --- main --------------------------------------------------------------------

describe("main", () => {
  const config: scan.Config = {
    subscriptionIds: ["sub"],
    containerUrl: "https://acct.blob.core.windows.net/reports",
    failOn: "Medium",
    profile: "passive",
    spiderMinutes: 5,
    timeoutSeconds: 60,
  };
  const graph = (rows: unknown[]): ResourceGraph => ({
    resources: async () => ({ data: rows }),
  });
  const clock = () => {
    let tick = 0;
    return () => new Date(Date.UTC(2026, 10, 5, 6, 0, tick++));
  };

  it("scans each target, uploads the summary, sends the digest and exits 0 on findings", async () => {
    const container = new FakeContainer();
    const digests: [string, string][] = [];

    const code = await scan.main(
      config,
      {
        resourceGraph: graph([row("a"), row("b", ""), row("c")]),
        container,
        sendDigest: async (_c, prefix, sender) => {
          digests.push([prefix, sender]);
        },
        warm: async () => [true, "HTTP 200", 0],
        scan: async (t) =>
          scan.scanResult(t, "completed", {
            risk_counts: { Medium: t.name === "a" ? 1 : 0 },
          }),
        workDir,
        now: clock(),
      },
      { ENVIRONMENT: "dev", DIGEST_EMAIL_FROM: "Scans <s@example.com>" },
    );

    expect(code).toBe(0);
    const prefix = "2026-11-05/060000Z-passive";
    expect(digests).toEqual([[prefix, "Scans <s@example.com>"]]);
    const summary = JSON.parse(container.text(`${prefix}/summary.json`) as string);
    expect(summary).toMatchObject({
      environment: "dev",
      profile: "passive",
      started: "2026-11-05T06:00:00.000Z",
      finished: "2026-11-05T06:00:01.000Z",
      fail_on: "Medium",
      skipped: [{ name: "b", reason: "no ingress FQDN" }],
    });
    // The Python scanner's snake_case shape, which the digest reads back.
    expect(summary.results[0]).toEqual({
      target: {
        id: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/containerApps/a",
        name: "a",
        resource_group: "rg",
        subscription_id: "sub",
        fqdn: "app.example.azurecontainerapps.io",
        mode: "baseline",
        openapi_path: null,
        url: "https://app.example.azurecontainerapps.io",
      },
      status: "completed",
      exit_code: null,
      risk_counts: { Medium: 1 },
      report_prefix: null,
      error: null,
    });
    const finished = lines.filter((l) => l.event === "scan_finished");
    expect(finished.map((l) => [l.target, l.over_threshold])).toEqual([
      ["a", true],
      ["c", false],
    ]);
    expect(lines.find((l) => l.event === "run_complete")).toMatchObject({
      scanned: 2,
      failing: 1,
      errored: 0,
    });
  });

  it("records a target that throws as an error, carries on, and exits 1", async () => {
    const container = new FakeContainer();
    const scanned: string[] = [];

    const code = await scan.main(
      config,
      {
        resourceGraph: graph([row("a"), row("b")]),
        container,
        sendDigest: async () => {},
        warm: async () => [true, "HTTP 200", 0],
        scan: async (t) => {
          scanned.push(t.name);
          if (t.name === "a") throw new Error("spawn ENOENT");
          if (t.name === "b") throw "not an Error";
          return scan.scanResult(t, "completed");
        },
        workDir,
        now: clock(),
      },
      {},
    );

    expect(code).toBe(1);
    expect(scanned).toEqual(["a", "b"]);
    const errors = lines.filter((l) => l.event === "scan_finished").map((l) => l.error);
    expect(errors).toEqual(["spawn ENOENT", "not an Error"]);
    const summary = JSON.parse(container.text("2026-11-05/060000Z-passive/summary.json") as string);
    expect(summary.environment).toBeNull();
  });

  it("runs the real scan path when none is injected", async () => {
    // No targets, so nothing is spawned; what is proven is the default wiring.
    const code = await scan.main(config, {
      resourceGraph: graph([]),
      container: new FakeContainer(),
      sendDigest: async () => {},
    });
    expect(code).toBe(0);
    expect(lines.find((l) => l.event === "discovery_complete")).toMatchObject({
      targets: 0,
    });
  });
});

describe("runFromEnv", () => {
  it("logs a bad configuration and exits 2 before building any client", async () => {
    let built = false;
    const code = await scan.runFromEnv(
      () => {
        built = true;
        throw new Error("built");
      },
      { REPORT_CONTAINER_URL: "x" },
    );
    expect(code).toBe(2);
    expect(built).toBe(false);
    expect(lines).toEqual([
      { source: "sectest", event: "config_error", error: "TARGET_SUBSCRIPTION_IDS is not set" },
    ]);
  });

  it("runs the scan with the clients it builds", async () => {
    const env = { TARGET_SUBSCRIPTION_IDS: "sub", REPORT_CONTAINER_URL: "https://acct/reports" };
    const code = await scan.runFromEnv((config) => {
      expect(config.containerUrl).toBe("https://acct/reports");
      return {
        resourceGraph: { resources: async () => ({ data: [] }) },
        container: new FakeContainer(),
        sendDigest: async () => {},
      };
    }, env);
    expect(code).toBe(0);
  });
});

describe("a whole run against a fake ZAP", () => {
  it("spawns the wrapper in the work dir, reads its report and uploads it", async () => {
    // A stand-in for zap-baseline.py: writes the -J report into its cwd, and
    // leaves a child behind in its process group, as the real one leaves ZAP's JVM.
    const bin = mkdtempSync(join(tmpdir(), "zap-bin-"));
    const script = join(bin, "zap-baseline.py");
    writeFileSync(
      script,
      `#!/bin/sh
while [ "$#" -gt 0 ]; do [ "$1" = "-J" ] && report="$2"; shift; done
printf '{"site":[{"alerts":[{"riskcode":"2"}]}]}' > "$report"
sleep 0.3 &
exit 2
`,
    );
    chmodSync(script, 0o755);
    const realPath = process.env.PATH;
    process.env.PATH = `${bin}:${realPath}`;
    const container = new FakeContainer();
    try {
      const code = await scan.main(
        {
          subscriptionIds: ["sub"],
          containerUrl: "x",
          failOn: "High",
          profile: "passive",
          spiderMinutes: 1,
          timeoutSeconds: 30,
        },
        {
          resourceGraph: { resources: async () => ({ data: [row("app")] }) },
          container,
          sendDigest: async () => {},
          warm: async () => [true, "HTTP 200", scan.monotonic()],
          workDir,
          now: () => new Date(Date.UTC(2026, 10, 5, 6)),
        },
        {},
      );
      expect(code).toBe(0);
    } finally {
      process.env.PATH = realPath;
    }
    const finished = lines.find((l) => l.event === "scan_finished");
    expect(finished).toMatchObject({
      status: "completed",
      risks: { Informational: 0, Low: 0, Medium: 1, High: 0 },
      report: "2026-11-05/060000Z-passive/sub/rg/app",
    });
    expect(container.text("2026-11-05/060000Z-passive/sub/rg/app/report.json")).toContain('"riskcode":"2"');
  });
});
