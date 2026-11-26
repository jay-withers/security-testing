// The pure parts of scan.ts and the warm-up logic: no Azure and no ZAP.
// A port of tests/test_scan.py, case for case.

import { describe, expect, it, vi } from "vitest";

import * as scan from "../src/scan.ts";
import type { Row, Target, TimedWarmUp, WarmUp } from "../src/scan.ts";
import { row } from "./helpers.ts";

function only(rows: Row[], profile = "passive"): Target {
  const target = scan.selectTargets(rows, profile).targets[0];
  if (!target) throw new Error("no target selected");
  return target;
}

/** A shell-like split of ZAP's -z value: ZAP splits it itself, quotes and all. */
function shlexSplit(value: string): string[] {
  const parts: string[] = [];
  const re = /'([^']*)'|"([^"]*)"|([^\s'"]+)/g;
  let current = "";
  let last = 0;
  for (const m of value.matchAll(re)) {
    const gap = value.slice(last, m.index);
    if (/\s/.test(gap) && current) {
      parts.push(current);
      current = "";
    }
    current += m[1] ?? m[2] ?? m[3] ?? "";
    last = (m.index ?? 0) + m[0].length;
  }
  if (current) parts.push(current);
  return parts;
}

describe("selectTargets", () => {
  it("defaults to baseline", () => {
    const { targets, skipped } = scan.selectTargets([row()]);
    expect(skipped).toEqual([]);
    expect(targets.map((t) => t.mode)).toEqual(["baseline"]);
    expect(scan.targetUrl(targets[0] as Target)).toBe("https://app.example.azurecontainerapps.io");
  });

  it("reads the opt-out tag case-insensitively", () => {
    const { targets, skipped } = scan.selectTargets([row("app", undefined, { "Security-Scan": "FALSE" })]);
    expect(targets).toEqual([]);
    expect(skipped[0]?.reason).toBe("opted out via tag");
  });

  it("skips apps without an FQDN or that are stopped", () => {
    const { targets, skipped } = scan.selectTargets([
      row("a", ""),
      row("b", undefined, null, { runningStatus: "Stopped" }),
    ]);
    expect(targets).toEqual([]);
    expect(Object.fromEntries(skipped.map((s) => [s.name, s.reason]))).toEqual({
      a: "no ingress FQDN",
      b: "app is stopped",
    });
  });

  it("never attacks in the passive profile", () => {
    const rows = [
      row("plain"),
      row("api", undefined, { "security-scan-openapi": "/openapi.json" }),
      // A leftover opt-in tag from the old model must not make the passive run active.
      row("legacy", undefined, { "security-scan-mode": "full" }),
    ];
    const { targets, skipped } = scan.selectTargets(rows, "passive");
    expect(skipped).toEqual([]);
    expect(Object.fromEntries(targets.map((t) => [t.name, t.mode]))).toEqual({
      plain: "baseline",
      api: "api",
      legacy: "baseline",
    });
    for (const t of targets) {
      const cmd = scan.buildCommand(t, 5);
      expect(cmd[0]).not.toBe("zap-full-scan.py");
      // zap-api-scan.py attacks by default; -S is what keeps it passive.
      expect(cmd[0] !== "zap-api-scan.py" || cmd.includes("-S")).toBe(true);
    }
  });

  it("makes active the default for every app in the active profile", () => {
    const { targets } = scan.selectTargets(
      [row(), row("api", undefined, { "security-scan-openapi": "/o.json" })],
      "active",
    );
    expect(targets.map((t) => t.mode)).toEqual(["full", "api-full"]);
    const [full, api] = targets.map((t) => scan.buildCommand(t, 3));
    expect(full?.slice(0, 5)).toEqual([
      "zap-full-scan.py",
      "-t",
      "https://app.example.azurecontainerapps.io",
      "-m",
      "3",
    ]);
    expect(api?.[0]).toBe("zap-api-scan.py");
    expect(api).toContain("https://app.example.azurecontainerapps.io/o.json");
    expect(api).not.toContain("-S");
  });

  it("lets the passive tag opt out of active only", () => {
    const tagged = row("app", undefined, { "Security-Scan-Mode": "Passive" });
    const active = scan.selectTargets([tagged], "active");
    expect(active.targets).toEqual([]);
    expect(active.skipped[0]?.reason).toBe("opted out of active scans via tag");
    expect(scan.selectTargets([tagged], "passive").targets.map((t) => t.mode)).toEqual(["baseline"]);
  });

  it("applies the opt-out of everything to both profiles", () => {
    for (const profile of scan.PROFILES) {
      const { targets } = scan.selectTargets([row("app", undefined, { "security-scan": "false" })], profile);
      expect(targets).toEqual([]);
    }
  });

  it("rejects an unknown profile", () => {
    expect(() => scan.selectTargets([row()], "aggressive")).toThrow(RangeError);
  });

  it("requires the openapi tag to be a path", () => {
    const { targets, skipped } = scan.selectTargets([
      row("app", undefined, {
        "security-scan-openapi": "https://evil.example/spec",
      }),
    ]);
    expect(targets).toEqual([]);
    expect(skipped[0]?.reason).toContain("must be a path");
  });

  it("fills in what a sparse row leaves out", () => {
    const { targets, skipped } = scan.selectTargets([{ fqdn: " app.example " }, {}]);
    expect(targets[0]).toMatchObject({
      id: "",
      name: "",
      resource_group: "",
      fqdn: "app.example",
    });
    expect(skipped).toEqual([{ id: null, name: "", reason: "no ingress FQDN" }]);
  });
});

describe("buildCommand", () => {
  it("writes all three reports for a baseline scan", () => {
    const cmd = scan.buildCommand(only([row("My_App")]), 5);
    expect(cmd[0]).toBe("zap-baseline.py");
    expect(cmd).toContain("-I");
    for (const [flag, ext] of [
      ["-J", "json"],
      ["-r", "html"],
      ["-w", "md"],
    ] as const) {
      expect(cmd[cmd.indexOf(flag) + 1]).toBe(`rg-my-app.${ext}`);
    }
  });

  it("sends the identifying User-Agent on every scan", () => {
    for (const [profile, tags] of [
      ["passive", {}],
      ["passive", { "security-scan-openapi": "/openapi.json" }],
      ["active", {}],
      ["active", { "security-scan-openapi": "/openapi.json" }],
    ] as const) {
      const cmd = scan.buildCommand(only([row("app", undefined, tags)], profile), 5);
      // ZAP shlex-splits -z itself, so the quoted UA must survive as one value.
      const options = shlexSplit(cmd[cmd.indexOf("-z") + 1] as string);
      expect(options).toContain(`connection.defaultUserAgent=${scan.USER_AGENT}`);
      expect(options).toContain(`connection.timeoutInSecs=${scan.ZAP_READ_TIMEOUT_SECONDS}`);
    }
  });
});

describe("risks", () => {
  it("counts alerts by risk, skipping riskcodes Python's int() would refuse", () => {
    const report = {
      site: [
        { alerts: [{ riskcode: "3" }, { riskcode: "1" }, { riskcode: "1" }] },
        { alerts: [{ riskcode: "0" }, { riskcode: "bogus" }] },
      ],
    };
    expect(scan.countRisks(report)).toEqual({
      Informational: 1,
      Low: 2,
      Medium: 0,
      High: 1,
    });
  });

  it("reads riskcodes the way Python's int() does", () => {
    expect(scan.riskcode(undefined)).toBe(0);
    expect(scan.riskcode(2)).toBe(2);
    expect(scan.riskcode(2.7)).toBe(2);
    expect(scan.riskcode(" 3 ")).toBe(3);
    expect(scan.riskcode(Number.NaN)).toBeNull();
    expect(scan.riskcode("2.5")).toBeNull();
    expect(scan.riskcode(null)).toBeNull();
    expect(scan.countRisks({ site: [{ alerts: [{ riskcode: "7" }] }, {}] })).toMatchObject({
      Informational: 1,
    });
  });

  it("compares counts with the threshold", () => {
    const counts = { Informational: 4, Low: 1, Medium: 0, High: 0 };
    expect(scan.exceedsThreshold(counts, "High")).toBe(false);
    expect(scan.exceedsThreshold(counts, "Medium")).toBe(false);
    expect(scan.exceedsThreshold(counts, "Low")).toBe(true);
    expect(scan.exceedsThreshold({}, "Low")).toBe(false);
  });
});

describe("log", () => {
  it("stamps every line with the source", () => {
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((line: string) => lines.push(line));
    try {
      scan.log("scan_finished", { target: "app", over_threshold: true });
    } finally {
      spy.mockRestore();
    }
    expect(JSON.parse(lines[0] as string)).toEqual({
      source: "sectest",
      event: "scan_finished",
      target: "app",
      over_threshold: true,
    });
  });
});

/** Deterministic time for warmUp: sleep() advances now. */
function fakeClock() {
  const clock = {
    now: 0,
    read: () => clock.now,
    sleep: async (seconds: number) => {
      clock.now += seconds;
    },
  };
  return clock;
}

describe("warmUp", () => {
  it("returns as soon as the app answers", async () => {
    const clock = fakeClock();
    expect(
      await scan.warmUp("https://a", {
        fetch: async () => 200,
        sleep: clock.sleep,
        clock: clock.read,
      }),
    ).toEqual([true, "HTTP 200"]);
    expect(clock.now).toBe(0);
  });

  it("treats any status the app returns as awake", async () => {
    // A 401 is the app answering: it is awake, just protected.
    const clock = fakeClock();
    const [awake] = await scan.warmUp("https://a", {
      fetch: async () => 401,
      sleep: clock.sleep,
      clock: clock.read,
    });
    expect(awake).toBe(true);
  });

  it("retries through a cold start", async () => {
    const clock = fakeClock();
    const responses = [503, 503, 200];
    const result = await scan.warmUp("https://a", {
      fetch: async () => responses.shift() as number,
      sleep: clock.sleep,
      clock: clock.read,
    });
    expect(result).toEqual([true, "HTTP 200"]);
    expect(clock.now).toBe(2 * scan.WARM_UP_RETRY_SECONDS);
  });

  it("gives up at the deadline", async () => {
    const clock = fakeClock();
    const [awake, detail] = await scan.warmUp("https://a", {
      fetch: async () => {
        throw new DOMException("read timed out", "TimeoutError");
      },
      sleep: clock.sleep,
      clock: clock.read,
      deadline: 60,
    });
    expect(awake).toBe(false);
    expect(detail).toContain("TimeoutError");
    expect(clock.now).toBeLessThan(60);
  });

  it("names a network error's cause", async () => {
    const clock = fakeClock();
    const [, detail] = await scan.warmUp("https://a", {
      fetch: async () => {
        throw new TypeError("fetch failed", { cause: new Error("getaddrinfo ENOTFOUND a") });
      },
      sleep: clock.sleep,
      clock: clock.read,
      deadline: 5,
    });
    expect(detail).toBe("TypeError: fetch failed (getaddrinfo ENOTFOUND a)");
  });

  it("retries an aborted request", async () => {
    const clock = fakeClock();
    const [awake, detail] = await scan.warmUp("https://a", {
      fetch: async () => {
        throw new DOMException("aborted", "AbortError");
      },
      sleep: clock.sleep,
      clock: clock.read,
      deadline: 5,
    });
    expect([awake, detail]).toEqual([false, "AbortError: aborted"]);
  });

  it.each([[new TypeError("Invalid URL")], [new RangeError("a bug")], ["not an Error"]])(
    "lets anything but a network failure through at once (%s)",
    async (thrown) => {
      const clock = fakeClock();
      await expect(
        scan.warmUp("https://a", {
          fetch: () => Promise.reject(thrown),
          sleep: clock.sleep,
          clock: clock.read,
        }),
      ).rejects.toBe(thrown);
      expect(clock.now).toBe(0);
    },
  );

  it("waits WARM_UP_RETRY_SECONDS between tries by default", async () => {
    vi.useFakeTimers();
    try {
      const statuses = [503, 200];
      const pending = scan.warmUp("https://a", {
        fetch: async () => statuses.shift() as number,
      });
      await vi.advanceTimersByTimeAsync(scan.WARM_UP_RETRY_SECONDS * 1000);
      expect(await pending).toEqual([true, "HTTP 200"]);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("fetchStatus", () => {
  it("returns error statuses rather than throwing, and sends the User-Agent", async () => {
    const seen: (string | null)[] = [];
    const real = globalThis.fetch;
    globalThis.fetch = (async (_url: string, init: RequestInit) => {
      seen.push(new Headers(init.headers).get("User-Agent"));
      return new Response("Service Unavailable", { status: 503 });
    }) as typeof fetch;
    try {
      expect(await scan.fetchStatus("https://example.test", 1)).toBe(503);
    } finally {
      globalThis.fetch = real;
    }
    expect(seen).toEqual([scan.USER_AGENT]);
  });

  it("copes with a response that has no body", async () => {
    const real = globalThis.fetch;
    globalThis.fetch = (async () => new Response(null, { status: 204 })) as typeof fetch;
    try {
      expect(await scan.fetchStatus("https://example.test", 1)).toBe(204);
    } finally {
      globalThis.fetch = real;
    }
  });
});

/** A promise and the functions that settle it, to hold a warm-up open. */
function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { open, opened };
}

describe("warmAhead", () => {
  const abc = () => scan.selectTargets(["a", "b", "c"].map((n) => row(n, `${n}.example`))).targets;

  it("wakes the next app while the current one scans", async () => {
    const order: string[] = [];
    const started: Record<string, ReturnType<typeof gate>> = {
      a: gate(),
      b: gate(),
      c: gate(),
    };
    const warm = async (target: Target): Promise<WarmUp> => {
      order.push(`warm ${target.name}`);
      started[target.name]?.open();
      return [true, "HTTP 200"];
    };

    for await (const [target, warming] of scan.warmAhead(abc(), warm)) {
      expect(await warming).toEqual([true, "HTTP 200"]);
      const next = ({ a: "b", b: "c" } as Record<string, string>)[target.name];
      // The "scan" of this target only finishes once the next app's warm-up
      // has begun, which it can only do if it was started concurrently.
      if (next) await started[next]?.opened;
      order.push(`scan ${target.name}`);
    }

    expect(order.indexOf("warm b")).toBeLessThan(order.indexOf("scan a"));
    expect(order.indexOf("warm c")).toBeLessThan(order.indexOf("scan b"));
    expect(order.filter((o) => o === "warm a")).toHaveLength(1);
  });

  it("yields nothing with no targets", async () => {
    const walked = [];
    for await (const pair of scan.warmAhead([], async () => [true, ""])) walked.push(pair);
    expect(walked).toEqual([]);
  });

  it("surfaces a warm-up error on that target only", async () => {
    const warm = async (target: Target): Promise<WarmUp> => {
      if (target.name === "a") throw new Error("dns");
      return [true, "HTTP 200"];
    };
    const outcomes: [string, unknown][] = [];
    for await (const [target, warming] of scan.warmAhead(abc().slice(0, 2), warm)) {
      outcomes.push([target.name, await warming.catch((error: Error) => error.message)]);
    }
    expect(outcomes).toEqual([
      ["a", "dns"],
      ["b", [true, "HTTP 200"]],
    ]);
  });

  it("stays only one app ahead", async () => {
    // Waking every app at the start would let later ones scale back to zero.
    const started: string[] = [];
    const release: Record<string, ReturnType<typeof gate>> = {
      a: gate(),
      b: gate(),
      c: gate(),
    };
    const warm = async (target: Target): Promise<WarmUp> => {
      started.push(target.name);
      await release[target.name]?.opened;
      return [true, "HTTP 200"];
    };
    release.a?.open();
    release.b?.open();
    const walk = scan.warmAhead(abc(), warm);

    const first = await walk.next();
    expect(first.value?.[0].name).toBe("a");
    await first.value?.[1];
    // b's warm-up runs and finishes during a's turn; c's must not follow it
    // until b is current. Anything queued early would start here.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(started).toEqual(["a", "b"]);

    const second = await walk.next();
    expect(second.value?.[0].name).toBe("b");
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(started).toEqual(["a", "b", "c"]);
    release.c?.open();
    await walk.return(undefined);
  });

  it("never starts a warm-up after the walk is abandoned", async () => {
    const started: string[] = [];
    const hold = gate();
    const warm = async (target: Target): Promise<WarmUp> => {
      started.push(target.name);
      if (target.name === "a") await hold.opened;
      return [true, "HTTP 200"];
    };
    const walk = scan.warmAhead(abc(), warm);
    await walk.next(); // a is current, b is queued behind a's warm-up
    await walk.return(undefined);
    hold.open();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(started).toEqual(["a"]);
  });

  it("starts the next warm-up even after the previous one failed", async () => {
    const started: string[] = [];
    const warm = async (target: Target): Promise<WarmUp> => {
      started.push(target.name);
      if (target.name === "a") throw new Error("dns");
      return [true, "HTTP 200"];
    };
    for await (const [, warming] of scan.warmAhead(abc(), warm)) await warming.catch(() => null);
    expect(started).toEqual(["a", "b", "c"]);
  });
});

describe("fresh warm-ups", () => {
  it("uses a fresh early warm-up as it is", async () => {
    const result = await scan.freshWarmUp(
      only([row()]),
      [true, "HTTP 200", 100],
      () => 160,
      async () => {
        throw new Error("rewarmed");
      },
    );
    expect(result).toEqual([true, "HTTP 200"]);
  });

  it("wakes the app again when the warm-up has gone stale", async () => {
    // After a long scan before it, the app may have scaled back to zero.
    const target = only([row()]);
    const calls: string[] = [];
    const result = await scan.freshWarmUp(
      target,
      [true, "HTTP 200", 100],
      () => 100 + scan.WARM_UP_STALE_SECONDS + 1,
      async (url) => {
        calls.push(url);
        return [true, "HTTP 401"];
      },
    );
    expect(result).toEqual([true, "HTTP 401"]);
    expect(calls).toEqual([scan.targetUrl(target)]);
  });

  it("stamps when the warm-up finished", async () => {
    let now = 10;
    const result = await scan.timedWarmUp(
      only([row()]),
      async () => {
        now = 40;
        return [true, "HTTP 200"];
      },
      () => now,
    );
    expect(result).toEqual([true, "HTTP 200", 40]);
  });

  it("passes the fresh warm-up to the scan", async () => {
    const target = only([row()]);
    const seen: Record<string, unknown> = {};
    const early: TimedWarmUp = [true, "HTTP 200", 1];
    await scan.scanTarget(
      target,
      Promise.resolve(early),
      5,
      60,
      async (t, _s, _timeout, warmed) => {
        seen.scan = warmed;
        return scan.scanResult(t, "completed");
      },
      async (_t, warmed) => {
        seen.fresh = warmed;
        return [false, "rewoken"];
      },
    );
    expect(seen).toEqual({
      fresh: [true, "HTTP 200", 1],
      scan: [false, "rewoken"],
    });
  });

  it("reads the monotonic clock in seconds", () => {
    const a = scan.monotonic();
    expect(scan.monotonic()).toBeGreaterThanOrEqual(a);
  });
});

describe("readConfig", () => {
  const base = {
    TARGET_SUBSCRIPTION_IDS: " sub-1, ,sub-2 ",
    REPORT_CONTAINER_URL: "https://acct.blob.core.windows.net/reports",
  };

  it("passes a spider cap of 0 and the longest timeout through", () => {
    expect(
      scan.readConfig({ ...base, SCAN_SPIDER_MINUTES: "0", SCAN_TARGET_TIMEOUT: "2147483" }),
    ).toMatchObject({ spiderMinutes: 0, timeoutSeconds: 2147483 });
  });

  it("reads the defaults", () => {
    expect(scan.readConfig(base)).toEqual({
      subscriptionIds: ["sub-1", "sub-2"],
      containerUrl: base.REPORT_CONTAINER_URL,
      failOn: "High",
      profile: "passive",
      spiderMinutes: 5,
      timeoutSeconds: 1800,
    });
  });

  it.each([
    [{ REPORT_CONTAINER_URL: "x" }, "TARGET_SUBSCRIPTION_IDS is not set"],
    [{ ...base, SCAN_FAIL_ON: "Critical" }, "SCAN_FAIL_ON must be one of"],
    [{ ...base, SCAN_PROFILE: "aggressive" }, "SCAN_PROFILE must be one of"],
    [{ ...base, SCAN_SPIDER_MINUTES: "five" }, "SCAN_SPIDER_MINUTES must be a whole number"],
    [{ ...base, SCAN_TARGET_TIMEOUT: "-1" }, "SCAN_TARGET_TIMEOUT must be a whole number"],
    // 0, or more than setTimeout can hold, would time every scan out at once.
    [{ ...base, SCAN_TARGET_TIMEOUT: "0" }, "SCAN_TARGET_TIMEOUT must be a whole number from 1 to 2147483"],
    [{ ...base, SCAN_TARGET_TIMEOUT: "3000000" }, "from 1 to 2147483, not '3000000'"],
  ])("refuses %j", (env, error) => {
    const result = scan.readConfig(env);
    expect("error" in result && result.error).toContain(error);
  });
});

describe("runPrefix", () => {
  it("names the time and the profile", () => {
    expect(scan.runPrefix(new Date("2026-11-05T06:00:07.123Z"), "active")).toBe("2026-11-05/060007Z-active");
  });
});
