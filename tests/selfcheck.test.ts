// `sectest selfcheck`, which `make smoke` runs in each scanner job after a
// deploy, and the CLI that dispatches to it. A port of tests/test_selfcheck.py.
//
// It has to fail on exactly what would break a scan, and touch nothing: a
// false failure rolls back a good release, and a scan would fire on every
// deploy.

import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { cli } from "../src/cli.ts";
import * as selfcheck from "../src/selfcheck.ts";
import type { SelfcheckServices } from "../src/selfcheck.ts";

function healthy(overrides: Partial<SelfcheckServices> = {}, env: NodeJS.ProcessEnv = {}) {
  const services: SelfcheckServices = {
    resourceGraph: () => ({ resources: async () => ({ data: [] }) }),
    reportContainer: async () => ({}),
    secret: async () => null,
    which: (name) => `/zap/${name}`,
    env: {
      TARGET_SUBSCRIPTION_IDS: "sub-1",
      REPORT_CONTAINER_URL: "https://acct.blob.core.windows.net/reports",
      ...env,
    },
    ...overrides,
  };
  const lines: string[] = [];
  return {
    run: () => selfcheck.run(services, (line) => lines.push(line)),
    lines,
  };
}

describe("selfcheck", () => {
  it("passes when everything a scan needs is there", async () => {
    const { run, lines } = healthy();
    expect(await run()).toBe(0);
    expect(lines.at(-1)).toBe("INFO selfcheck: all checks passed");
  });

  it("fails without a report container", async () => {
    const { run, lines } = healthy({}, { REPORT_CONTAINER_URL: "" });
    expect(await run()).toBe(1);
    expect(lines.join("\n")).toContain("FAIL config");
  });

  it("fails when a ZAP script is missing", async () => {
    const { run, lines } = healthy({
      which: (name) => (name === "zap-full-scan.py" ? null : name),
    });
    expect(await run()).toBe(1);
    expect(lines.join("\n")).toContain("zap-full-scan.py");
  });

  it("fails when a recipient has no API key, without naming the recipient", async () => {
    const { run, lines } = healthy({
      secret: async (name) => (name === "DIGEST-EMAIL-TO" ? "someone@example.com" : null),
    });
    expect(await run()).toBe(1);
    const log = lines.join("\n");
    expect(log).toContain("FAIL digest secrets");
    expect(log).not.toContain("someone@example.com");
  });

  it("fails when discovery or the report container does", async () => {
    const { run, lines } = healthy({
      resourceGraph: () => ({
        resources: () => Promise.reject(new Error("AuthorizationFailed")),
      }),
      reportContainer: () => Promise.reject("unreachable"),
    });
    expect(await run()).toBe(1);
    const log = lines.join("\n");
    expect(log).toContain("FAIL discovery (Resource Graph): Error: AuthorizationFailed");
    expect(log).toContain("FAIL report container: Error: unreachable");
    expect(log).toContain("ERROR selfcheck: 2 check(s) failed");
  });
});

describe("which", () => {
  it("finds an executable file on PATH, and nothing else", () => {
    const dir = mkdtempSync(join(tmpdir(), "which-"));
    const bin = join(dir, "bin");
    mkdirSync(bin);
    mkdirSync(join(bin, "a-directory"));
    writeFileSync(join(bin, "zap-baseline.py"), "#!/bin/sh\n");
    chmodSync(join(bin, "zap-baseline.py"), 0o755);
    writeFileSync(join(bin, "not-executable"), "");
    const path = `${join(dir, "missing")}::${bin}`;

    expect(selfcheck.which("zap-baseline.py", path)).toBe(join(bin, "zap-baseline.py"));
    expect(selfcheck.which("not-executable", path)).toBeNull();
    expect(selfcheck.which("a-directory", path)).toBeNull();
    expect(selfcheck.which("absent", path)).toBeNull();
  });

  it("reads PATH by default", () => {
    expect(selfcheck.which("sh")).not.toBeNull();
  });
});

describe("cli", () => {
  const commands = { scan: async () => 0, selfcheck: async () => 3 };

  it("runs a scan with no arguments and the selfcheck when asked", async () => {
    expect(await cli([], commands)).toBe(0);
    expect(await cli(["selfcheck"], commands)).toBe(3);
  });

  it("refuses anything else", async () => {
    const errors: string[] = [];
    expect(await cli(["bogus"], commands, (line) => errors.push(line))).toBe(2);
    expect(await cli(["selfcheck", "extra"], commands, (line) => errors.push(line))).toBe(2);
    expect(errors[0]).toBe("usage: sectest [selfcheck] (got 'bogus')");
  });
});
