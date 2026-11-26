// Golden parity with the Python digest. tests/fixtures/digest-golden.json is
// what src/sectest/digest.py rendered for the runs in digest-scenarios.json,
// byte for byte, so the email a reader gets does not change with the port.
// While the Python is still here, regenerate it after a deliberate change to
// the digest's output with the script in tests/fixtures/README.md.

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import * as digest from "../src/digest.ts";
import type { Summary } from "../src/digest.ts";
import type { ZapReport } from "../src/scan.ts";

interface StoredRun {
  prefix: string;
  summary: Summary;
  reports: Record<string, ZapReport>;
}

interface Scenario {
  name: string;
  current: StoredRun;
  earlier: StoredRun[];
}

const read = (name: string) => JSON.parse(readFileSync(new URL(`fixtures/${name}`, import.meta.url), "utf8"));
const scenarios: Scenario[] = read("digest-scenarios.json");
const golden: Record<string, { subject: string; text: string; html: string; open: unknown }> =
  read("digest-golden.json");

const build = (r: StoredRun) => digest.buildRun(r.prefix, r.summary, new Map(Object.entries(r.reports)));

describe("parity with the Python digest", () => {
  it.each(scenarios.map((s) => [s.name, s] as const))("renders %s exactly as it did", (name, s) => {
    const d = digest.compare(build(s.current), s.earlier.map(build));
    expect({
      subject: digest.subject(d),
      text: digest.renderText(d),
      html: digest.renderHtml(d),
      open: d.totalOpen(),
    }).toEqual(golden[name]);
  });
});
