// Golden parity with the Python digest. tests/fixtures/digest-golden.json is
// what the Python scanner's digest.py rendered for the runs in
// digest-scenarios.json, byte for byte, so the email a reader gets did not
// change with the port, and does not drift by accident since.
//
// After a deliberate change to the digest's output, rewrite it from this
// digest with `UPDATE_GOLDEN=1 npm test -- tests/parity.test.ts`, and review
// the diff in tests/fixtures/digest-golden.json as part of the change.

import { readFileSync, writeFileSync } from "node:fs";

import { afterAll, describe, expect, it } from "vitest";

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

const fixture = (name: string) => new URL(`fixtures/${name}`, import.meta.url);
const read = (name: string) => JSON.parse(readFileSync(fixture(name), "utf8"));
const scenarios: Scenario[] = read("digest-scenarios.json");
const golden: Record<string, { subject: string; text: string; html: string; open: unknown }> =
  read("digest-golden.json");

const build = (r: StoredRun) => digest.buildRun(r.prefix, r.summary, new Map(Object.entries(r.reports)));

const rendered: Record<string, unknown> = {};

// Sorted keys, as the Python wrote it, so a rewrite only shows real changes.
const sortKeys = (value: unknown): unknown =>
  value && typeof value === "object" && !Array.isArray(value)
    ? Object.fromEntries(
        Object.keys(value)
          .sort()
          .map((k) => [k, sortKeys((value as Record<string, unknown>)[k])]),
      )
    : value;

const updating = process.env.UPDATE_GOLDEN === "1";

afterAll(() => {
  if (updating) {
    // Every scenario or nothing: a filtered run (-t) or a scenario that threw
    // would otherwise drop the rest from the golden file without a word.
    const missing = scenarios.map((s) => s.name).filter((name) => !(name in rendered));
    if (missing.length)
      throw new Error(`not rewriting digest-golden.json: ${missing.join(", ")} did not render`);
    writeFileSync(fixture("digest-golden.json"), JSON.stringify(sortKeys(rendered), null, 2) + "\n");
  }
});

describe("parity with the Python digest", () => {
  it.each(scenarios.map((s) => [s.name, s] as const))("renders %s exactly as it did", (name, s) => {
    const d = digest.compare(build(s.current), s.earlier.map(build));
    const out = {
      subject: digest.subject(d),
      text: digest.renderText(d),
      html: digest.renderHtml(d),
      open: d.totalOpen(),
    };
    rendered[name] = out;
    if (!updating) expect(out).toEqual(golden[name]);
  });
});
