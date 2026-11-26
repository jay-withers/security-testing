/**
 * `sectest selfcheck`: prove a scanner job's container could do a real run,
 * and do nothing.
 *
 * After every deploy, `make smoke` (workflows' smoke.sh) starts one run of
 * each scanner job with its args set to `selfcheck`. That run gets everything
 * a real one does (the image, the managed identity, the env and Key Vault
 * access) and checks what a scan needs before it starts: the configuration is
 * valid, the ZAP scripts are on PATH, Resource Graph answers the discovery
 * query, the report container is reachable, and the digest's secrets resolve.
 * It requests nothing from any app, attacks nothing, uploads nothing and sends
 * nothing.
 *
 * Exits 1 if any check fails, naming each failure but never a secret's value.
 * A failure fails the smoke test, which rolls the deploy back.
 */

import { accessSync, constants, statSync } from "node:fs";
import { delimiter, join } from "node:path";

import type { Secret } from "./mailer.ts";
import { discoverTargets, readConfig, type ResourceGraph } from "./scan.ts";

// What buildCommand can invoke.
export const ZAP_SCRIPTS = ["zap-baseline.py", "zap-full-scan.py", "zap-api-scan.py"];

/** The path an executable on PATH resolves to, as shutil.which finds it. */
export function which(name: string, path: string = process.env.PATH ?? ""): string | null {
  for (const dir of path.split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, name);
    try {
      if (!statSync(candidate).isFile()) continue;
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      continue;
    }
  }
  return null;
}

export interface SelfcheckServices {
  resourceGraph: () => ResourceGraph;
  /** Resolves once the report container has answered a properties request. */
  reportContainer: (url: string) => Promise<unknown>;
  secret: Secret;
  which?: (name: string) => string | null;
  env?: NodeJS.ProcessEnv;
}

export type Check = [label: string, check: () => unknown];

export function checks(services: SelfcheckServices): Check[] {
  const { env = process.env, which: find = (name: string) => which(name) } = services;

  const config = () => {
    const result = readConfig(env);
    if ("error" in result) throw new RangeError(result.error);
    return result;
  };

  return [
    ["config", config],
    [
      "zap scripts",
      () => {
        const missing = ZAP_SCRIPTS.filter((s) => find(s) === null);
        if (missing.length) throw new Error(`not on PATH: ${missing.join(", ")}`);
      },
    ],
    [
      "discovery (Resource Graph)",
      () => {
        const subscriptions = (env.TARGET_SUBSCRIPTION_IDS ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        return discoverTargets(services.resourceGraph(), subscriptions);
      },
    ],
    ["report container", () => services.reportContainer(env.REPORT_CONTAINER_URL ?? "")],
    [
      "digest secrets",
      async () => {
        // The same rule as mailer.send: no recipient skips the digest, but a
        // recipient without an API key is a failed send.
        if ((await services.secret("DIGEST-EMAIL-TO")) && !(await services.secret("RESEND-API-KEY"))) {
          throw new Error("DIGEST-EMAIL-TO is set but RESEND-API-KEY is not");
        }
      },
    ],
  ];
}

/** Run every check, logging each outcome. Resolves the exit code. */
export async function run(
  services: SelfcheckServices,
  write: (line: string) => void = console.log,
): Promise<number> {
  let failed = 0;
  for (const [label, check] of checks(services)) {
    try {
      await check();
      write(`INFO selfcheck: ok ${label}`);
    } catch (error) {
      failed += 1;
      const err = error instanceof Error ? error : new Error(String(error));
      write(`ERROR selfcheck: FAIL ${label}: ${err.name}: ${err.message.slice(0, 300)}`);
    }
  }
  if (failed) {
    write(`ERROR selfcheck: ${failed} check(s) failed`);
    return 1;
  }
  write("INFO selfcheck: all checks passed");
  return 0;
}
