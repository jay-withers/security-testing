/**
 * The `sectest` command, which the image's ENTRYPOINT runs.
 *
 * No arguments runs the scan SCAN_PROFILE selects, as every scheduled run
 * does. `sectest selfcheck` is what `make smoke` runs after a deploy instead
 * (selfcheck.ts); anything else is refused rather than read as a scan.
 */

export interface Commands {
  scan: () => Promise<number>;
  selfcheck: () => Promise<number>;
}

export async function cli(
  args: readonly string[],
  commands: Commands,
  stderr: (line: string) => void = console.error,
): Promise<number> {
  if (args.length === 1 && args[0] === "selfcheck") return commands.selfcheck();
  if (args.length) {
    stderr(`usage: sectest [selfcheck] (got '${args.join(" ")}')`);
    return 2;
  }
  return commands.scan();
}
