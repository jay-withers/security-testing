#!/usr/bin/env node
// The image's ENTRYPOINT: `node src/main.ts [selfcheck]`. Left out of coverage
// with azure.ts, for the same reason.
import { commands } from "./azure.ts";
import { cli } from "./cli.ts";

process.exitCode = await cli(process.argv.slice(2), commands);
