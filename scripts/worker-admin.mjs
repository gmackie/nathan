#!/usr/bin/env node
import { parseArgs } from "node:util";
import { adminCommand } from "./lib/admin-wizard.mjs";

try {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    config: { type: "string", default: "nathan.config.json" }, apply: { type: "boolean" }, help: { type: "boolean" }
  } });
  if (values.help || positionals.length === 0) {
    console.log("Usage: nathan-worker-admin init|promote [--config nathan.config.json] [--apply]");
  } else {
    if (positionals.length !== 1 || !["init", "promote"].includes(positionals[0])) throw Error("Expected init or promote");
    await adminCommand(positionals, values.config, values.apply);
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
