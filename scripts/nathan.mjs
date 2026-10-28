#!/usr/bin/env node
import { loadConfig, buildPlan } from "./lib/config.mjs";
const command = process.argv[2] ?? "help";
const file = process.argv[3] ?? "nathan.config.json";
if (command === "help" || command === "--help") {
  console.log("Nathan early development planner\nUsage: node scripts/nathan.mjs <plan|doctor> [config.json]\nNo Cloudflare changes are made.");
  process.exit(0);
}
if (!["plan", "doctor"].includes(command)) {
  console.error("Unknown command. This bootstrap supports only plan and doctor.");
  process.exit(2);
}
try {
  const cfg = await loadConfig(file);
  if (command === "doctor") {
    console.log("Configuration valid. Cloudflare integration and auth endpoint checks are NOT implemented.");
  } else {
    console.log(JSON.stringify({ warning: "Proposal only. No resources created.", resources: buildPlan(cfg) }, null, 2));
  }
} catch (error) {
  console.error("Nathan configuration error:\n" + error.message);
  process.exitCode = 1;
}
