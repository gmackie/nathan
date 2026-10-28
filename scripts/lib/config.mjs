import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const ALLOWED_PROFILES = new Set(["standard", "business", "high"]);
const HOST = /^(?=.{1,253}$)(?!-)[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;

export function validateConfig(value) {
  const errors = [];
  if (!value || typeof value !== "object" || Array.isArray(value)) return ["Configuration must be a JSON object"];
  if (typeof value.name !== "string" || !/^[a-z][a-z0-9-]{0,62}$/.test(value.name)) errors.push("name must be a lowercase deployment slug");
  if (typeof value.hostname !== "string" || !HOST.test(value.hostname) || value.hostname.includes("..")) errors.push("hostname must be a valid DNS name");
  if (!ALLOWED_PROFILES.has(value.securityProfile)) errors.push("securityProfile must be standard, business, or high");
  if (value.database?.type !== "d1" || typeof value.database?.name !== "string" || !value.database.name) errors.push("database must specify a D1 name");
  if (!Array.isArray(value.applications)) errors.push("applications must be an array");
  else {
    const ids = new Set();
    for (const app of value.applications) {
      if (!app || typeof app.id !== "string" || !/^[a-z][a-z0-9-]*$/.test(app.id)) { errors.push("Each application needs an id slug"); continue; }
      if (ids.has(app.id)) errors.push("Duplicate application id: " + app.id);
      ids.add(app.id);
      if (!["worker", "external", "gateway"].includes(app.kind)) errors.push(app.id + ": invalid kind");
      if (app.kind === "worker" && !app.workerName) errors.push(app.id + ": workerName required");
      if (app.protection === "gateway" && !app.hostname) errors.push(app.id + ": hostname required for gateway");
    }
  }
  return errors;
}
export async function loadConfig(filename = "nathan.config.json") {
  const path = resolve(filename);
  const value = JSON.parse(await readFile(path, "utf8"));
  const errors = validateConfig(value);
  if (errors.length) throw new Error(errors.join("\n"));
  return value;
}
export function buildPlan(cfg) {
  return [
    { operation: "propose", resource: "worker", name: cfg.name + "-auth" },
    { operation: "propose", resource: "d1", name: cfg.database.name },
    { operation: "propose", resource: "custom-domain", name: cfg.hostname },
    ...cfg.applications.map(a => ({
      operation: "propose", resource: a.kind === "worker" ? "worker-binding" : "oidc-registration", name: a.id
    }))
  ];
}
