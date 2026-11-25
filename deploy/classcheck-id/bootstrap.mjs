/** One-time, account-authorized initialization of each dedicated ClassCheck installation. */
import { readFile, writeFile } from "node:fs/promises";
import { text } from "node:stream/consumers";
import { pathToFileURL } from "node:url";
import { CloudflareClient } from "../../scripts/lib/cloudflare.mjs";
import { stripJsonc } from "../../scripts/lib/wrangler.mjs";
import { standaloneWebStatements } from "../standalone-web-install.mjs";

const rolePermissions = {
  member: ["profile:read"],
  guardian: ["profile:read", "family:read", "family:write"],
  staff: ["profile:read", "school:read", "school:manage", "attendance:write", "transport:manage", "family:read", "family:write"],
  driver: ["profile:read", "school:read", "trips:drive"],
  platform_admin: ["profile:read", "platform:admin", "school:read", "school:manage", "attendance:write", "transport:manage", "family:read", "family:write"]
};

export const receiptId = stage => "install:classcheck:" + stage;

export async function readStage(stage) {
  if (stage !== "staging" && stage !== "production") throw Error("Choose staging or production");
  const config = new URL("../classcheck-" + stage + "/wrangler.auth.jsonc", import.meta.url);
  const worker = JSON.parse(stripJsonc(await readFile(config, "utf8")));
  const origin = stage === "staging" ? "https://beta.classcheck.io" : "https://classcheck.io";
  const name = "nathan-classcheck-" + (stage === "staging" ? "stg" : "prod") + "-auth";
  const db = worker.d1_databases.find(v => v.binding === "DB");
  if (worker.name !== name || db?.database_name !== name || worker.vars.NATHAN_APP_ORIGIN !== origin ||
      worker.vars.NATHAN_APP_ID !== "classcheck") throw Error("Dedicated installation configuration mismatch");
  return { stage, worker, db, origin, name, clientId: "classcheck-web-" + stage };
}

export function installStatements(spec, owner, secret) {
  const guard = {
    sql: "INSERT INTO nathan_security_audit (id,actor,action,target,outcome) SELECT ?,?,'classcheck_install',?, " +
      "CASE WHEN NOT EXISTS (SELECT 1 FROM user) AND NOT EXISTS (SELECT 1 FROM nathan_applications) " +
      "AND NOT EXISTS (SELECT 1 FROM oauthClient) THEN 'succeeded' ELSE NULL END",
    params: [receiptId(spec.stage), "cli:" + spec.worker.account_id, spec.name],
  };
  return [guard, ...standaloneWebStatements(spec, owner, secret, {
    displayName: "ClassCheck", rolePermissions, scopes: ["openid", "email", "profile", "offline_access"],
    grantTypes: ["authorization_code", "refresh_token"],
  })];
}

async function main([stage, command, destination, ...extra]) {
  if (extra.length || (command !== "--apply" && command !== "--batch-out") ||
      (command === "--batch-out" ? !destination : destination)) throw Error("Expected <stage> --apply or <stage> --batch-out <private-file>");
  const spec = await readStage(stage);
  const secret = (await text(process.stdin)).trimEnd();
  const ops = installStatements(spec, process.env.NATHAN_ADMIN_EMAILS, secret);
  if (command === "--batch-out") {
    await writeFile(destination, JSON.stringify({ accountId: spec.worker.account_id, databaseId: spec.db.database_id,
      receipt: receiptId(stage), batch: ops }), { flag: "wx", mode: 0o600 });
    console.log("Prepared the install batch for " + spec.name);
    return;
  }
  const api = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN, spec.worker.account_id);
  const db = await api.databaseNamed(spec.name);
  if (db?.uuid !== spec.db.database_id) throw Error("Dedicated database identity mismatch");
  const readReceipt = () => api.queryDatabase(db.uuid,
    "SELECT id FROM nathan_security_audit WHERE id=? AND action='classcheck_install' AND target=? AND outcome='succeeded'", [receiptId(stage), spec.name]);
  if (!(await readReceipt()).length) {
    await api.batchDatabase(db.uuid, ops);
    if (!(await readReceipt()).length) throw Error("Install receipt missing");
  }
  console.log("Verified install receipt for " + spec.name + " and client " + spec.clientId);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main(process.argv.slice(2)).catch(e => { console.error(e.message); process.exitCode = 1; });
