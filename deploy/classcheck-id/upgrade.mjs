import { writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { readStage, receiptId } from "./bootstrap.mjs";
import { CloudflareClient } from "../../scripts/lib/cloudflare.mjs";

export const upgradeId = (spec, operation) => receiptId(spec.stage) + ":" + operation;

export function startUpgrade(spec, operation) {
  // This guard, the change, and its audit commit together. Keep existing operator policy
  // authoritative if the app or resource was removed, disabled or reassigned.
  return {
    sql: "INSERT INTO nathan_security_audit(id,actor,action,target,outcome) SELECT ?,?,?,?, " +
      "CASE WHEN EXISTS(SELECT 1 FROM nathan_security_audit WHERE id=? AND target=? AND outcome='succeeded') " +
      "AND EXISTS(SELECT 1 FROM nathan_applications a JOIN nathan_token_audiences b ON b.app_id=a.id " +
      "JOIN oauthResource r ON r.identifier=b.identifier WHERE a.id='classcheck' AND a.enabled=1 " +
      "AND a.access_mode='approved' AND a.hostname=? AND b.identifier=? AND COALESCE(r.disabled,0)=0) " +
      "THEN 'succeeded' ELSE NULL END",
    params: [upgradeId(spec, operation), "cli:" + spec.worker.account_id, operation, spec.name,
      receiptId(spec.stage), spec.name, new URL(spec.origin).hostname, spec.origin + "/api"]
  };
}

export function runUpgrade(url, operation, changes) {
  if (!process.argv[1] || url !== pathToFileURL(process.argv[1]).href) return;
  async function run([stage, command, destination, ...extra]) {
    if (extra.length || (command !== "--apply" && command !== "--batch-out") ||
        (command === "--batch-out" ? !destination : destination)) throw Error("Expected <stage> --apply or <stage> --batch-out <private-file>");
    const spec = await readStage(stage);
    const receipt = upgradeId(spec, operation);
    const batch = changes(spec);
    if (command === "--batch-out") {
      await writeFile(destination, JSON.stringify({ accountId: spec.worker.account_id, databaseId: spec.db.database_id,
        receipt, batch }), { flag: "wx", mode: 0o600 });
      console.log("Prepared " + operation + " for " + spec.name);
      return;
    }
    const api = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN, spec.worker.account_id);
    const db = await api.databaseNamed(spec.name);
    if (db?.uuid !== spec.db.database_id) throw Error("Dedicated database identity mismatch");
    const check = () => api.queryDatabase(db.uuid,
      "SELECT id FROM nathan_security_audit WHERE id=? AND action=? AND target=? AND outcome='succeeded'", [receipt, operation, spec.name]);
    if (!(await check()).length) {
      await api.batchDatabase(db.uuid, batch);
      if (!(await check()).length) throw Error("Upgrade receipt missing");
    }
    console.log("Verified " + operation + " receipt for " + spec.name);
  }
  run(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
}
