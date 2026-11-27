import { randomBytes } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { installStatements } from "../../deploy/classcheck-id/bootstrap.mjs";

export function applyBatch(db, statements) {
  db.exec("BEGIN");
  try {
    for (const { sql, params } of statements) db.prepare(sql).run(...params);
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

export function freshInstallation(spec) {
  const db = new DatabaseSync(":memory:");
  const migrations = new URL("../../migrations/", import.meta.url);
  for (const name of readdirSync(migrations).filter(f => f.endsWith(".sql")).sort())
    db.exec(readFileSync(new URL(name, migrations), "utf8"));
  applyBatch(db, installStatements(spec, "operator@example.test", randomBytes(40).toString("base64url")));
  return db;
}
