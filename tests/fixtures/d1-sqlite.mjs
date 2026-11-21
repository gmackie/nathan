/**
 * A minimal D1 binding over node:sqlite for unit tests of code that takes `env.DB`.
 * Every call yields to the event loop first, so concurrent callers interleave at their awaits the
 * way they would against real D1; batch() is one transaction (all or nothing), as in D1.
 */
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";

const plain = row => (row ? { ...row } : null);
const tick = () => new Promise(resolve => setImmediate(resolve));

export function d1(db) {
  const statement = (sql, params = []) => ({
    sql, params,
    bind: (...values) => statement(sql, values),
    first: async () => { await tick(); return plain(db.prepare(sql).get(...params)); },
    all: async () => { await tick(); return { results: db.prepare(sql).all(...params).map(plain), success: true }; },
    run: async () => { await tick(); const r = db.prepare(sql).run(...params); return { success: true, meta: { changes: Number(r.changes) } }; }
  });
  return {
    statements: 0,
    prepare(sql) { return statement(sql); },
    async batch(statements) {
      await tick();
      this.statements += statements.length;
      db.exec("BEGIN");
      try {
        const out = statements.map(s => ({ results: db.prepare(s.sql).all(...s.params).map(plain), success: true }));
        db.exec("COMMIT");
        return out;
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
  };
}

/** A fresh in-memory database with every top-level migration applied. */
export function migratedDatabase() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort())
    db.exec(readFileSync("migrations/" + file, "utf8"));
  return db;
}
