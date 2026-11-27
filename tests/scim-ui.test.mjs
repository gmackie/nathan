/**
 * NATH-11, ported to the Kumo Studio (NATH-39): every SCIM lifecycle write sends an exact
 * confirmation, after a dialog that states the consequence. The confirmations live in
 * src/ui/pages/studio/confirmations.ts; the SCIM panel (src/ui/pages/studio/panels/Scim.tsx) asks
 * each one before its call.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";

await mkdir(".nathan/test-ui", { recursive: true });
const outfile = ".nathan/test-ui/scim-confirmations.mjs";
await build({ entryPoints: ["src/ui/pages/studio/confirmations.ts"], outfile, bundle: true, platform: "node", format: "esm", logLevel: "error" });
const { scim } = await import(pathToFileURL(outfile).href + "?" + Date.now());
const panel = readFileSync("src/ui/pages/studio/panels/Scim.tsx", "utf8");

test("Studio SCIM lifecycle controls exist and every write sends an exact confirmation", () => {
  assert.equal(scim.settings("acme", true, false).phrase, "CONFIRM SCIM SETTINGS acme");
  assert.equal(scim.map("acme", "grp-1", "engineering").phrase, "CONFIRM MAP acme/grp-1 TO engineering");
  assert.equal(scim.unmap("engineering").phrase, "CONFIRM UNMAP engineering");
  assert.match(scim.settings("acme", true, false).question, /Set linking ON and just-in-time creation OFF for acme\?/);
  // The panel has the lifecycle controls and sends each write with the confirmation it asked.
  for (const control of ["Save lifecycle settings", "Map group", "Remove mapping and its memberships", "Approve", "Dismiss", "Keep active", "Unlink",
    "Show outbox head", "Skip the failing head entry", "Show reviews", "Starting at item"]) assert.ok(panel.includes(control), control);
  for (const [path, conf] of [["/scim/settings", "settings"], ["/scim/mappings", "map"], ["/scim/mappings", "unmap"], ["/scim/users", "approve"],
    ["/scim/users", "dismiss"], ["/scim/users", "keepActive"], ["/scim/users", "unlink"], ["/scim/outbox", "skip"]])
    assert.match(panel, new RegExp("apiPost\\(\"" + path.replaceAll("/", "\\/") + "\"[^]*?confirm: confirmations\\.scim\\." + conf + "\\("), path + " asks " + conf);
  assert.doesNotMatch(panel, /innerHTML|dangerouslySetInnerHTML/, "output is rendered as React text only");
});

test("Studio SCIM review, override and outbox controls send exact confirmations after a dialog that states the consequence", () => {
  const link = { id: "r1", action: "link", email: "admin@acme.example", userName: "admin" };
  const deprovision = { id: "r2", action: "deprovision", email: "admin@acme.example", userName: "admin" };
  const user = { scimId: "s1", email: "jane@acme.example", userName: "jane" };
  const head = { kind: "User", resourceId: "u-9", seq: 3, attempts: 4, lastError: "boom", resource: { userName: "jane" } };
  assert.equal(scim.approve(link).phrase, "CONFIRM APPROVE LINK admin@acme.example");
  assert.equal(scim.approve(deprovision).phrase, "CONFIRM APPROVE DEPROVISION admin@acme.example");
  assert.equal(scim.dismiss(link).phrase, "CONFIRM DISMISS LINK admin@acme.example");
  assert.equal(scim.keepActive(user).phrase, "CONFIRM KEEP ACTIVE jane@acme.example");
  assert.equal(scim.unlink(user).phrase, "CONFIRM UNLINK jane@acme.example");
  assert.equal(scim.skip(head).phrase, "CONFIRM SKIP USER u-9");
  // The dialog is the human check (as in the rest of Studio), so it must say what happens.
  const text = [scim.approve(deprovision), scim.approve(link), scim.dismiss(link), scim.dismiss(deprovision), scim.keepActive(user), scim.unlink(user),
    scim.skip(head), scim.settings("acme", true, true), scim.map("acme", "g", "eng"), scim.unmap("eng")].map(c => c.question).join("\n");
  for (const consequence of [
    /blocks the account, ends every Nathan session, revokes every token and sends back-channel logout/,
    /Sessions and tokens revoked earlier are not restored/,
    /a new deactivation or deletion from the directory blocks the account again/,
    /group memberships \(and the roles they carry\) are removed/,
    /Nathan will NOT apply it\. If it deactivates or deletes a user, that user is NOT blocked/,
    /lose every session and token \(administrators wait for review\)/,
    /lose the roles granted to/
  ]) assert.match(text, consequence);
  assert.match(scim.skip(head).question, /Skip the change to User jane \(failed 4 times: boom\)\?/);
  // Every lifecycle write in the panel goes through a confirmation: eight dialogs, as before.
  const asked = panel.match(/confirm: confirmations\.scim\.(settings|map|unmap|approve|dismiss|keepActive|unlink|skip)\(/g) ?? [];
  assert.equal(asked.length, 8);
});
