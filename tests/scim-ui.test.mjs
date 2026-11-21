/** NATH-11: the Studio SCIM lifecycle section is on the page and its script only uses elements that exist. */
import test from "node:test";
import assert from "node:assert/strict";
import { studioPage } from "../src/auth/ui.ts";
import { SCIM_LIFECYCLE_SCRIPT } from "../src/auth/scim-ui.ts";

test("Studio SCIM lifecycle controls exist and every write sends an exact confirmation", async () => {
  const html = await studioPage("admin@example.com").text();
  const used = [...SCIM_LIFECYCLE_SCRIPT.matchAll(/el\('([a-z0-9-]+)'\)/g)].map(m => m[1]);
  assert.ok(used.length >= 10);
  for (const id of new Set(used)) assert.match(html, new RegExp('id="' + id + '"'), "missing element #" + id);
  assert.match(SCIM_LIFECYCLE_SCRIPT, /confirm:'CONFIRM SCIM SETTINGS '\+id\(\)/);
  assert.match(SCIM_LIFECYCLE_SCRIPT, /confirm:'CONFIRM MAP '\+id\(\)\+'\/'\+ref\+' TO '\+group/);
  assert.match(SCIM_LIFECYCLE_SCRIPT, /confirm:'CONFIRM UNMAP '\+group/);
  assert.doesNotMatch(SCIM_LIFECYCLE_SCRIPT, /innerHTML/, "output is rendered with textContent only");
});

test("Studio SCIM review, override and outbox controls send exact confirmations after a dialog that states the consequence", () => {
  const script = SCIM_LIFECYCLE_SCRIPT;
  assert.match(script, /confirm:'CONFIRM APPROVE '\+r\.action\.toUpperCase\(\)\+' '\+r\.email/);
  assert.match(script, /confirm:'CONFIRM DISMISS '\+r\.action\.toUpperCase\(\)\+' '\+r\.email/);
  assert.match(script, /confirm:'CONFIRM KEEP ACTIVE '\+u\.email/);
  assert.match(script, /confirm:'CONFIRM UNLINK '\+u\.email/);
  assert.match(script, /confirm:'CONFIRM SKIP '\+h\.kind\.toUpperCase\(\)\+' '\+h\.resourceId/);
  // The browser dialog is the human check (as in the rest of Studio), so it must say what happens.
  for (const consequence of [
    /blocks the account, ends every Nathan session, revokes every token and sends back-channel logout/,
    /Sessions and tokens revoked earlier are not restored/,
    /a new deactivation or deletion from the directory blocks the account again/,
    /group memberships \(and the roles they carry\) are removed/,
    /Nathan will NOT apply it\. If it deactivates or deletes a user, that user is NOT blocked/,
    /lose every session and token \(administrators wait for review\)/,
    /lose the roles granted to/
  ]) assert.match(script, consequence);
  // Every confirm() call in the script is followed by an early return when cancelled.
  const dialogs = script.match(/if\(!confirm\(/g) ?? [];
  assert.equal(dialogs.length, 8);
});
