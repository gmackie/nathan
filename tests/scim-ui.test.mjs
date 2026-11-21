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
