/** NATH-11: RFC 7644 PATCH semantics for Users and Groups, with Okta and Microsoft Entra request shapes. */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { applyUserPatch, applyGroupPatch, scimBoolean, ScimError, sameUser, sameGroup } from "../src/auth/scim/patch.mjs";
import { validateScimUser, validateScimGroup, SCIM_PATCH } from "../src/auth/scim/validation.mjs";

const okta = JSON.parse(readFileSync("tests/fixtures/scim/okta.json", "utf8"));
const entra = JSON.parse(readFileSync("tests/fixtures/scim/entra.json", "utf8"));
const USER_ID = "6f9619ff-8b86-4011-b42d-00c04fc964ff";
const GROUP_ID = "7a9619ff-8b86-4011-b42d-00c04fc964aa";
const fill = value => JSON.parse(JSON.stringify(value).replaceAll("USER_ID", USER_ID).replaceAll("GROUP_ID", GROUP_ID));

test("Okta and Entra create payloads validate; Entra string booleans are accepted", () => {
  const alice = validateScimUser(okta.createUser);
  assert.equal(alice.externalId, "00u1a2b3c4D5E6F7g8h9");
  assert.equal(alice.active, true);
  assert.deepEqual(alice.emails, [{ value: "alice@acme.example", type: "work", primary: true }]);
  const entraUser = validateScimUser(entra.createUser);
  assert.equal(entraUser.displayName, "givenName familyName");
  assert.equal(validateScimUser({ ...entra.createUser, active: "False" }).active, false);
  assert.equal(validateScimUser({ ...entra.createUser, active: "true" }).active, true);
  assert.throws(() => validateScimUser({ ...entra.createUser, active: "no" }), /active/);
  assert.equal(validateScimGroup(entra.createGroup).externalId, "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159");
  assert.equal(validateScimGroup(okta.createGroup).externalId, null);
});

test("scimBoolean accepts JSON booleans and Entra's capitalized strings only", () => {
  for (const [input, output] of [[true, true], [false, false], ["True", true], ["False", false], ["false", false], ["TRUE", true]])
    assert.equal(scimBoolean(input), output);
  for (const bad of ["yes", 0, 1, null, "", "Falsey"]) assert.throws(() => scimBoolean(bad), ScimError);
});

test("Okta deactivation is a pathless replace; Entra's is a string 'False' on path active", () => {
  const current = validateScimUser(okta.createUser);
  assert.equal(applyUserPatch(current, okta.deactivateUser).active, false);
  assert.equal(applyUserPatch({ ...current, active: false }, okta.reactivateUser).active, true);
  const entraUser = validateScimUser(entra.createUser);
  assert.equal(applyUserPatch(entraUser, entra.disableUser).active, false);
  assert.equal(applyUserPatch({ ...entraUser, active: false }, entra.enableUser).active, true);
});

test("Entra filtered email paths, dotted pathless keys and enterprise attributes", () => {
  const current = validateScimUser(entra.createUser);
  const updated = applyUserPatch(current, entra.updateUser);
  assert.deepEqual(updated.emails, [{ value: "updated.email@acme.example", type: "work", primary: true }]);
  assert.equal(updated.userName, current.userName, "userName is not changed by an email update");
  const renamed = applyUserPatch(current, entra.pathlessReplace);
  assert.equal(renamed.displayName, "Test User");
  // Attributes Nathan does not store are accepted and ignored, never an error the IdP keeps retrying.
  assert.ok(sameUser(applyUserPatch(current, { schemas: [SCIM_PATCH], Operations: [{ op: "Add", path: "title", value: "x" }] }), current));
});

test("unknown paths, externalId changes, removals of required attributes and bad payloads are rejected", () => {
  const current = validateScimUser(okta.createUser);
  const patch = (...Operations) => ({ schemas: [SCIM_PATCH], Operations });
  const reject = (body, scimType) => assert.throws(() => applyUserPatch(current, body), e => e instanceof ScimError && e.scimType === scimType);
  reject(patch({ op: "replace", path: "isAdmin", value: true }), "invalidPath");
  reject(patch({ op: "replace", path: "externalId", value: "other" }), "mutability");
  reject(patch({ op: "remove", path: "active" }), "invalidValue");
  reject(patch({ op: "remove", path: "userName" }), "invalidValue");
  reject(patch({ op: "move", path: "active", value: true }), "invalidSyntax");
  reject(patch({ op: "replace", path: "userName", value: "not an email" }), "invalidValue");
  reject({ schemas: ["wrong"], Operations: [] }, "invalidSyntax");
  reject({ schemas: [SCIM_PATCH], Operations: new Array(101).fill({ op: "replace", path: "active", value: true }) }, "invalidSyntax");
  assert.equal(applyUserPatch(current, patch({ op: "replace", path: "externalId", value: current.externalId })).externalId, current.externalId,
    "re-sending the same externalId is allowed");
});

test("group PATCH: Okta add/remove-by-filter/pathless rename and Entra add/remove-by-value", () => {
  const other = "11111111-2222-4333-8444-555555555555";
  const base = { displayName: "Engineering", externalId: null, members: [other] };
  const added = applyGroupPatch(base, fill(okta.addMember));
  assert.deepEqual(added.members, [USER_ID, other].sort());
  assert.deepEqual(applyGroupPatch(added, fill(okta.removeMember)).members, [other], "removes only the filtered member");
  assert.equal(applyGroupPatch(base, fill(okta.renameGroup)).displayName, "Okta Engineering Team");
  const entraAdded = applyGroupPatch(base, fill(entra.addMember));
  assert.deepEqual(entraAdded.members, [USER_ID, other].sort());
  assert.deepEqual(applyGroupPatch(entraAdded, fill(entra.removeMember)).members, [other]);
  assert.equal(applyGroupPatch(base, entra.renameGroup).displayName, "Entra Engineering (renamed)");
  // Idempotent: adding an existing member or removing an absent one changes nothing.
  assert.ok(sameGroup(applyGroupPatch(added, fill(okta.addMember)), added));
  assert.ok(sameGroup(applyGroupPatch(base, fill(entra.removeMember)), base));
  // replace members sets the list; remove without value clears it.
  const P = Operations => ({ schemas: [SCIM_PATCH], Operations });
  assert.deepEqual(applyGroupPatch(base, P([{ op: "replace", path: "members", value: [{ value: USER_ID }] }])).members, [USER_ID]);
  assert.deepEqual(applyGroupPatch(base, P([{ op: "remove", path: "members" }])).members, []);
  assert.throws(() => applyGroupPatch(base, P([{ op: "add", path: "members", value: [{ value: "../etc" }] }])), ScimError);
  assert.throws(() => applyGroupPatch({ ...base, externalId: "a" }, P([{ op: "replace", path: "externalId", value: "b" }])),
    e => e.scimType === "mutability");
  assert.equal(applyGroupPatch(base, P([{ op: "add", path: "externalId", value: "ext-1" }])).externalId, "ext-1",
    "a group without an externalId may receive one");
});
