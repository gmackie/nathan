import test from "node:test";
import assert from "node:assert/strict";
import { evaluateAccess, ACCESS_MODES, isPermissionKey, isRoleKey, isGroupId } from "../src/shared/policy.mjs";

const roles = [
  { key: "viewer", permissions: ["invoices:read"] },
  { key: "editor", permissions: ["invoices:read", "invoices:write"] },
  { key: "auditor", permissions: ["audit:read"] }
];
const app = (overrides = {}) => ({ id: "billing", enabled: true, accessMode: "approved", ...overrides });
const user = (overrides = {}) => ({ id: "u1", banned: false, ...overrides });
const grant = (role, principalType, principalId) => ({ role, principalType, principalId });
const base = (overrides = {}) => ({ app: app(), user: user(), groups: [], grants: [], roles, ...overrides });

test("access modes are exactly the two NATH-1 modes", () => {
  assert.deepEqual([...ACCESS_MODES], ["approved", "any_signed_in"]);
});

test("deny by default: an approved-mode app with no grants denies", () => {
  assert.deepEqual(evaluateAccess(base()), { allowed: false, reason: "no_grant", roles: [], permissions: [] });
});

test("a direct user grant allows and expands the role's permissions", () => {
  const result = evaluateAccess(base({ grants: [grant("editor", "user", "u1")] }));
  assert.deepEqual(result, { allowed: true, reason: "granted", roles: ["editor"], permissions: ["invoices:read", "invoices:write"] });
});

test("a group grant applies only to members of that group", () => {
  const grants = [grant("viewer", "group", "finance")];
  assert.equal(evaluateAccess(base({ grants, groups: ["finance"] })).allowed, true);
  assert.deepEqual(evaluateAccess(base({ grants, groups: ["finance"] })).roles, ["viewer"]);
  assert.equal(evaluateAccess(base({ grants, groups: ["engineering"] })).allowed, false);
});

test("grants for other users, other groups or unknown roles are ignored", () => {
  const grants = [grant("editor", "user", "u2"), grant("editor", "group", "other"), grant("ghost", "user", "u1")];
  assert.deepEqual(evaluateAccess(base({ grants, groups: ["finance"] })), { allowed: false, reason: "no_grant", roles: [], permissions: [] });
});

test("a revoked grant (absent from input) no longer allows", () => {
  const granted = base({ grants: [grant("viewer", "user", "u1")] });
  assert.equal(evaluateAccess(granted).allowed, true);
  assert.equal(evaluateAccess({ ...granted, grants: [] }).allowed, false);
});

test("roles and permissions from several grants are merged, unique and sorted", () => {
  const result = evaluateAccess(base({
    groups: ["finance"],
    grants: [grant("viewer", "group", "finance"), grant("editor", "user", "u1"), grant("auditor", "group", "finance"), grant("viewer", "user", "u1")]
  }));
  assert.deepEqual(result.roles, ["auditor", "editor", "viewer"]);
  assert.deepEqual(result.permissions, ["audit:read", "invoices:read", "invoices:write"]);
});

test("any-signed-in mode allows every active user; grants still add roles", () => {
  const open = base({ app: app({ accessMode: "any_signed_in" }) });
  assert.deepEqual(evaluateAccess(open), { allowed: true, reason: "signed_in", roles: [], permissions: [] });
  const withGrant = evaluateAccess({ ...open, grants: [grant("viewer", "user", "u1")] });
  assert.deepEqual(withGrant, { allowed: true, reason: "granted", roles: ["viewer"], permissions: ["invoices:read"] });
});

test("a blocked user is denied in both modes, even with grants", () => {
  for (const accessMode of ACCESS_MODES) {
    const result = evaluateAccess(base({ app: app({ accessMode }), user: user({ banned: true }), grants: [grant("editor", "user", "u1")] }));
    assert.deepEqual(result, { allowed: false, reason: "user_blocked", roles: [], permissions: [] }, accessMode);
  }
});

test("a disabled app is denied in both modes, even with grants", () => {
  for (const accessMode of ACCESS_MODES) {
    const result = evaluateAccess(base({ app: app({ accessMode, enabled: false }), grants: [grant("editor", "user", "u1")] }));
    assert.deepEqual(result, { allowed: false, reason: "app_disabled", roles: [], permissions: [] }, accessMode);
  }
});

test("unknown app and unknown user deny", () => {
  assert.equal(evaluateAccess(base({ app: null })).reason, "unknown_app");
  assert.equal(evaluateAccess(base({ user: null })).reason, "unknown_user");
  assert.equal(evaluateAccess(base({ app: null, user: null })).allowed, false);
});

test("malformed input fails closed", () => {
  const cases = [
    undefined, null, 42, "x", {},
    base({ app: app({ accessMode: "everyone" }) }),
    base({ app: app({ enabled: 1 }) }),
    base({ app: app({ id: "" }) }),
    base({ user: user({ banned: "no" }) }),
    base({ user: user({ id: 7 }) }),
    base({ groups: "finance" }),
    base({ grants: "all" }),
    base({ roles: null }),
    base({ grants: [grant("editor", "robot", "u1")] }),
    base({ grants: [grant("editor", "user", "u1")], roles: [{ key: "editor", permissions: "invoices:write" }] }),
    base({ grants: [grant("editor", "user", "u1")], roles: [{ key: "editor", permissions: ["bad key!"] }] })
  ];
  for (const input of cases) {
    const result = evaluateAccess(input);
    assert.equal(result.allowed, false, JSON.stringify(input));
    assert.deepEqual(result.roles, []);
    assert.deepEqual(result.permissions, []);
  }
});

test("evaluation does not mutate its input", () => {
  const input = base({ grants: [grant("editor", "user", "u1")] });
  const snapshot = structuredClone(input);
  evaluateAccess(input);
  assert.deepEqual(input, snapshot);
});

test("exhaustive: allowed exactly when app enabled, user active, and (signed-in mode or a matching grant)", () => {
  const grantSets = {
    none: [],
    direct: [grant("viewer", "user", "u1")],
    group: [grant("viewer", "group", "finance")],
    otherGroup: [grant("viewer", "group", "other")],
    otherUser: [grant("viewer", "user", "u2")]
  };
  for (const accessMode of ACCESS_MODES)
    for (const enabled of [true, false])
      for (const banned of [true, false])
        for (const [name, grants] of Object.entries(grantSets))
          for (const appKnown of [true, false])
            for (const userKnown of [true, false]) {
              const result = evaluateAccess({
                app: appKnown ? app({ accessMode, enabled }) : null,
                user: userKnown ? user({ banned }) : null,
                groups: ["finance"], grants, roles
              });
              const matching = name === "direct" || name === "group";
              const expected = appKnown && userKnown && enabled && !banned && (accessMode === "any_signed_in" || matching);
              const label = JSON.stringify({ accessMode, enabled, banned, name, appKnown, userKnown });
              assert.equal(result.allowed, expected, label);
              assert.deepEqual(result.roles, expected && matching ? ["viewer"] : [], label);
              assert.deepEqual(result.permissions, expected && matching ? ["invoices:read"] : [], label);
            }
});

test("key validators accept documented formats and reject others", () => {
  for (const key of ["invoices:write", "invoices:read", "reports", "a:b:c", "billing.invoices:export", "x_y-z:w"]) assert.ok(isPermissionKey(key), key);
  for (const key of ["", "Invoices:write", "invoices:", ":write", "invoices write", "invoices:*", "*", "a".repeat(129), 7]) assert.ok(!isPermissionKey(key), String(key));
  for (const key of ["admin", "editor", "invoice_admin", "read-only"]) assert.ok(isRoleKey(key), key);
  for (const key of ["", "Admin", "1admin", "a:b", "a".repeat(64)]) assert.ok(!isRoleKey(key), key);
  for (const id of ["finance", "legacy-role-admin", "eng_platform"]) assert.ok(isGroupId(id), id);
  for (const id of ["", "Finance", "-x", "a b", "a".repeat(81)]) assert.ok(!isGroupId(id), id);
});
