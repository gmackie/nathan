import test from "node:test";
import assert from "node:assert/strict";
import { passkeyRpName, instanceName } from "../src/auth/passkey-config.mjs";

test("passkey relying-party name is instance configuration with a Nathan default", () => {
  assert.equal(passkeyRpName({}), "Nathan");
  assert.equal(passkeyRpName({ NATHAN_PASSKEY_RP_NAME: "  " }), "Nathan");
  assert.equal(passkeyRpName({ NATHAN_PASSKEY_RP_NAME: " gmacko " }), "gmacko");
});

test("passkey relying-party name refuses control characters, markup and overlong values", () => {
  for (const bad of ["gm\nacko", "<b>gmacko</b>", "x".repeat(65)])
    assert.throws(() => passkeyRpName({ NATHAN_PASSKEY_RP_NAME: bad }), /NATHAN_PASSKEY_RP_NAME/);
});

test("the instance name names TOTP, Better Auth and passkeys; a passkey-specific name still overrides", () => {
  assert.equal(instanceName({}), "Nathan");
  assert.equal(instanceName({ NATHAN_INSTANCE_NAME: " gmacko " }), "gmacko");
  assert.equal(passkeyRpName({ NATHAN_INSTANCE_NAME: "gmacko" }), "gmacko");
  assert.equal(passkeyRpName({ NATHAN_INSTANCE_NAME: "gmacko", NATHAN_PASSKEY_RP_NAME: "gmacko keys" }), "gmacko keys");
  assert.throws(() => instanceName({ NATHAN_INSTANCE_NAME: "<b>" }), /NATHAN_INSTANCE_NAME/);
});
