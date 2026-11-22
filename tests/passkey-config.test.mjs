import test from "node:test";
import assert from "node:assert/strict";
import { passkeyRpName } from "../src/auth/passkey-config.mjs";

test("passkey relying-party name is instance configuration with a Nathan default", () => {
  assert.equal(passkeyRpName({}), "Nathan");
  assert.equal(passkeyRpName({ NATHAN_PASSKEY_RP_NAME: "  " }), "Nathan");
  assert.equal(passkeyRpName({ NATHAN_PASSKEY_RP_NAME: " gmacko " }), "gmacko");
});

test("passkey relying-party name refuses control characters, markup and overlong values", () => {
  for (const bad of ["gm\nacko", "<b>gmacko</b>", "x".repeat(65)])
    assert.throws(() => passkeyRpName({ NATHAN_PASSKEY_RP_NAME: bad }), /NATHAN_PASSKEY_RP_NAME/);
});
