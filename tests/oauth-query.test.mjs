import test from "node:test";
import assert from "node:assert/strict";
import { signedOAuthQuery } from "../src/auth/oauth-query.mjs";

test("signedOAuthQuery keeps only the signed parameters, sig and the signed-name list", () => {
  const search = "?client_id=a&redirect_uri=https%3A%2F%2Fapp%2Fcb&ba_param=ba_param&ba_param=client_id&ba_param=redirect_uri&sig=S&extra=x";
  const kept = new URLSearchParams(signedOAuthQuery(search));
  assert.deepEqual([...kept.keys()].sort(), ["ba_param", "ba_param", "ba_param", "client_id", "redirect_uri", "sig"]);
  assert.equal(kept.get("extra"), null);
});

test("signedOAuthQuery is undefined without a signature or a signed-name list", () => {
  assert.equal(signedOAuthQuery(""), undefined);
  assert.equal(signedOAuthQuery("?client_id=a&ba_param=client_id"), undefined);
  assert.equal(signedOAuthQuery("?client_id=a&sig=S"), undefined);
});

test("signedOAuthQuery has no free variables, so the sign-in page can inline its source", () => {
  const inlined = new Function("return (" + signedOAuthQuery.toString() + ")")();
  assert.equal(inlined("?a=1&ba_param=a&ba_param=ba_param&sig=S"), signedOAuthQuery("?a=1&ba_param=a&ba_param=ba_param&sig=S"));
});
