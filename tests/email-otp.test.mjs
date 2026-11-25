/** NATH-52: single-app email sign-in is only the Insure identity instances. */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("single-app sign-in is only Insure's identity instances (NATH-52)", () => {
  const vars = file => JSON.parse(readFileSync(file, "utf8").replace(/^\s*\/\/.*$/gm, "")).vars;
  for (const file of [
    "wrangler.auth.jsonc",
    "deploy/production/wrangler.auth.jsonc",
    "deploy/staging/wrangler.auth.jsonc",
    "deploy/classcheck-production/wrangler.auth.jsonc",
    "deploy/classcheck-staging/wrangler.auth.jsonc",
  ]) assert.equal(vars(file).AUTH_MODE, undefined, file);
  for (const file of ["deploy/insure-production/wrangler.auth.jsonc", "deploy/insure-staging/wrangler.auth.jsonc"]) {
    assert.equal(vars(file).AUTH_MODE, "single-app", file);
    assert.equal(vars(file).ENABLE_EMAIL_OTP, "true", file);
  }
  assert.equal(vars("deploy/production/wrangler.auth.jsonc").ENABLE_EMAIL_OTP, "false");
  assert.equal(vars("wrangler.auth.jsonc").ENABLE_EMAIL_OTP, "false");
});
