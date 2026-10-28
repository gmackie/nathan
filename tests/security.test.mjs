import test from "node:test";
import assert from "node:assert/strict";
import { safeReturnPath, parseCookie, makeCookie, validateIssuer, constantTimeEqual, isAllowedUnsafeRequest } from "../src/shared/security.mjs";
test("safe redirect paths",()=>{
  for(const p of ["//evil.com","/\\evil.com","https://evil.com","/hello\nSet-Cookie:evil","/hello\\world"])
    assert.equal(safeReturnPath(p),"/");
  assert.equal(safeReturnPath("/docs?q=1"),"/docs?q=1");
});
test("parses exact cookie names",()=>assert.equal(parseCookie("xx=1; __Host-nathan-session=abc123; other=z","__Host-nathan-session"),"abc123"));
test("forbids insecure cookies",()=>{
  assert.match(makeCookie("__Host-nathan-session","abc"),/Secure; HttpOnly; SameSite=Lax/);
  assert.throws(()=>makeCookie("session","abc"));
  assert.throws(()=>makeCookie("__Host-session","evil;path=/"));
});
test("strict issuer validation",()=>{
  assert.equal(validateIssuer("https://auth.example.com/api/auth"),"https://auth.example.com/api/auth");
  assert.throws(()=>validateIssuer("http://auth.example.com"));
  assert.throws(()=>validateIssuer("https://user:pass@auth.example.com"));
});
test("constant time string comparison behavior",()=>{
  assert.equal(constantTimeEqual("abc","abc"),true);
  assert.equal(constantTimeEqual("abc","ab"),false);
  assert.equal(constantTimeEqual("abc","abd"),false);
});

test("CSRF guard denies unsafe cross-origin and originless writes",()=>{
  const same="https://app.example.com";
  assert.equal(isAllowedUnsafeRequest("POST",same,same,"same-origin"),true);
  assert.equal(isAllowedUnsafeRequest("PUT","https://evil.example",same,"cross-site"),false);
  assert.equal(isAllowedUnsafeRequest("POST",null,same,null),false);
  assert.equal(isAllowedUnsafeRequest("DELETE",same,same,"cross-site"),false);
  assert.equal(isAllowedUnsafeRequest("GET",null,same,"cross-site"),true);
});
