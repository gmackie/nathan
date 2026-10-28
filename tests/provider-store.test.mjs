import test from "node:test";
import assert from "node:assert/strict";
import {generateConfigKey,encryptProviderSecret,decryptProviderSecret,validateOAuthProviderInput} from "../src/auth/config-crypto.mjs";
import {DatabaseSync} from "node:sqlite";
import {readFileSync} from "node:fs";

test("provider secrets are AES-GCM ciphertext with authenticated provider identity",async()=>{
  const master=generateConfigKey(),plaintext="client-secret-of-provider-12345";
  const a=await encryptProviderSecret("google",plaintext,master);
  const b=await encryptProviderSecret("google",plaintext,master);
  assert.notEqual(a,b);
  assert.ok(!a.includes(plaintext));
  assert.equal(await decryptProviderSecret("google",a,master),plaintext);
  await assert.rejects(()=>decryptProviderSecret("github",a,master));
  await assert.rejects(()=>decryptProviderSecret("google",a,generateConfigKey()));
});
test("credentials must never accept unsupported provider or tiny secrets",()=>{
  for(const id of ["evil","oauth","google;DELETE",""]){
    assert.throws(()=>validateOAuthProviderInput({id,clientId:"123456",clientSecret:"123456789"}));
  }
  assert.throws(()=>validateOAuthProviderInput({id:"google",clientId:"",clientSecret:"123456789"}));
  assert.throws(()=>validateOAuthProviderInput({id:"google",clientId:"123456",clientSecret:"abc"}));
});
test("control-plane schema stores encrypted secrets but not cleartext oauth tokens",()=>{
  const db=new DatabaseSync(":memory:");
  db.exec(readFileSync("migrations/0006_control_plane.sql","utf8"));
  const cols=db.prepare("PRAGMA table_info(nathan_oauth_providers)").all().map(x=>x.name);
  assert.ok(cols.includes("secret_cipher"));
  assert.ok(!cols.includes("client_secret"));
  assert.ok(!cols.includes("refresh_token"));
  db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,secret_cipher,enabled,updated_by) VALUES (?,?,?,?,?)")
    .run("google","id12345","v1.encrypted.fake",1,"admin");
  assert.equal(db.prepare("SELECT enabled FROM nathan_oauth_providers WHERE id='google'").get().enabled,1);
  db.close();
});
