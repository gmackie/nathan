import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { ssoPluginOptions, samlProviderFromPath, samlUserCreateGuard, emailInDomain, SAML_ACS_ENDPOINT,
  attributeMapping, resolveSsoConnection, certificateSwapStatements } from "../src/auth/saml-policy.mjs";

// Configuration snapshot only: it pins the options Nathan passes to the plugin.
// It proves nothing about enforcement. In particular algorithms.onDeprecated
// does not cover XML signatures in POSTed responses; Nathan's own message
// guard (inspectSamlMessage, below and in tests/runtime/saml.test.mjs) does.
test("SSO plugin options passed to @better-auth/sso (config snapshot, not proof of enforcement)", () => {
  assert.deepEqual(ssoPluginOptions(), {
    domainVerification: { enabled: true },
    trustEmailVerified: false,
    saml: {
      enableInResponseToValidation: true,
      allowIdpInitiated: false,
      requireTimestamps: true,
      clockSkew: 120000,
      algorithms: { onDeprecated: "reject" },
      maxMetadataSize: 102400
    }
  });
});

test("SAML protocol paths name their connection; everything else does not", () => {
  assert.equal(samlProviderFromPath("/api/auth/sso/saml2/sp/acs/acme-okta"), "acme-okta");
  assert.equal(samlProviderFromPath("/api/auth/sso/saml2/sp/slo/acme-okta"), "acme-okta");
  assert.equal(samlProviderFromPath("/api/auth/sso/saml2/logout/acme-okta"), "acme-okta");
  assert.equal(samlProviderFromPath("/api/auth/sso/saml2/sp/acs/acme%2Fx"), "");
  assert.equal(samlProviderFromPath("/api/auth/sso/saml2/sp/metadata"), null);
  assert.equal(samlProviderFromPath("/api/auth/sso/callback/acme"), null);
});

test("email domain match is exact or subdomain, never suffix-only", () => {
  assert.ok(emailInDomain("a@acme.example", "acme.example"));
  assert.ok(emailInDomain("a@eu.acme.example", "acme.example"));
  assert.ok(!emailInDomain("a@evilacme.example", "acme.example"));
  assert.ok(!emailInDomain("a@acme.example.evil", "acme.example"));
  assert.ok(!emailInDomain("not-an-email", "acme.example"));
});

test("attribute mapping presets match each IdP's default claim names", () => {
  assert.equal(attributeMapping("entra").email, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
  assert.equal(attributeMapping("okta").email, "email");
  assert.equal(attributeMapping("google").email, "email");
  assert.throws(() => attributeMapping("nope"), /preset/);
});

function db() {
  const d = new DatabaseSync(":memory:");
  for (const f of ["0002_better_auth.sql", "0013_saml.sql"])
    d.exec(readFileSync("migrations/" + f, "utf8"));
  d.exec(`INSERT INTO "user"(id,name,email,emailVerified,createdAt,updatedAt) VALUES('u','u','admin@example.test',1,0,0)`);
  const add = (id, domain, verified, enabled, provisioning, saml = true) => {
    d.prepare(`INSERT INTO "ssoProvider"(id,issuer,samlConfig,oidcConfig,userId,providerId,domain,domainVerified) VALUES(?,?,?,?,?,?,?,?)`)
      .run(id, "https://sp/" + id, saml ? "{}" : null, saml ? null : "{}", "u", id, domain, verified);
    if (saml) d.prepare(`INSERT INTO nathan_saml_connections(provider_id,domain,idp_entity_id,sso_url,certificates,provisioning,attribute_preset,enabled,created_by) VALUES(?,?,?,?,?,?,?,?,?)`)
      .run(id, domain, "https://idp/" + id, "https://idp/sso", "[]", provisioning, "generic", enabled, "u");
  };
  add("jit", "acme.example", 1, 1, "just-in-time");
  add("invite", "invite.example", 1, 1, "invitation-only");
  add("off", "off.example", 1, 0, "just-in-time");
  add("unverified", "unv.example", 0, 1, "just-in-time");
  add("oidc", "oidc.example", 1, 0, null, false);
  add("eu", "eu.acme.example", 1, 1, "just-in-time");
  // D1-shaped adapter over node:sqlite
  return { prepare: sql => ({ bind: (...a) => ({ first: async () => d.prepare(sql).get(...a) ?? null, all: async () => ({ results: d.prepare(sql).all(...a) }) }) }) };
}
const acs = providerId => ({ path: SAML_ACS_ENDPOINT, params: { providerId } });

test("new SAML users are created only for enabled, verified, just-in-time connections inside the domain", async () => {
  const d = db();
  assert.deepEqual(await samlUserCreateGuard(d, { email: "jane@acme.example" }, acs("jit")), { data: { emailVerified: true } });
  assert.equal(await samlUserCreateGuard(d, { email: "jane@invite.example" }, acs("invite")), false, "invitation-only");
  assert.equal(await samlUserCreateGuard(d, { email: "jane@off.example" }, acs("off")), false, "disabled");
  assert.equal(await samlUserCreateGuard(d, { email: "jane@unv.example" }, acs("unverified")), false, "unverified domain");
  assert.equal(await samlUserCreateGuard(d, { email: "ceo@other.example" }, acs("jit")), false, "foreign domain");
  assert.equal(await samlUserCreateGuard(d, { email: "x@acme.example" }, acs("missing")), false, "unknown connection");
  assert.equal(await samlUserCreateGuard(d, { email: "x@acme.example" }, { path: "/callback/:id", params: {} }), undefined, "other flows untouched");
  assert.equal(await samlUserCreateGuard(d, { email: "x@acme.example" }, null), undefined);
  assert.equal(await samlUserCreateGuard(d, { email: "jane@acme.example" }, { path: "/sso/saml2/sp/acs2/:id", params: { id: "jit" } }), false,
    "unknown SAML routes fail closed (plugin upgrade guard)");
});

test("SSO sign-in routing picks the most specific enabled connection by email domain", async () => {
  const d = db();
  assert.deepEqual(await resolveSsoConnection(d, "jane@acme.example"), { providerId: "jit", type: "saml" });
  assert.deepEqual(await resolveSsoConnection(d, "jane@eu.acme.example"), { providerId: "eu", type: "saml" });
  assert.deepEqual(await resolveSsoConnection(d, "jane@sub.eu.acme.example"), { providerId: "eu", type: "saml" });
  assert.equal(await resolveSsoConnection(d, "jane@off.example"), null, "disabled SAML is never routed");
  assert.equal(await resolveSsoConnection(d, "jane@unv.example"), null, "unverified domain is never routed");
  assert.deepEqual(await resolveSsoConnection(d, "jane@oidc.example"), { providerId: "oidc", type: "oidc" });
  assert.equal(await resolveSsoConnection(d, "jane@nowhere.example"), null);
  assert.equal(await resolveSsoConnection(d, "garbage"), null);
});

import { weakSamlAlgorithm, inspectSamlMessage } from "../src/auth/saml-policy.mjs";
import { samlResponse } from "./fixtures/saml-idp.mjs";
import { makeCertificate } from "./fixtures/x509.mjs";

test("SAML responses signed or digested with SHA-1 are detected, including entity-encoded attributes", () => {
  const c = makeCertificate();
  const xml = o => Buffer.from(samlResponse({ issuer: "https://idp", audience: "https://sp", acs: "https://sp/acs",
    email: "a@b.example", privateKey: c.privateKey, certB64: c.certB64, ...o }), "base64").toString("utf8");
  assert.equal(weakSamlAlgorithm(xml({})), null);
  assert.match(weakSamlAlgorithm(xml({ signatureAlgorithm: "rsa-sha1" })), /sha1/);
  assert.match(weakSamlAlgorithm(xml({}).replace("xmldsig-more#rsa-sha256", "xmldsig#rsa-&#x73;ha1")), /sha1/);
  assert.match(weakSamlAlgorithm(xml({}).replace("xmlenc#sha256", "xmldsig#sha1")), /sha1/);
  assert.equal(weakSamlAlgorithm(xml({ sign: false })), null);
  assert.equal(weakSamlAlgorithm("<not xml"), "unparseable");
  assert.equal(weakSamlAlgorithm('<!DOCTYPE x [<!ENTITY a "b">]><x/>'), "dtd");
});

test("SAML message guard: exactly one SAMLResponse and at most one of each binding parameter", () => {
  const FORM = "application/x-www-form-urlencoded";
  const key = makeCertificate({ cn: "guard" });
  const sign = over => samlResponse({ issuer: "https://idp.example/saml", audience: "sp", acs: "https://sp.example/acs",
    email: "a@acme.example", privateKey: key.privateKey, certB64: key.certB64, ...over });
  const strong = sign({}), weak = sign({ signatureAlgorithm: "rsa-sha1" });
  const form = fields => new URLSearchParams(fields).toString();
  const acs = (body, { search = "", contentType = FORM } = {}) =>
    inspectSamlMessage({ endpoint: "acs", method: "POST", search, contentType, body });
  const code = r => r?.code ?? null;

  assert.equal(acs(form([["SAMLResponse", strong], ["RelayState", "r"]])), null, "a well-formed SHA-256 response passes");
  assert.equal(acs(form([["SAMLResponse", strong]]), { contentType: "application/x-www-form-urlencoded; charset=UTF-8" }), null);
  for (const pair of [[strong, weak], [weak, strong], [strong, strong]])
    assert.equal(code(acs(form([["SAMLResponse", pair[0]], ["SAMLResponse", pair[1]]]))), "saml_duplicate_parameter");
  assert.equal(code(acs(form([["SAMLResponse", strong], ["RelayState", "a"], ["RelayState", "b"]]))), "saml_duplicate_parameter");
  assert.equal(code(acs(form([["SAMLResponse", strong], ["RelayState", "a"]]), { search: "?RelayState=b" })), "saml_duplicate_parameter",
    "a parameter may not appear in both the query and the body");
  assert.equal(code(acs(form([["SAMLResponse", strong]]), { search: "?SAMLResponse=x" })), "saml_duplicate_parameter");
  assert.equal(code(acs(form([["RelayState", "r"]]))), "saml_missing_response");
  assert.equal(code(acs(form([["SAMLResponse", ""]]))), "saml_unreadable");
  assert.equal(code(acs("", { search: "?SAMLResponse=" + encodeURIComponent(strong) })), "saml_missing_response",
    "the ACS only processes a SAMLResponse in the POST body");
  assert.equal(code(acs(JSON.stringify({ SAMLResponse: strong }), { contentType: "application/json" })), "saml_form_required",
    "the HTTP-POST binding is form-encoded");
  for (const contentType of ["text/plain", "multipart/form-data; boundary=x", "application/x-www-form-urlencodedx", "", "APPLICATION/X-WWW-FORM-URLENCODED, application/json"])
    assert.equal(code(acs(form([["SAMLResponse", strong]]), { contentType })), "saml_form_required", contentType);

  assert.equal(code(acs(form([["SAMLResponse", weak]]))), "saml_weak_algorithm");
  assert.equal(code(acs(form([["SAMLResponse", sign({ mutate: x => x.replace("xmlenc#sha256", "xmldsig#sha1") })]]))), "saml_weak_algorithm");
  assert.equal(code(acs(form([["SAMLResponse", Buffer.from("<!DOCTYPE x><x/>").toString("base64")]]))), "saml_unreadable");
  assert.equal(code(acs(form([["SAMLResponse", "not base64!"]]))), "saml_unreadable");
  assert.equal(code(acs(form([["SAMLResponse", Buffer.from([0xff, 0xfe, 0x3c]).toString("base64")]]))), "saml_unreadable", "invalid UTF-8");
  const encrypted = sign({ mutate: x => x.replace(/<saml:Assertion[\s\S]*<\/saml:Assertion>/,
    '<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>') });
  assert.equal(code(acs(form([["SAMLResponse", encrypted]]))), "saml_encrypted_assertion");
  // Whitespace is stripped exactly as the plugin does before decoding.
  const wrapped = strong.replace(/(.{76})/g, "$1\r\n");
  assert.equal(acs(form([["SAMLResponse", wrapped]])), null);

  // Redirect binding and logout endpoints: every binding parameter at most once.
  for (const name of ["SAMLRequest", "SAMLResponse", "SigAlg", "Signature", "RelayState"]) {
    for (const endpoint of ["acs", "slo"])
      assert.equal(code(inspectSamlMessage({ endpoint, method: "GET", search: "?" + name + "=a&" + name + "=b", contentType: "", body: "" })),
        "saml_duplicate_parameter", endpoint + " " + name);
  }
  assert.equal(inspectSamlMessage({ endpoint: "slo", method: "GET", search: "?SAMLRequest=a&SigAlg=b&Signature=c&RelayState=d", contentType: "", body: "" }), null);
  assert.equal(inspectSamlMessage({ endpoint: "logout", method: "POST", search: "", contentType: "application/json", body: '{"callbackURL":"/"}' }), null,
    "the SP-initiated logout call is JSON");
  assert.equal(code(inspectSamlMessage({ endpoint: "slo", method: "POST", search: "", contentType: FORM, body: form([["SAMLResponse", weak]]) })), "saml_weak_algorithm");
  assert.equal(code(inspectSamlMessage({ endpoint: "slo", method: "POST", search: "?SigAlg=x", contentType: FORM, body: form([["SigAlg", "y"]]) })), "saml_duplicate_parameter");
  assert.equal(code(inspectSamlMessage({ endpoint: "slo", method: "POST", search: "", contentType: "application/json", body: '{"SAMLRequest":1}' })), "saml_unreadable");
  assert.equal(code(inspectSamlMessage({ endpoint: "slo", method: "POST", search: "", contentType: "application/json", body: "[" })), "saml_unreadable");
});

test("certificate rotation is compare-and-swap: a stale writer changes nothing", () => {
  const d = new DatabaseSync(":memory:");
  for (const f of ["0002_better_auth.sql", "0013_saml.sql"]) d.exec(readFileSync("migrations/" + f, "utf8"));
  d.exec(`INSERT INTO "user"(id,name,email,emailVerified,createdAt,updatedAt) VALUES('u','u','admin@example.test',1,0,0)`);
  d.prepare(`INSERT INTO "ssoProvider"(id,issuer,samlConfig,userId,providerId,domain,domainVerified) VALUES('p','i','{"v":0}','u','acme','acme.example',1)`).run();
  d.prepare(`INSERT INTO nathan_saml_connections(provider_id,domain,idp_entity_id,sso_url,certificates,created_by) VALUES('acme','acme.example','e','s','["X"]','u')`).run();
  // One transaction, as D1 batch() runs it.
  const apply = statements => {
    d.exec("BEGIN");
    const changes = statements.map(({ sql, args }) => Number(d.prepare(sql).run(...args).changes));
    d.exec("COMMIT");
    return changes;
  };
  const state = () => [d.prepare(`SELECT "samlConfig" AS c FROM "ssoProvider" WHERE "providerId"='acme'`).get().c,
    d.prepare("SELECT certificates AS c FROM nathan_saml_connections WHERE provider_id='acme'").get().c];
  // Two admins both read ["X"]; A adds "A", then B (stale) adds "B".
  assert.deepEqual(apply(certificateSwapStatements("acme", '["X"]', '["X","A"]', '{"v":"A"}')), [1, 1]);
  assert.deepEqual(state(), ['{"v":"A"}', '["X","A"]']);
  assert.deepEqual(apply(certificateSwapStatements("acme", '["X"]', '["X","B"]', '{"v":"B"}')), [0, 0], "stale write refused");
  assert.deepEqual(state(), ['{"v":"A"}', '["X","A"]'], "A's update survives; nothing half-applied");
  assert.deepEqual(apply(certificateSwapStatements("acme", '["X","A"]', '["X","A","B"]', '{"v":"AB"}')), [1, 1], "a fresh read succeeds");
  assert.deepEqual(state(), ['{"v":"AB"}', '["X","A","B"]']);
  assert.deepEqual(apply(certificateSwapStatements("other", '["X","A","B"]', '[]', '{}')), [0, 0], "scoped to its connection");
});
