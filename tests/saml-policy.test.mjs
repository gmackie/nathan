import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { ssoPluginOptions, samlProviderFromPath, samlUserCreateGuard, emailInDomain, SAML_ACS_ENDPOINT,
  attributeMapping, resolveSsoConnection } from "../src/auth/saml-policy.mjs";

test("SSO plugin options are hardened (config snapshot)", () => {
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

import { weakSamlAlgorithm } from "../src/auth/saml-policy.mjs";
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
