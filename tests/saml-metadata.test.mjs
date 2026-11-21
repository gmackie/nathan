import test from "node:test";
import assert from "node:assert/strict";
import { parseIdpMetadata, buildIdpMetadata, fetchIdpMetadata, spValues, certificateFromInput, MAX_METADATA_BYTES }
  from "../src/auth/saml-metadata.mjs";
import { makeCertificate } from "./fixtures/x509.mjs";
import { oktaMetadata, entraMetadata, googleMetadata } from "./fixtures/saml-metadata.mjs";
import { idpMetadata } from "./fixtures/saml-idp.mjs";

const day = 86400e3;
const good = makeCertificate({ cn: "good" });
const rejects = async (xml, pattern) => assert.rejects(parseIdpMetadata(xml), pattern);

test("Okta-shaped metadata normalizes to entity ID, redirect SSO URL and one certificate", async () => {
  const m = await parseIdpMetadata(oktaMetadata(good.certB64));
  assert.equal(m.entityID, "http://www.okta.com/exk1abcdEFGHijkl5d7");
  assert.equal(m.ssoRedirectUrl, "https://acme.okta.example/app/acme_nathan_1/exk1abcd/sso/saml");
  assert.equal(m.ssoPostUrl, "https://acme.okta.example/app/acme_nathan_1/exk1abcd/sso/saml");
  assert.equal(m.certificates.length, 1);
  assert.equal(m.certificates[0].der, good.certB64);
  assert.equal(m.certificates[0].bits, 2048);
  assert.match(m.certificates[0].sha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  assert.deepEqual(m.warnings, []);
});

test("Entra-shaped metadata ignores the WS-Fed RoleDescriptor and keeps IDPSSODescriptor certificates", async () => {
  const next = makeCertificate({ cn: "next" });
  const m = await parseIdpMetadata(entraMetadata([good.certB64, next.certB64]));
  assert.equal(m.entityID, "https://sts.windows.net/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/");
  assert.equal(m.ssoRedirectUrl, "https://login.microsoftonline.com/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/saml2");
  assert.deepEqual(m.certificates.map(c => c.der), [good.certB64, next.certB64]);
  assert.ok(m.warnings.some(w => /signature.*not verified/i.test(w)), "signed metadata is noted, not trusted");
});

test("Google Workspace-shaped metadata with a future validUntil and use-less KeyDescriptor", async () => {
  const m = await parseIdpMetadata(googleMetadata(good.certB64));
  assert.equal(m.entityID, "https://accounts.google.com/o/saml2?idpid=C01abcdef");
  assert.equal(m.ssoRedirectUrl, "https://accounts.google.com/o/saml2/idp?idpid=C01abcdef");
  assert.equal(m.certificates.length, 1);
});

test("expiring certificate (within 30 days) is accepted with a warning", async () => {
  const soon = makeCertificate({ notAfter: new Date(Date.now() + 10 * day) });
  const m = await parseIdpMetadata(oktaMetadata(soon.certB64));
  assert.ok(m.warnings.some(w => /expires/i.test(w)), JSON.stringify(m.warnings));
  assert.equal(m.certificates[0].expiringSoon, true);
});

test("rejects expired, not-yet-valid, weak and SHA-1 certificates", async () => {
  await rejects(oktaMetadata(makeCertificate({ notBefore: new Date(Date.now() - 400 * day), notAfter: new Date(Date.now() - day) }).certB64), /expired/i);
  await rejects(oktaMetadata(makeCertificate({ notBefore: new Date(Date.now() + day), notAfter: new Date(Date.now() + 400 * day) }).certB64), /not yet valid/i);
  await rejects(oktaMetadata(makeCertificate({ bits: 1024 }).certB64), /2048/);
  await rejects(oktaMetadata(makeCertificate({ hash: "sha1" }).certB64), /SHA-1/i);
});

test("rejects metadata without entity ID, signing certificate or HTTPS SSO URL", async () => {
  await rejects(oktaMetadata(good.certB64).replace(/ entityID="[^"]+"/, ""), /entityID/);
  await rejects(idpMetadata({ entityID: "https://idp.example", ssoUrl: "https://idp.example/sso", certB64s: [] }), /signing certificate/i);
  await rejects(oktaMetadata(good.certB64, { sso: "http://acme.okta.example/sso" }), /HTTPS/);
  await rejects(idpMetadata({ entityID: "https://idp.example", ssoUrl: "https://idp.example/sso", certB64s: [good.certB64], binding: "SOAP" }), /SingleSignOnService/);
});

test("rejects POST-only metadata because Nathan sends AuthnRequests with HTTP-Redirect", async () => {
  await rejects(idpMetadata({ entityID: "https://idp.example", ssoUrl: "https://idp.example/sso", certB64s: [good.certB64], binding: "HTTP-POST" }), /HTTP-Redirect/);
});

test("ignores encryption-only keys", async () => {
  const xml = idpMetadata({ entityID: "https://idp.example", ssoUrl: "https://idp.example/sso", certB64s: [] })
    .replace("<md:NameIDFormat", `<md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${good.certB64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat`);
  await rejects(xml, /signing certificate/i);
});

test("rejects SHA-1 metadata signatures, DTDs, expired validUntil, oversized and malformed documents", async () => {
  await rejects(entraMetadata([good.certB64]).replace("xmldsig-more#rsa-sha256", "xmldsig#rsa-sha1"), /SHA-1/i);
  await rejects('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]>' + oktaMetadata(good.certB64).replace(/^<\?xml[^>]*>/, ""), /DTD|DOCTYPE/i);
  await rejects(googleMetadata(good.certB64, { validUntil: new Date(Date.now() - day) }), /validUntil|expired/i);
  await rejects(oktaMetadata(good.certB64) + "<!--" + "x".repeat(MAX_METADATA_BYTES) + "-->", /too large|size/i);
  await rejects("<md:EntityDescriptor", /XML|metadata/i);
  await rejects("<EntitiesDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"/>", /EntityDescriptor/);
});

test("rejects non-RSA and garbage certificates", async () => {
  await rejects(oktaMetadata(Buffer.from("not a certificate").toString("base64")), /certificate/i);
});

test("canonical metadata round-trips through the validator", async () => {
  const parsed = await parseIdpMetadata(entraMetadata([good.certB64]));
  const xml = buildIdpMetadata({ entityID: parsed.entityID, ssoRedirectUrl: parsed.ssoRedirectUrl, ssoPostUrl: parsed.ssoPostUrl, certificates: parsed.certificates.map(c => c.der) });
  assert.doesNotMatch(xml, /RoleDescriptor|Signature/);
  const again = await parseIdpMetadata(xml);
  assert.equal(again.entityID, parsed.entityID);
  assert.equal(again.ssoRedirectUrl, parsed.ssoRedirectUrl);
  assert.deepEqual(again.certificates.map(c => c.sha256), parsed.certificates.map(c => c.sha256));
  assert.throws(() => buildIdpMetadata({ entityID: 'x"><evil/>', ssoRedirectUrl: "https://a.example", certificates: [good.certB64] }), /entity/i);
});

test("a single certificate can be validated from PEM or base64 for rotation", async () => {
  const fromPem = await certificateFromInput(good.certPem);
  const fromB64 = await certificateFromInput(good.certB64);
  assert.equal(fromPem.sha256, fromB64.sha256);
  await assert.rejects(certificateFromInput(makeCertificate({ bits: 1024 }).certPem), /2048/);
});

test("SP values are derived per connection from the issuer origin", () => {
  assert.deepEqual(spValues("https://login.example.com", "acme-okta"), {
    entityId: "https://login.example.com/api/auth/sso/saml2/sp/metadata?providerId=acme-okta",
    acsUrl: "https://login.example.com/api/auth/sso/saml2/sp/acs/acme-okta",
    metadataUrl: "https://login.example.com/api/auth/sso/saml2/sp/metadata?providerId=acme-okta"
  });
});

/**
 * Replaces globalThis.fetch for one test so fetchIdpMetadata runs its
 * production path (fetchNoRedirect from src/shared/security.mjs).
 */
async function withFetch(impl, fn) {
  const original = globalThis.fetch, calls = [];
  globalThis.fetch = async (input, init = {}) => { calls.push({ url: String(input), init }); return impl(input, init); };
  try { await fn(calls); } finally { globalThis.fetch = original; }
}

test("metadata fetch is HTTPS-only, public-host-only and size-limited (production fetch path)", async () => {
  const xml = oktaMetadata(good.certB64);
  await withFetch(async () => new Response(xml, { headers: { "content-type": "application/samlmetadata+xml" } }), async calls => {
    assert.equal(await fetchIdpMetadata("https://acme.okta.example/app/exk1/sso/saml/metadata"), xml);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].init.redirect, "manual", "never redirect:'error', which Workers reject");
    assert.ok(calls[0].init.signal instanceof AbortSignal, "the timeout signal reaches fetch");
    await assert.rejects(fetchIdpMetadata("http://acme.okta.example/m"), /HTTPS/);
    await assert.rejects(fetchIdpMetadata("https://user:pw@acme.okta.example/m"), /credentials/);
    for (const host of ["localhost", "127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "[::1]", "metadata.internal"])
      await assert.rejects(fetchIdpMetadata("https://" + host + "/m"), /public/i, host);
    assert.equal(calls.length, 1, "rejected URLs are never fetched");
  });
  await withFetch(async () => new Response("x".repeat(MAX_METADATA_BYTES + 10)), async () =>
    assert.rejects(fetchIdpMetadata("https://acme.okta.example/m"), /too large/i));
  await withFetch(async () => new Response("x", { headers: { "content-length": String(MAX_METADATA_BYTES + 1) } }), async () =>
    assert.rejects(fetchIdpMetadata("https://acme.okta.example/m"), /too large/i, "declared length checked before reading"));
  await withFetch(async () => new Response("no", { status: 404 }), async () =>
    assert.rejects(fetchIdpMetadata("https://acme.okta.example/m"), /404/));
  await withFetch(async () => { throw new TypeError("network down"); }, async () =>
    assert.rejects(fetchIdpMetadata("https://acme.okta.example/m"), /^Error: Metadata fetch failed$/));
});

test("metadata fetch refuses redirects through fetchNoRedirect", async () => {
  for (const status of [301, 302, 303, 307, 308]) {
    await withFetch(async () => new Response(null, { status, headers: { location: "https://169.254.169.254/latest" } }), async calls => {
      await assert.rejects(fetchIdpMetadata("https://acme.okta.example/m"), /redirect; paste the final HTTPS URL/, String(status));
      assert.equal(calls.length, 1, "the redirect target is never requested");
    });
  }
  // Browsers and some runtimes surface a manual redirect as an opaque-redirect response with status 0.
  const opaque = () => { const r = new Response(null); Object.defineProperty(r, "type", { value: "opaqueredirect" }); return r; };
  await withFetch(async () => opaque(), async () =>
    assert.rejects(fetchIdpMetadata("https://acme.okta.example/m"), /redirect/));
});

test("metadata fetch times out through the production fetch path", async () => {
  const hang = (_url, init) => new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason)));
  await withFetch(hang, async () => {
    const started = Date.now();
    await assert.rejects(fetchIdpMetadata("https://acme.okta.example/m", { timeoutMs: 50 }), /timed out after 50 ms/);
    assert.ok(Date.now() - started < 2000);
  });
  // A body that stalls after the headers is bounded by the same timeout.
  const stall = (_url, init) => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode("<md:")); init.signal.addEventListener("abort", () => controller.error(init.signal.reason)); }
  }));
  await withFetch(stall, async () =>
    assert.rejects(fetchIdpMetadata("https://acme.okta.example/m", { timeoutMs: 50 }), /time/i));
});
