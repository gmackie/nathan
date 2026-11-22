/**
 * Test-only SAML identity provider: metadata and signed Responses built in
 * Node with xml-crypto, posted to Nathan's ACS running in workerd.
 */
import { SignedXml } from "xml-crypto";
import { inflateRawSync } from "node:zlib";

const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export function idpMetadata({ entityID, ssoUrl, certB64s, binding = "HTTP-Redirect", extra = "" }) {
  const keys = certB64s.map(c =>
    `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${c}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`).join("");
  return `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${esc(entityID)}"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keys}<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:${binding}" Location="${esc(ssoUrl)}"/>${extra}</md:IDPSSODescriptor></md:EntityDescriptor>`;
}

/** Extracts the AuthnRequest ID from an HTTP-Redirect binding URL. */
export function authnRequestId(redirectUrl) {
  const xml = inflateRawSync(Buffer.from(new URL(redirectUrl).searchParams.get("SAMLRequest"), "base64")).toString("utf8");
  return /\sID="([^"]+)"/.exec(xml)[1];
}

const iso = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

/**
 * Builds a base64 SAML Response. Options let tests break exactly one property.
 */
export function samlResponse({
  issuer, audience, acs, inResponseTo, email, privateKey, certB64,
  sign = true, notBefore = Date.now() - 60e3, notOnOrAfter = Date.now() + 5 * 60e3,
  assertionId = "_a" + crypto.randomUUID().replace(/-/g, ""), signatureAlgorithm = "rsa-sha256",
  mutate = x => x
}) {
  const now = iso(Date.now());
  const irt = inResponseTo ? ` InResponseTo="${esc(inResponseTo)}"` : "";
  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${now}">` +
    `<saml:Issuer>${esc(issuer)}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${esc(email)}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${irt} NotOnOrAfter="${iso(notOnOrAfter)}" Recipient="${esc(acs)}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${iso(notBefore)}" NotOnOrAfter="${iso(notOnOrAfter)}"><saml:AudienceRestriction><saml:Audience>${esc(audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${now}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${esc(email)}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` +
    `</saml:Assertion>`;
  let xml =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${crypto.randomUUID().replace(/-/g, "")}" Version="2.0" IssueInstant="${now}" Destination="${esc(acs)}"${irt}>` +
    `<saml:Issuer>${esc(issuer)}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    assertion + `</samlp:Response>`;
  if (sign) {
    const algorithms = {
      "rsa-sha256": ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmlenc#sha256"],
      "rsa-sha1": ["http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2000/09/xmldsig#sha1"]
    }[signatureAlgorithm];
    const sig = new SignedXml({
      privateKey, signatureAlgorithm: algorithms[0],
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      getKeyInfoContent: () => `<ds:X509Data><ds:X509Certificate>${certB64}</ds:X509Certificate></ds:X509Data>`
    });
    sig.addReference({
      xpath: "//*[local-name(.)='Assertion']",
      digestAlgorithm: algorithms[1],
      transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"]
    });
    sig.computeSignature(xml, {
      prefix: "ds",
      location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: "after" }
    });
    xml = sig.getSignedXml();
  }
  return Buffer.from(mutate(xml), "utf8").toString("base64");
}
