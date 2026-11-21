/**
 * IdP metadata documents shaped like the ones Okta, Microsoft Entra ID and
 * Google Workspace publish (namespaces, element order, extra descriptors).
 * Certificates are generated per test run; identifiers are fictitious.
 */
const kd = (cert, use = "signing", ns = "md", ds = "ds") =>
  `<${ns}:KeyDescriptor${use ? ` use="${use}"` : ""}><${ds}:KeyInfo xmlns:${ds}="http://www.w3.org/2000/09/xmldsig#"><${ds}:X509Data><${ds}:X509Certificate>${cert.match(/.{1,76}/g).join("\n")}</${ds}:X509Certificate></${ds}:X509Data></${ds}:KeyInfo></${ns}:KeyDescriptor>`;

export function oktaMetadata(certB64, { sso = "https://acme.okta.example/app/acme_nathan_1/exk1abcd/sso/saml" } = {}) {
  return `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/exk1abcdEFGHijkl5d7"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${kd(certB64)}<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${sso}"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${sso}"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
}

export function entraMetadata(certB64s, { tenant = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0" } = {}) {
  const sso = `https://login.microsoftonline.com/${tenant}/saml2`;
  const sig = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_entra"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AAAA</DigestValue></Reference></SignedInfo><SignatureValue>AAAA</SignatureValue></Signature>`;
  // Entra uses default namespaces rather than md:/ds: prefixes.
  const keys = certB64s.map(c =>
    `<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${c}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>`).join("");
  return `<?xml version="1.0" encoding="utf-8"?><EntityDescriptor ID="_entra" entityID="https://sts.windows.net/${tenant}/" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">${sig}` +
    `<RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706">${keys}<fed:PassiveRequestorEndpoint><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>https://login.microsoftonline.com/${tenant}/wsfed</Address></EndpointReference></fed:PassiveRequestorEndpoint></RoleDescriptor>` +
    `<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keys}<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${sso}"/><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${sso}"/><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${sso}"/></IDPSSODescriptor></EntityDescriptor>`;
}

export function googleMetadata(certB64, { idpid = "C01abcdef", validUntil = new Date(Date.now() + 5 * 365 * 86400e3) } = {}) {
  const sso = `https://accounts.google.com/o/saml2/idp?idpid=${idpid}`;
  return `<?xml version="1.0" encoding="UTF-8" standalone="no"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://accounts.google.com/o/saml2?idpid=${idpid}" validUntil="${validUntil.toISOString()}"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${kd(certB64, "")}<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${sso.replace("&", "&amp;")}"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${sso.replace("&", "&amp;")}"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
}
