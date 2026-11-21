/**
 * Nathan policy around the @better-auth/sso SAML implementation. Plain JS so
 * the same code is unit-tested in Node and bundled into the auth Worker.
 */
import { DOMParser } from "@xmldom/xmldom";
import { MAX_METADATA_BYTES } from "./saml-metadata.mjs";

export const SAML_CLOCK_SKEW_MS = 2 * 60 * 1000;
/** Better Auth endpoint path (route template) of the SAML ACS. */
export const SAML_ACS_ENDPOINT = "/sso/saml2/sp/acs/:providerId";

/**
 * Options for the sso() plugin. Signed assertions are required per connection
 * (wantAssertionsSigned); here: SHA-1 rejected, SP-initiated only with
 * InResponseTo bound to a stored AuthnRequest, timestamps required with a
 * 2 minute skew, and IdP email_verified claims never trusted — email trust
 * comes only from Better Auth's DNS-verified domain.
 * @returns {import("@better-auth/sso").SSOOptions}
 */
export function ssoPluginOptions() {
  return {
    domainVerification: { enabled: true },
    trustEmailVerified: false,
    saml: {
      enableInResponseToValidation: true,
      allowIdpInitiated: false,
      requireTimestamps: true,
      clockSkew: SAML_CLOCK_SKEW_MS,
      algorithms: { onDeprecated: "reject" },
      maxMetadataSize: MAX_METADATA_BYTES
    }
  };
}

/**
 * Returns the connection named by a SAML protocol path (ACS, SLO, logout),
 * "" when the path names an unusable connection, or null for other paths.
 */
export function samlProviderFromPath(pathname) {
  const m = /^\/api\/auth\/sso\/saml2\/(?:sp\/acs|sp\/slo|logout)\/([^/]*)$/.exec(pathname);
  if (!m) return null;
  let id;
  try { id = decodeURIComponent(m[1]); } catch { return ""; }
  return /^[a-z][a-z0-9-]{1,62}$/.test(id) ? id : "";
}

export function emailInDomain(email, domain) {
  if (typeof email !== "string" || typeof domain !== "string") return false;
  const at = email.lastIndexOf("@");
  if (at < 1) return false;
  const host = email.slice(at + 1).toLowerCase(), d = domain.toLowerCase();
  return Boolean(d) && (host === d || host.endsWith("." + d));
}

/** Attribute names each IdP sends by default; generic expects "email"/"firstName"/"lastName". */
const PRESETS = {
  generic: { email: "email", firstName: "firstName", lastName: "lastName" },
  okta: { email: "email", firstName: "firstName", lastName: "lastName" },
  google: { email: "email", firstName: "firstName", lastName: "lastName" },
  entra: {
    email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    firstName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    lastName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
  }
};
export const ATTRIBUTE_PRESETS = Object.keys(PRESETS);
export function attributeMapping(preset) {
  if (!Object.hasOwn(PRESETS, preset)) throw Error("Unknown attribute preset");
  return { ...PRESETS[preset] };
}

const CONNECTION_SQL =
  'SELECT c.enabled AS enabled,c.provisioning AS provisioning,c.domain AS domain,p."domainVerified" AS verified ' +
  'FROM nathan_saml_connections c JOIN "ssoProvider" p ON p."providerId"=c.provider_id ' +
  'WHERE c.provider_id=? AND p."samlConfig" IS NOT NULL LIMIT 1';

/** True only for a Nathan-managed, enabled SAML connection whose domain is verified. */
export async function samlConnectionUsable(db, providerId) {
  if (!providerId) return false;
  const row = await db.prepare(CONNECTION_SQL).bind(providerId).first();
  return Boolean(row && Number(row.enabled) === 1 && Number(row.verified) === 1);
}

/**
 * Better Auth databaseHooks.user.create.before. For users arriving through the
 * SAML ACS it is the "disableImplicitSignUp" equivalent, per connection:
 * accounts are only created for just-in-time connections and only for email
 * addresses inside the connection's DNS-verified domain. Existing users are
 * linked by the plugin only when the domain is verified and matches.
 * Returns undefined for non-SAML flows (no change).
 */
export async function samlUserCreateGuard(db, user, ctx) {
  const path = typeof ctx?.path === "string" ? ctx.path : "";
  if (!path.includes("/saml2/")) return undefined;
  // Fail closed for any SAML route other than the ACS this guard understands.
  if (path !== SAML_ACS_ENDPOINT) return false;
  const providerId = typeof ctx?.params?.providerId === "string" ? ctx.params.providerId : "";
  const row = providerId ? await db.prepare(CONNECTION_SQL).bind(providerId).first() : null;
  if (!row || Number(row.enabled) !== 1 || Number(row.verified) !== 1) return false;
  if (row.provisioning !== "just-in-time") return false;
  if (!emailInDomain(user?.email, row.domain)) return false;
  // The domain's owner proved DNS control and its IdP signed this address.
  return { data: { emailVerified: true } };
}

/**
 * Routes "Sign in with SSO" by email domain to exactly one usable connection:
 * the most specific enabled SAML connection, else a verified OIDC provider.
 */
export async function resolveSsoConnection(db, email) {
  if (typeof email !== "string" || email.length > 254) return null;
  const at = email.lastIndexOf("@");
  const host = at > 0 ? email.slice(at + 1).trim().toLowerCase() : "";
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) return null;
  const labels = host.split(".");
  const candidates = labels.slice(0, -1).map((_, i) => labels.slice(i).join("."));
  for (const domain of candidates) {
    const saml = await db.prepare(
      'SELECT c.provider_id AS id FROM nathan_saml_connections c JOIN "ssoProvider" p ON p."providerId"=c.provider_id ' +
      'WHERE c.domain=? AND c.enabled=1 AND p."domainVerified"=1 AND p."samlConfig" IS NOT NULL ORDER BY c.provider_id LIMIT 1'
    ).bind(domain).first();
    if (saml) return { providerId: saml.id, type: "saml" };
    const oidc = await db.prepare(
      'SELECT "providerId" AS id FROM "ssoProvider" WHERE "domain"=? AND "domainVerified"=1 AND "oidcConfig" IS NOT NULL ' +
      'AND "samlConfig" IS NULL ORDER BY "providerId" LIMIT 1'
    ).bind(domain).first();
    if (oidc) return { providerId: oidc.id, type: "oidc" };
  }
  return null;
}

const WEAK_ALGORITHM = /(sha1|md5)$/i;
/**
 * The plugin's onDeprecated check only sees the HTTP-Redirect SigAlg query
 * parameter, not the XML signature inside a POSTed Response. Returns a reason
 * when any SignatureMethod/DigestMethod is SHA-1 or MD5 (or the XML has a DTD
 * or cannot be parsed), else null. Attribute values are read after XML
 * entity decoding so character references cannot hide "sha1".
 */
export function weakSamlAlgorithm(xml) {
  if (typeof xml !== "string") return "unparseable";
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) return "dtd";
  let doc, failed = false;
  try {
    doc = new DOMParser({ onError: (level) => { if (level !== "warning") failed = true; } })
      .parseFromString(xml, "application/xml");
  } catch { return "unparseable"; }
  if (failed || !doc?.documentElement) return "unparseable";
  const stack = [doc.documentElement];
  while (stack.length) {
    const el = stack.pop();
    if (el.localName === "SignatureMethod" || el.localName === "DigestMethod") {
      const alg = el.getAttribute("Algorithm") || "";
      if (WEAK_ALGORITHM.test(alg)) return "weak algorithm " + alg.replace(/^.*#/, "");
    }
    for (const child of Array.from(el.childNodes || [])) if (child.nodeType === 1) stack.push(child);
  }
  return null;
}

/**
 * Extracts and decodes the SAMLResponse of an ACS POST (form or JSON body).
 * Returns undefined when there is none, null when it cannot be decoded.
 */
export function samlResponseXml(contentType, raw) {
  let value;
  if (contentType === "application/x-www-form-urlencoded") value = new URLSearchParams(raw).get("SAMLResponse") ?? undefined;
  else if (contentType === "application/json") {
    try { const body = JSON.parse(raw); value = body?.SAMLResponse; } catch { return null; }
    if (value !== undefined && typeof value !== "string") return null;
  } else return null;
  if (value === undefined) return undefined;
  try {
    const bin = atob(value.replace(/\s+/g, ""));
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bin, c => c.charCodeAt(0)));
  } catch { return null; }
}
