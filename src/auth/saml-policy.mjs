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
 * (wantAssertionsSigned); here: SP-initiated only with InResponseTo bound to a
 * stored AuthnRequest, timestamps required with a 2 minute skew, and IdP
 * email_verified claims never trusted — email trust comes only from Better
 * Auth's DNS-verified domain. algorithms.onDeprecated:"reject" covers only
 * the algorithms the plugin itself inspects (configuration and the
 * HTTP-Redirect SigAlg); it does NOT reject a SHA-1/MD5 XML signature inside
 * a POSTed Response. Nathan enforces that in inspectSamlMessage, which the
 * auth Worker runs before the plugin sees any SAML message.
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
 * The two statements that store a rotated certificate list, to run in one
 * D1 batch (a transaction). Compare-and-swap: both apply only while Nathan's
 * row still holds `previousCertificates` (the list the caller read), and the
 * second only once the first has written the plugin's config, so concurrent
 * rotations cannot silently overwrite each other or leave the two rows apart.
 * The caller must check that each statement changed exactly one row.
 */
export function certificateSwapStatements(providerId, previousCertificates, certificates, samlConfig) {
  return [
    { sql: 'UPDATE "ssoProvider" SET "samlConfig"=? WHERE "providerId"=? AND "samlConfig" IS NOT NULL ' +
        "AND EXISTS(SELECT 1 FROM nathan_saml_connections WHERE provider_id=? AND certificates=?)",
      args: [samlConfig, providerId, providerId, previousCertificates] },
    { sql: "UPDATE nathan_saml_connections SET certificates=?,updated_at=unixepoch() WHERE provider_id=? AND certificates=? " +
        'AND EXISTS(SELECT 1 FROM "ssoProvider" WHERE "providerId"=? AND "samlConfig"=?)',
      args: [certificates, providerId, previousCertificates, providerId, samlConfig] }
  ];
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
const ENCRYPTED = new Set(["EncryptedAssertion", "EncryptedID", "EncryptedAttribute", "EncryptedData", "EncryptedKey"]);

/** Parses SAML XML once; reports a DTD, a parse error, the first weak algorithm and any encrypted element. */
function scanSamlXml(xml) {
  if (typeof xml !== "string") return { error: "unparseable" };
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) return { error: "dtd" };
  let doc, failed = false;
  try {
    doc = new DOMParser({ onError: (level) => { if (level !== "warning") failed = true; } })
      .parseFromString(xml, "application/xml");
  } catch { return { error: "unparseable" }; }
  if (failed || !doc?.documentElement) return { error: "unparseable" };
  let weak = null, encrypted = false;
  const stack = [doc.documentElement];
  while (stack.length) {
    const el = stack.pop();
    if (ENCRYPTED.has(el.localName)) encrypted = true;
    if (!weak && (el.localName === "SignatureMethod" || el.localName === "DigestMethod")) {
      const alg = el.getAttribute("Algorithm") || "";
      if (WEAK_ALGORITHM.test(alg)) weak = "weak algorithm " + alg.replace(/^.*#/, "");
    }
    for (const child of Array.from(el.childNodes || [])) if (child.nodeType === 1) stack.push(child);
  }
  return { weak, encrypted };
}

/**
 * The plugin's onDeprecated check only sees the HTTP-Redirect SigAlg query
 * parameter, not the XML signature inside a POSTed Response. Returns a reason
 * when any SignatureMethod/DigestMethod is SHA-1 or MD5 (or the XML has a DTD
 * or cannot be parsed), else null. Attribute values are read after XML
 * entity decoding so character references cannot hide "sha1".
 */
export function weakSamlAlgorithm(xml) {
  const r = scanSamlXml(xml);
  return r.error ?? r.weak;
}

/** SAML binding parameters (HTTP-Redirect and HTTP-POST). Each may appear at most once per message. */
export const SAML_BINDING_PARAMETERS = ["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"];
const FORM = "application/x-www-form-urlencoded";
const refuse = (code, message) => ({ status: 400, code, message });

/** Decodes a base64 SAML message exactly as the plugin will see it (whitespace stripped), strictly. */
function decodeSamlMessage(value) {
  try {
    const bin = atob(value.replace(/\s+/g, ""));
    if (!bin) return null;
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bin, c => c.charCodeAt(0)));
  } catch { return null; }
}

/**
 * Nathan's guard for a SAML protocol message, run before @better-auth/sso
 * parses anything. `endpoint` is "acs", "slo" or "logout"; `search` the URL
 * query; `body` the raw request body text. Returns null to let the plugin
 * handle the message, else {status, code, message} to refuse it.
 *
 * - Every SAML binding parameter appears at most once across the query and
 *   the body. Different parsers disagree on which duplicate wins (URLSearchParams.get
 *   takes the first, the plugin's form parsing keeps the last), so a
 *   duplicate could make Nathan check one message and the plugin process
 *   another. Refusing duplicates means the checked bytes are the processed bytes.
 * - Query strings and form bodies must be canonically encoded: a '%' that does
 *   not start a valid %HH escape is refused. URLSearchParams keeps such a name
 *   verbatim ("SAMLResp%onse") while workerd's formData(), which the plugin
 *   uses, drops the stray '%' and reads a second SAMLResponse. The route gate
 *   additionally compares this parse with formData() itself (formDataMatches).
 * - The ACS accepts only the form-encoded HTTP-POST binding with exactly one
 *   SAMLResponse in the body.
 * - Any SAMLResponse/SAMLRequest in a POST body is decoded as the plugin
 *   decodes it and refused if it is unreadable, has a DTD, uses SHA-1/MD5
 *   anywhere, or carries encrypted content (Nathan configures no SP
 *   decryption key, so encrypted algorithms could not be inspected).
 */
const MALFORMED_ESCAPE = /%(?![0-9A-Fa-f]{2})/;
export function inspectSamlMessage({ endpoint, method, search, contentType, body }) {
  if (MALFORMED_ESCAPE.test(search ?? ""))
    return refuse("saml_noncanonical_encoding", "SAML message rejected: malformed percent-encoding");
  const counts = new Map();
  const count = name => { if (SAML_BINDING_PARAMETERS.includes(name)) counts.set(name, (counts.get(name) ?? 0) + 1); };
  for (const name of new URLSearchParams(search ?? "").keys()) count(name);
  const posted = new Map();
  if (method === "POST") {
    const type = String(contentType ?? "").split(";")[0].trim().toLowerCase();
    if (type === FORM) {
      if (MALFORMED_ESCAPE.test(body ?? ""))
        return refuse("saml_noncanonical_encoding", "SAML message rejected: malformed percent-encoding");
      for (const [name, value] of new URLSearchParams(body ?? "")) { count(name); if (SAML_BINDING_PARAMETERS.includes(name)) posted.set(name, value); }
    } else if (type === "application/json" && endpoint !== "acs") {
      let parsed;
      try { parsed = JSON.parse(body ?? ""); } catch { return refuse("saml_unreadable", "Unreadable SAML message"); }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return refuse("saml_unreadable", "Unreadable SAML message");
      for (const name of SAML_BINDING_PARAMETERS) {
        if (!Object.hasOwn(parsed, name)) continue;
        if (typeof parsed[name] !== "string") return refuse("saml_unreadable", "Unreadable SAML message");
        count(name); posted.set(name, parsed[name]);
      }
    } else return refuse("saml_form_required", "SAML messages must use the form-encoded HTTP-POST binding");
  }
  for (const [name, n] of counts)
    if (n > 1) return refuse("saml_duplicate_parameter", "SAML message rejected: " + name + " appears more than once");
  if (endpoint === "acs" && method === "POST" && !posted.has("SAMLResponse"))
    return refuse("saml_missing_response", "SAML message rejected: exactly one SAMLResponse is required");
  for (const name of ["SAMLResponse", "SAMLRequest"]) {
    if (!posted.has(name)) continue;
    const xml = decodeSamlMessage(posted.get(name));
    const scan = xml === null ? { error: "undecodable" } : scanSamlXml(xml);
    if (scan.error) return refuse("saml_unreadable", "Unreadable SAML message");
    if (scan.weak) return refuse("saml_weak_algorithm", "SAML response rejected: SHA-1/MD5 signatures and digests are not accepted");
    if (scan.encrypted) return refuse("saml_encrypted_assertion", "SAML response rejected: encrypted assertions are not supported");
  }
  return null;
}

/**
 * True when the runtime's own form parser (what @better-auth/sso reads via
 * request.formData()) yields exactly the same ordered name/value pairs as the
 * URLSearchParams parse Nathan inspects. Any disagreement means the checked
 * bytes may not be the processed bytes, so the gate refuses the message.
 * @param {string} body @param {Iterable<[string, FormDataEntryValue]>} formEntries
 */
export function formDataMatches(body, formEntries) {
  const expected = [...new URLSearchParams(body ?? "")];
  const actual = [...formEntries];
  if (expected.length !== actual.length) return false;
  return expected.every(([name, value], i) => actual[i][0] === name && actual[i][1] === value);
}
