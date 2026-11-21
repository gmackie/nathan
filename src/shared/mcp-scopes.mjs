/**
 * NATH-14: remote MCP scope catalogs, pure and runtime independent (after ForgeGraph FORGE-396/401).
 *
 * An MCP server is a Nathan application registered as a token audience. Its scopes are that app's
 * NATH-13 permission keys (permission key = scope string). Catalog metadata stored next to the
 * resource adds a label, a one-sentence description, a group, implied scopes (`requires`) and the
 * sensitive / admin-only flags; the resource may also name aliases and a Full access marker.
 *
 * Rules:
 * - Reserved OIDC scopes and every `nathan:*` scope are never MCP scopes.
 * - Sensitive scopes are never implied: no alias, no Full access marker and no `requires` covers
 *   them. They are granted only when named and ticked on their own.
 * - Full access is stored as a marker, so it covers non-sensitive scopes added to the app later.
 * - Effective scopes = what the grant holds ∩ the user's current permissions on the app (and
 *   admin-only scopes only for current Nathan administrators).
 * No I/O here; src/auth/mcp-oauth.ts reads D1 and calls these, and tests call them directly.
 */
import { isPermissionKey } from "./policy.mjs";

/** Nathan MCP access tokens live 300 s (Gatekeeper's 900 s cap is the hard limit). */
export const MCP_ACCESS_TOKEN_SECONDS = 300;
/** Absolute lifetime of a grant; the user consents again afterwards. */
export const MCP_GRANT_SECONDS = 30 * 24 * 3600;
export const MCP_CODE_SECONDS = 300;
export const MCP_TICKET_SECONDS = 600;
/** Dynamic registrations expire; clients register again. */
export const MCP_CLIENT_SECONDS = 180 * 24 * 3600;
/** A registration that never obtained a grant is pruned after a day (scheduled, and at each registration). */
export const MCP_UNUSED_CLIENT_SECONDS = 24 * 3600;
/** At most this many registrations without a grant exist at once; registration answers 503 beyond it. */
export const MCP_UNUSED_CLIENT_LIMIT = 1000;
/** Stored metadata bounds: one registration row stays under 4 KB. */
const MAX_CLIENT_NAME = 64;
const MAX_REDIRECT_URIS = 5;
const MAX_REDIRECT_URI = 512;
const MAX_REGISTRATION_SCOPE = 1024;
/** The SDK caches a grant check for at most this long, so edits and revocation reach Workers within 60 s. */
export const MCP_MAX_CHECK_CACHE_SECONDS = 30;

const OIDC_SCOPES = new Set(["openid", "profile", "email", "address", "phone", "offline_access"]);
/** @param {unknown} scope */
export const isReservedScope = scope => typeof scope === "string" && (OIDC_SCOPES.has(scope) || scope === "nathan" || scope.startsWith("nathan:"));
const isScopeName = value => isPermissionKey(value) && !isReservedScope(value);
const GROUP = /^[a-z][a-z0-9_-]{0,39}$/;
const CONTROL = /[\x00-\x1f\x7f]/;
const MAX_SCOPE_PARAM = 4096;
const MAX_ENTRIES = 200;

export class ScopeError extends Error {
  /** @param {string} message @param {string} [code] */
  constructor(message, code = "invalid_scope") { super(message); this.code = code; }
}
/** @param {unknown} value @param {number} max @param {string} what */
function text(value, max, what) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string" || value.length > max || CONTROL.test(value)) throw Error("Invalid " + what);
  return value.trim();
}
const unique = values => new Set(values).size === values.length;

/**
 * @typedef {{ scope: string, label: string, description: string, group: string, requires: string[], sensitive: boolean, adminOnly: boolean }} ScopeInfo
 * @typedef {{ name: string, full: string|null, aliases: Record<string,string[]>, scopes: ScopeInfo[] }} ResourceConfig
 * @typedef {{ full: string|null, aliases: Map<string,string[]>, entries: ScopeInfo[], byScope: Map<string,ScopeInfo> }} Catalog
 */

/**
 * Validates the catalog metadata an administrator stores for an MCP resource.
 * @param {any} input @param {string[]} permissionKeys the app's permission keys now
 * @returns {ResourceConfig}
 */
export function validateResourceConfig(input, permissionKeys) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw Error("Invalid MCP resource configuration");
  const name = text(input.name, 100, "name");
  if (!name) throw Error("Invalid name: give the MCP server a name");
  const keys = new Set(permissionKeys.filter(isScopeName));
  const rawScopes = input.scopes ?? {};
  if (typeof rawScopes !== "object" || Array.isArray(rawScopes) || Object.keys(rawScopes).length > MAX_ENTRIES) throw Error("Invalid scope metadata");
  /** @type {Map<string, ScopeInfo>} */
  const metadata = new Map();
  for (const [scope, raw] of Object.entries(rawScopes)) {
    if (isReservedScope(scope)) throw Error("Invalid scope " + scope + ": reserved by Nathan");
    if (!keys.has(scope)) throw Error("Unknown permission " + scope + ": declare it on the application first");
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw Error("Invalid metadata for " + scope);
    const adminOnly = raw.adminOnly === true;
    const requires = raw.requires ?? [];
    if (!Array.isArray(requires) || requires.length > 20 || !unique(requires)) throw Error("Invalid requires for " + scope);
    for (const r of requires) {
      if (r === scope) throw Error("Invalid requires for " + scope + ": a scope cannot require itself");
      if (!keys.has(r)) throw Error("Unknown required scope " + r);
    }
    const group = raw.group === undefined ? "general" : raw.group;
    if (typeof group !== "string" || !GROUP.test(group)) throw Error("Invalid group for " + scope);
    if (raw.sensitive !== undefined && typeof raw.sensitive !== "boolean") throw Error("Invalid sensitive flag for " + scope);
    if (raw.adminOnly !== undefined && typeof raw.adminOnly !== "boolean") throw Error("Invalid adminOnly flag for " + scope);
    metadata.set(scope, {
      scope, label: text(raw.label, 80, "label for " + scope), description: text(raw.description, 300, "description for " + scope),
      group, requires: [...requires], sensitive: raw.sensitive === true || adminOnly, adminOnly
    });
  }
  const sensitive = scope => metadata.get(scope)?.sensitive === true;
  for (const info of metadata.values())
    for (const r of info.requires) if (sensitive(r)) throw Error("Invalid requires for " + info.scope + ": " + r + " is sensitive and never implied");

  let full = null;
  if (input.full !== undefined && input.full !== null && input.full !== "") {
    if (!isScopeName(input.full) || keys.has(input.full)) throw Error("Invalid Full access marker: use a new scope name such as notes:full");
    full = input.full;
  }
  const rawAliases = input.aliases ?? {};
  if (typeof rawAliases !== "object" || Array.isArray(rawAliases) || Object.keys(rawAliases).length > 20) throw Error("Invalid aliases");
  /** @type {Record<string,string[]>} */
  const aliases = {};
  for (const [alias, members] of Object.entries(rawAliases)) {
    if (!isScopeName(alias) || keys.has(alias) || alias === full) throw Error("Invalid alias " + alias + ": use a name that is not a permission or the Full access marker");
    if (!Array.isArray(members) || !members.length || members.length > MAX_ENTRIES || !unique(members)) throw Error("Invalid alias " + alias);
    for (const m of members) {
      if (!keys.has(m)) throw Error("Unknown scope " + m + " in alias " + alias);
      if (sensitive(m)) throw Error("Invalid alias " + alias + ": " + m + " is sensitive and never implied");
    }
    aliases[alias] = [...members].sort();
  }
  return { name, full, aliases, scopes: [...metadata.values()].sort((a, b) => a.scope < b.scope ? -1 : 1) };
}

/**
 * The live catalog: every current, non-reserved app permission, with stored metadata where present.
 * @param {{ full?: string|null, aliases?: Record<string,string[]>, permissions: {key:string, description?:string}[], metadata?: ScopeInfo[] }} input
 * @returns {Catalog}
 */
export function buildCatalog({ full = null, aliases = {}, permissions, metadata = [] }) {
  const meta = new Map(metadata.map(m => [m.scope, m]));
  const entries = permissions.filter(p => isScopeName(p.key)).map(p => {
    const m = meta.get(p.key);
    return {
      scope: p.key, label: m?.label || p.key, description: m?.description || p.description || "",
      group: m?.group || "general", requires: Array.isArray(m?.requires) ? m.requires : [],
      sensitive: m?.sensitive === true || m?.adminOnly === true, adminOnly: m?.adminOnly === true
    };
  }).sort((a, b) => a.scope < b.scope ? -1 : 1);
  const byScope = new Map(entries.map(e => [e.scope, e]));
  const safe = scope => byScope.has(scope) && !byScope.get(scope)?.sensitive;
  const aliasMap = new Map(Object.entries(aliases ?? {}).map(([a, members]) => [a, (members ?? []).filter(safe)]));
  return { full: typeof full === "string" && full ? full : null, aliases: aliasMap, entries, byScope };
}

/** Adds implied scopes transitively; sensitive scopes are never implied. @param {Catalog} catalog @param {Iterable<string>} scopes */
export function withPrerequisites(catalog, scopes) {
  const out = new Set(scopes);
  const queue = [...out];
  while (queue.length) {
    const info = catalog.byScope.get(/** @type {string} */ (queue.pop()));
    for (const r of info?.requires ?? []) {
      const required = catalog.byScope.get(r);
      if (required && !required.sensitive && !out.has(r)) { out.add(r); queue.push(r); }
    }
  }
  return out;
}

/**
 * Parses a space-separated scope parameter. Aliases expand (never to sensitive scopes), the Full
 * access marker stays in the set, `offline_access` is accepted and dropped. Null when any value is
 * unknown or reserved.
 * @param {Catalog} catalog @param {string|null|undefined} value @param {{ prerequisites?: boolean }} [options]
 */
export function parseRequestedScopes(catalog, value, { prerequisites = true } = {}) {
  if (value !== undefined && value !== null && (typeof value !== "string" || value.length > MAX_SCOPE_PARAM)) return null;
  const out = new Set();
  for (const part of (value ?? "").split(" ").filter(Boolean)) {
    if (part === "offline_access") continue;
    if (catalog.full && part === catalog.full) out.add(part);
    else if (catalog.aliases.has(part)) for (const s of catalog.aliases.get(part) ?? []) out.add(s);
    else if (catalog.byScope.has(part)) out.add(part);
    else return null;
  }
  return prerequisites ? withPrerequisites(catalog, out) : out;
}

/** Concrete scopes of a set: the Full access marker becomes every non-sensitive scope; unknown values drop.
 * @param {Catalog} catalog @param {Iterable<string>} scopes */
export function concreteScopes(catalog, scopes) {
  const out = new Set();
  for (const s of scopes) {
    if (catalog.full && s === catalog.full) { for (const e of catalog.entries) if (!e.sensitive) out.add(e.scope); }
    else if (catalog.byScope.has(s)) out.add(s);
  }
  return out;
}

/** Canonical stored grant string: the Full access marker (if chosen), then every scope it does not cover, in catalog order.
 * @param {Catalog} catalog @param {Set<string>} scopes */
export function formatGrant(catalog, scopes) {
  const full = Boolean(catalog.full && scopes.has(catalog.full));
  const parts = full ? [/** @type {string} */ (catalog.full)] : [];
  for (const e of catalog.entries) if (scopes.has(e.scope) && (!full || e.sensitive)) parts.push(e.scope);
  return parts.join(" ");
}

/** What a stored grant string holds against the current catalog (concrete scopes). Tolerant of removed permissions.
 * @param {Catalog} catalog @param {string|null|undefined} stored */
export function parseGrant(catalog, stored) {
  if (typeof stored !== "string" || stored.length > MAX_SCOPE_PARAM * 4) return new Set();
  return concreteScopes(catalog, stored.split(" ").filter(Boolean));
}

/** Scopes this user may grant now: catalog scopes they hold as permissions; admin-only ones only for administrators.
 * @param {Catalog} catalog @param {Set<string>} permissions @param {{ admin: boolean }} who */
export function offeredScopes(catalog, permissions, { admin }) {
  return new Set(catalog.entries.filter(e => permissions.has(e.scope) && (!e.adminOnly || admin)).map(e => e.scope));
}

/**
 * The scopes a user ticked on the consent or connections page. Each value must be offered (or be the
 * Full access marker); implied scopes the user can hold are added. Throws ScopeError otherwise.
 * @param {Catalog} catalog @param {unknown[]} values @param {Set<string>} offered
 * @returns {{ stored: string, concrete: Set<string> }}
 */
export function selectScopes(catalog, values, offered) {
  if (!Array.isArray(values) || values.length > MAX_ENTRIES + 1 || !unique(values) ||
      !values.every(v => typeof v === "string" && (offered.has(v) || (catalog.full !== null && v === catalog.full))))
    throw new ScopeError("Invalid scope selection");
  const chosen = new Set(/** @type {string[]} */ (values));
  for (const s of withPrerequisites(catalog, chosen)) if (offered.has(s)) chosen.add(s);
  const concrete = new Set([...concreteScopes(catalog, chosen)].filter(s => offered.has(s)));
  if (!concrete.size) throw new ScopeError("Select at least one permission, or choose Deny");
  return { stored: formatGrant(catalog, chosen), concrete };
}

/** Grant ∩ current permissions (admin-only scopes need a current administrator).
 * @param {Catalog} catalog @param {Set<string>} granted @param {Set<string>} permissions @param {{ admin: boolean }} who */
export function effectiveScopes(catalog, granted, permissions, { admin }) {
  const offered = offeredScopes(catalog, permissions, { admin });
  return new Set([...granted].filter(s => offered.has(s)));
}

/** Concrete scopes as a canonical, space-separated string (the token's `scope`). @param {Catalog} catalog @param {Set<string>} scopes */
export function scopeString(catalog, scopes) {
  return catalog.entries.filter(e => scopes.has(e.scope)).map(e => e.scope).join(" ");
}

/**
 * RFC 6749 §6 narrowing on refresh: the scopes the client names (aliases and Full access expand,
 * prerequisites of named scopes come along) intersected with what the grant holds now. Null when a
 * value is unknown; an empty set when nothing remains.
 * @param {Catalog} catalog @param {string} value @param {Set<string>} granted
 */
export function narrowScopes(catalog, value, granted) {
  const requested = parseRequestedScopes(catalog, value, { prerequisites: false });
  if (!requested) return null;
  const named = new Set([...concreteScopes(catalog, requested)].filter(s => granted.has(s)));
  return new Set([...withPrerequisites(catalog, named)].filter(s => granted.has(s)));
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
/** An exact redirect URI for a public client: https, or http on a loopback host. No fragment or credentials.
 * @param {unknown} value @returns {string|null} */
export function validateRedirectUri(value) {
  if (typeof value !== "string" || !value || value.length > 2048 || CONTROL.test(value) || value.includes("*") || value.includes("#")) return null;
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.username || url.password || url.hash) return null;
  if (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname))) return value;
  return null;
}

/**
 * RFC 7591 public-client registration for MCP clients. Only `none` authentication, the code and
 * refresh grants, and scopes from registered MCP catalogs. Throws ScopeError with an RFC 7591 code.
 * Only the name, redirect URIs and scope are kept, each tightly bounded; every other field
 * (informational URIs, contacts, software statements, unknown extensions) is dropped, never stored.
 * @param {any} body @param {Set<string>} knownScopes every MCP catalog scope, alias and Full access marker
 * @returns {{ client_name: string, redirect_uris: string[], scope?: string }}
 */
export function parseRegistration(body, knownScopes) {
  const meta = message => new ScopeError(message, "invalid_client_metadata");
  if (!body || typeof body !== "object" || Array.isArray(body)) throw meta("Invalid client metadata");
  const uris = body.redirect_uris;
  if (!Array.isArray(uris) || !uris.length || uris.length > MAX_REDIRECT_URIS || !unique(uris) ||
      !uris.every(u => typeof u === "string" && u.length <= MAX_REDIRECT_URI && validateRedirectUri(u) !== null))
    throw new ScopeError("Use 1–" + MAX_REDIRECT_URIS + " exact HTTPS redirect URIs of at most " + MAX_REDIRECT_URI + " characters (HTTP only on loopback hosts)", "invalid_redirect_uri");
  if (body.token_endpoint_auth_method !== undefined && body.token_endpoint_auth_method !== "none")
    throw meta("Only public clients (token_endpoint_auth_method none) can register");
  if (body.grant_types !== undefined && (!Array.isArray(body.grant_types) || !body.grant_types.length ||
      !body.grant_types.every(g => g === "authorization_code" || g === "refresh_token") || !body.grant_types.includes("authorization_code")))
    throw meta("Only authorization_code and refresh_token grants are supported");
  if (body.response_types !== undefined && (!Array.isArray(body.response_types) || body.response_types.join(" ") !== "code"))
    throw meta("Only the code response type is supported");
  let name;
  try { name = text(body.client_name, MAX_CLIENT_NAME, "client name") || "MCP client"; } catch { throw meta("Invalid client_name (at most " + MAX_CLIENT_NAME + " characters)"); }
  const out = { client_name: name, redirect_uris: [...uris] };
  if (body.scope !== undefined) {
    if (typeof body.scope !== "string" || body.scope.length > MAX_REGISTRATION_SCOPE) throw meta("Invalid scope");
    const parts = body.scope.split(" ").filter(Boolean);
    if (!parts.every(s => s === "offline_access" || (!isReservedScope(s) && knownScopes.has(s))))
      throw meta("Registration scope must name MCP resource scopes only");
    if (parts.length) out.scope = parts.join(" ");
  }
  return out;
}
