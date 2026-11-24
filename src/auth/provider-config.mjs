/**
 * Managed social login providers (NATH-9): credential sources, enable/disable rules and
 * test sign-in evidence. Works on any D1-shaped `env.DB`.
 *
 * Every provider has exactly one credential source, resolved in this order:
 *   1. the NATHAN_PROVIDER_<ID> Worker secret, a JSON bundle written by
 *      `nathan providers add <id> --apply` (CLI);
 *   2. the encrypted nathan_oauth_providers D1 row (Identity Studio or the installer);
 *   3. the legacy GOOGLE_/GITHUB_CLIENT_ID and _CLIENT_SECRET Worker secrets.
 * A malformed Worker secret turns the provider off; it never falls back to an older source.
 * Credentials are never copied between sources. Studio refuses to save credentials while the
 * Worker secret exists, and reports lower-precedence credentials that are present but unused.
 *
 * Enabled flags and test records live in nathan_provider_state for every source. A test
 * counts only for the credential version (a keyed digest of the credentials) it ran against,
 * so a change through any path voids it. Secrets never leave this module except as Better
 * Auth config inside the Worker, and are never written to the audit log.
 */
import {
  PROVIDER_IDS, PROVIDERS, getProvider, callbackUrl, providerGuide, envBundleName,
  secretFieldNames, publicFieldNames, validateProviderCredentials, inputError
} from "../shared/providers.mjs";
import { decryptProviderSecret, decryptProviderField, sealProviderCredentials } from "./config-crypto.mjs";
import { mintAppleClientSecret } from "./apple-secret.mjs";
import { resolveUpstream } from "./nathan-upstream.mjs";

const CREDENTIAL_COLUMNS = "id,client_id,secret_cipher,config,secret_fields,updated_at,updated_by";
const STATE_COLUMNS = "id,enabled,updated_at,updated_by,tested_at,tested_by,tested_user,tested_version";
const TICKET_TTL = 600, EVIDENCE_TTL = 3600;

/**
 * @typedef {(env: any, actor: string, action: string, target: string, outcome: string) => Promise<void>} Audit
 * @typedef {{ audit: Audit, isAdmin?: (user: {id: string, email: string, role: string, emailVerified: boolean}) => Promise<boolean> }} Deps
 */

async function byId(env, sql) {
  const result = await env.DB.prepare(sql).all();
  return new Map((result.results || []).map(r => [r.id, r]));
}
function parseJson(text) {
  try { const v = JSON.parse(text || "{}"); return v && typeof v === "object" && !Array.isArray(v) ? v : {}; }
  catch { return {}; }
}
const utf8 = text => new TextEncoder().encode(text);
function base64url(bytes) {
  let raw = ""; for (const b of bytes) raw += String.fromCharCode(b);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function digest(text) {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(text))));
}
async function hmac(key, message) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, utf8(message)));
}

/**
 * Version of a credential: HMAC-SHA-256 over the provider id and its registry fields, under a
 * key derived from BETTER_AUTH_SECRET for this purpose only. Identical credentials have the
 * same version whichever source holds them; any field change yields a new version.
 */
export async function credentialVersion(env, id, values) {
  if (typeof env.BETTER_AUTH_SECRET !== "string" || env.BETTER_AUTH_SECRET.length < 32)
    throw Error("BETTER_AUTH_SECRET missing: provider credentials cannot be versioned");
  const key = await hmac(utf8(env.BETTER_AUTH_SECRET), "nathan:provider-credential-version-key:v1");
  const fields = getProvider(id).fields.map(f => [f.name, typeof values?.[f.name] === "string" ? values[f.name] : null]);
  return base64url(await hmac(key, JSON.stringify(["nathan:provider-credential:v1", id, fields])));
}

const deleteCommand = name => "npx wrangler secret delete " + name + " --name <your Nathan Auth Worker>";
function legacyNames(id) { return PROVIDERS[id].legacyEnv || null; }
function legacyCredentials(env, id) {
  const legacy = legacyNames(id);
  return legacy && env[legacy[0]] && env[legacy[1]] ? { clientId: env[legacy[0]], clientSecret: env[legacy[1]] } : null;
}
function hasWorkerSecret(env, id) {
  const bundle = env[envBundleName(id)];
  return typeof bundle === "string" && bundle.length > 0;
}
function workerSecretManaged(id) {
  const name = PROVIDERS[id].name, secret = envBundleName(id);
  return name + " is managed by the Worker secret " + secret + " (CLI), which takes precedence over Studio. " +
    "Rotate it with `node scripts/nathan.mjs providers add " + id + " --apply`, or delete it with `" + deleteCommand(secret) +
    "` and then save the credentials here. Nothing was saved.";
}

async function decryptRow(env, row) {
  if (!env.NATHAN_CONFIG_KEY) throw Error("Configured provider cannot be decrypted: NATHAN_CONFIG_KEY missing");
  const values = { clientId: row.client_id, ...parseJson(row.config) };
  const sealed = parseJson(row.secret_fields);
  for (const name of secretFieldNames(row.id)) {
    if (typeof sealed[name] === "string") values[name] = await decryptProviderField(row.id, name, sealed[name], env.NATHAN_CONFIG_KEY);
    else if (name === "clientSecret" && row.secret_cipher) // pre-0012 v1 ciphertext
      values[name] = await decryptProviderSecret(row.id, row.secret_cipher, env.NATHAN_CONFIG_KEY);
    else throw Error("Stored provider is missing an encrypted secret field");
  }
  return values;
}

/** The one credential source for `id`, with its values (null when unusable). */
async function resolveSource(env, id, row) {
  if (hasWorkerSecret(env, id)) {
    try { return { source: "worker-secret", values: validateProviderCredentials(id, JSON.parse(env[envBundleName(id)])), error: null }; }
    catch {
      return { source: "worker-secret", values: null, error: "The Worker secret " + envBundleName(id) + " is not a valid " +
        PROVIDERS[id].name + " credential bundle, so " + PROVIDERS[id].name + " sign-in is off. Fix it with `node scripts/nathan.mjs providers add " +
        id + " --apply`." };
    }
  }
  if (row) {
    try { return { source: "encrypted-d1", values: await decryptRow(env, row), error: null }; }
    catch (cause) { return { source: "encrypted-d1", values: null, error: "Stored credentials cannot be decrypted. Check NATHAN_CONFIG_KEY.", cause }; }
  }
  const legacy = legacyCredentials(env, id);
  if (legacy) return { source: "legacy-worker-secret", values: legacy, error: null };
  return { source: "not-configured", values: null, error: null };
}

/** Credential source, state and current credential version for each provider. */
async function inventory(env, only) {
  const [credentials, states] = await Promise.all([
    byId(env, "SELECT " + CREDENTIAL_COLUMNS + " FROM nathan_oauth_providers"),
    byId(env, "SELECT " + STATE_COLUMNS + " FROM nathan_provider_state")
  ]);
  const ids = only ? [only] : PROVIDER_IDS;
  return Promise.all(ids.map(async id => {
    const row = credentials.get(id) || null, state = states.get(id) || null;
    const resolved = await resolveSource(env, id, row);
    return {
      id, row, state, ...resolved,
      // A configured provider is enabled until an administrator disables it.
      enabled: Boolean(resolved.values) && (state ? state.enabled === 1 : true),
      version: resolved.values ? await credentialVersion(env, id, resolved.values) : null
    };
  }));
}
const testCounts = p => Boolean(p.state?.tested_version && p.version && p.state.tested_version === p.version);

/**
 * Better Auth wants {clientId, clientSecret}; Apple's secret is minted from the .p8 key. The Nathan
 * upstream (NATH-51) also needs its parent's validated discovery document, cached per isolate; a
 * parent whose discovery fails is unusable (`unusable_credentials`) until it recovers.
 */
async function resolve(env, id, values) {
  if (id === "apple") return { clientId: values.clientId, clientSecret: await mintAppleClientSecret(values) };
  if (id === "nathan") return resolveUpstream(values, { selfIssuer: env.NATHAN_ISSUER });
  return { clientId: values.clientId, clientSecret: values.clientSecret };
}

/** Read on every auth request, so disable and rotation take effect immediately. */
export async function loadSocialProviderCredentials(env) {
  return (await loadSocialProviderState(env)).credentials;
}

/** Why a configured, enabled provider cannot be used (nathan_provider_health.reason). */
const unusableReason = source => source === "worker-secret" ? "invalid_worker_secret" : "decrypt_failed";
/** One audit row per provider per hour while it stays unavailable (NATH-17). */
const UNAVAILABLE_AUDIT_WINDOW = 3600;

/**
 * NATH-17: credentials for every usable, enabled provider, and the configured, enabled providers
 * that cannot be used. Each provider is isolated: an undecryptable D1 row, a malformed Worker secret
 * or an Apple key that cannot sign turns only that provider off. It is never replaced by a
 * lower-precedence source (resolveSource stops at the first configured source). The unavailable
 * provider is recorded in nathan_provider_health (reason code only, no secret) for Studio (the
 * public /healthz only counts it) and audited at most once per window; recovery or an administrator's disable clears it.
 * Health bookkeeping never fails a request.
 */
export async function loadSocialProviderState(env) {
  const [credentials, states, health] = await Promise.all([
    byId(env, "SELECT " + CREDENTIAL_COLUMNS + " FROM nathan_oauth_providers"),
    byId(env, "SELECT id,enabled FROM nathan_provider_state"),
    byId(env, "SELECT id,reason,audited_at FROM nathan_provider_health").catch(() => null)
  ]);
  const out = {}, unavailable = [];
  for (const id of PROVIDER_IDS) {
    if (states.get(id)?.enabled === 0) continue;
    const { source, values } = await resolveSource(env, id, credentials.get(id));
    if (!values) {
      if (source !== "not-configured") unavailable.push({ id, reason: unusableReason(source) });
      continue;
    }
    try { out[id] = await resolve(env, id, values); }
    catch { unavailable.push({ id, reason: "unusable_credentials" }); }
  }
  if (health) await recordProviderHealth(env, unavailable, health).catch(() => {});
  return { credentials: out, unavailable };
}

/** Writes only on a change or when an audit is due, so steady state costs no D1 writes. */
async function recordProviderHealth(env, unavailable, health) {
  const now = Math.floor(Date.now() / 1000);
  for (const { id, reason } of unavailable) {
    const row = health.get(id);
    if (!row || row.reason !== reason) {
      await env.DB.prepare(
        "INSERT INTO nathan_provider_health(id,reason) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET reason=excluded.reason, last_failed_at=unixepoch()"
      ).bind(id, reason).run();
    }
    if (row && row.audited_at !== null && row.audited_at > now - UNAVAILABLE_AUDIT_WINDOW) continue;
    // Compare-and-set, so concurrent requests write one audit row per window.
    const due = await env.DB.prepare(
      "UPDATE nathan_provider_health SET audited_at=unixepoch(), last_failed_at=unixepoch() WHERE id=? AND (audited_at IS NULL OR audited_at<=unixepoch()-?) RETURNING id"
    ).bind(id, UNAVAILABLE_AUDIT_WINDOW).first();
    if (due) await env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,'system:providers','oauth_provider_unavailable',?,?)")
      .bind(crypto.randomUUID(), id, "skipped_" + reason).run();
  }
  for (const id of health.keys()) {
    if (unavailable.some(u => u.id === id)) continue;
    const cleared = await env.DB.prepare("DELETE FROM nathan_provider_health WHERE id=? RETURNING id").bind(id).first();
    if (cleared) await env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,'system:providers','oauth_provider_unavailable',?,'cleared')")
      .bind(crypto.randomUUID(), id).run();
  }
}

/** Current Nathan administrators, as decided by the injected admin predicate. */
async function currentAdmins(env, isAdmin) {
  if (!isAdmin) return [];
  const result = await env.DB.prepare(
    'SELECT "id","email","emailVerified","role" FROM "user" WHERE "role"=\'admin\' AND "emailVerified"=1 LIMIT 500'
  ).all();
  const admins = [];
  for (const u of result.results || []) {
    const user = { id: u.id, email: u.email, role: u.role, emailVerified: u.emailVerified === 1 || u.emailVerified === true };
    if (await isAdmin(user)) admins.push({ id: u.id, email: String(u.email).trim().toLowerCase() });
  }
  return admins;
}
/** Non-social sign-in paths a current administrator can actually use. */
async function adminRecoveryMethods(env, admins) {
  const methods = [];
  if (!admins.length) return methods;
  if (env.ENABLE_PASSWORD === "true" && await env.DB.prepare(
    'SELECT 1 AS ok FROM "account" WHERE "providerId"=\'credential\' AND "password" IS NOT NULL ' +
    'AND "userId" IN (SELECT value FROM json_each(?)) LIMIT 1'
  ).bind(JSON.stringify(admins.map(a => a.id))).first()) methods.push("password");
  const domains = [...new Set(admins.map(a => a.email.split("@")[1]).filter(Boolean))];
  if (env.ENTERPRISE_SSO === "true" && domains.length && await env.DB.prepare(
    'SELECT 1 AS ok FROM "ssoProvider" WHERE "domainVerified"=1 AND lower("domain") IN (SELECT value FROM json_each(?)) LIMIT 1'
  ).bind(JSON.stringify(domains)).first()) methods.push("enterprise-sso");
  return methods;
}

/** Non-secret status for Identity Studio. */
export async function providerStatus(env, deps = {}) {
  const [providers, admins, health] = await Promise.all([inventory(env), currentAdmins(env, deps.isAdmin),
    byId(env, "SELECT id,reason,first_failed_at FROM nathan_provider_health").catch(() => new Map())]);
  const adminIds = new Set(admins.map(a => a.id));
  return providers.map(p => {
    const { id, row, state, source } = p;
    const name = PROVIDERS[id].name, secret = envBundleName(id), legacy = legacyNames(id);
    const shown = p.values || (source === "encrypted-d1" && row ? { clientId: row.client_id, ...parseJson(row.config) } : {});
    const values = {};
    for (const field of publicFieldNames(id)) if (typeof shown[field] === "string") values[field] = shown[field];
    const sealed = row ? parseJson(row.secret_fields) : {};
    const secretsSet = source === "encrypted-d1" ? secretFieldNames(id).filter(n => sealed[n] || (n === "clientSecret" && row.secret_cipher))
      : p.values ? secretFieldNames(id) : [];
    const tested = testCounts(p), testedByAdmin = tested && adminIds.has(state.tested_user);
    const shadowed = [];
    if (source === "worker-secret" && row) shadowed.push({ source: "encrypted-d1", updatedAt: row.updated_at });
    if (source !== "legacy-worker-secret" && legacyCredentials(env, id)) shadowed.push({ source: "legacy-worker-secret", names: [...legacy] });
    const notices = [];
    if (source === "worker-secret") notices.push(name + " is managed by the Worker secret " + secret + ". Rotate it with `node scripts/nathan.mjs providers add " +
      id + " --apply`. Studio cannot save " + name + " credentials while that secret exists.");
    for (const s of shadowed) {
      if (s.source === "encrypted-d1") notices.push("Credentials saved in Identity Studio (" + new Date(s.updatedAt * 1000).toISOString().slice(0, 10) +
        ") are not used: the Worker secret " + secret + " takes precedence. To manage " + name + " in Studio, run `" + deleteCommand(secret) +
        "` and save the credentials here again.");
      else notices.push("The legacy Worker secrets " + legacy.join(" and ") + " are not used: " +
        (source === "worker-secret" ? "the Worker secret " + secret : "the credentials saved in Identity Studio") +
        " take precedence. Remove them with `" + deleteCommand(legacy[0]) + "` and `" + deleteCommand(legacy[1]) + "`.");
    }
    if (state?.tested_at && !tested) notices.push(name + " credentials changed after the last successful test sign-in. Run a new test.");
    if (tested && !testedByAdmin) notices.push("The last test sign-in used an account that is not a current Nathan administrator. It shows " +
      name + " works, but does not count toward keeping administrator access.");
    // NATH-17: configured and not disabled by an administrator, but its credentials cannot be used.
    const switchedOn = state ? state.enabled === 1 : true;
    const marked = health.get(id);
    const unavailable = source !== "not-configured" && switchedOn && (!p.values || marked)
      ? { reason: marked?.reason ?? unusableReason(source), since: marked?.first_failed_at ?? null } : null;
    if (unavailable) notices.push(name + " sign-in is unavailable: its credentials cannot be used, so the button is hidden and other methods keep working. " +
      "Save new credentials to repair it, or disable it.");
    const guide = providerGuide(id, env.NATHAN_ISSUER);
    // NATH-51: the upstream's OAuth client lives in the configured parent's own Identity Studio.
    if (id === "nathan" && typeof values.issuer === "string") {
      try { guide.consoleUrl = new URL(values.issuer).origin + "/studio"; } catch {}
    }
    return {
      ...guide,
      enabled: p.enabled,
      available: source !== "not-configured" && switchedOn && !unavailable,
      unavailable,
      configured: source !== "not-configured",
      source,
      secretName: source === "worker-secret" ? secret : source === "legacy-worker-secret" ? legacy.join(", ") : null,
      values,
      secretsSet,
      clientIdHint: typeof values.clientId === "string" ? values.clientId.slice(0, 5) + "…" : null,
      updatedAt: source === "encrypted-d1" ? row.updated_at : null,
      testedAt: tested ? state.tested_at : null,
      testedByAdmin,
      testStale: Boolean(state?.tested_at) && !tested,
      shadowed,
      notices,
      error: p.error,
      canSaveInStudio: Boolean(env.NATHAN_CONFIG_KEY) && source !== "worker-secret",
      canUpdate: Boolean(env.NATHAN_CONFIG_KEY) && source !== "worker-secret"
    };
  });
}

async function validated(env, id, input) {
  const values = validateProviderCredentials(id, input);
  // Prove an Apple key can actually sign before storing it.
  if (id === "apple") await mintAppleClientSecret(values);
  // NATH-51: prove the parent publishes a usable discovery document for exactly this issuer.
  if (id === "nathan") await resolveUpstream(values, { selfIssuer: env.NATHAN_ISSUER, fresh: true });
  return values;
}

/**
 * Add or rotate one provider's credentials in D1. Refused while the provider's CLI Worker
 * secret exists. Saving enables the provider, clears its test record and voids open test
 * tickets, in one batch. Every attempt is audited, including validation failures.
 * @param {Deps} deps
 */
export async function upsertSocialProvider(env, input, actor, deps) {
  const { audit } = deps;
  const id = PROVIDER_IDS.includes(input?.id) ? input.id : null;
  const target = id ?? "unsupported";
  await audit(env, actor, "oauth_provider_update", target, "attempted");
  const fail = async (outcome, error) => {
    await audit(env, actor, "oauth_provider_update", target, outcome);
    throw error;
  };
  if (!id) return fail("failed_validation", inputError("Unsupported social provider"));
  if (hasWorkerSecret(env, id)) return fail("denied_worker_secret", inputError(workerSecretManaged(id)));
  let values;
  try { values = await validated(env, id, input); } catch (e) { return fail("failed_validation", e); }
  if (!env.NATHAN_CONFIG_KEY)
    return fail("failed_config_key", inputError("NATHAN_CONFIG_KEY missing: provision the encryption key before updating providers"));
  try {
    const sealed = await sealProviderCredentials(id, values, env.NATHAN_CONFIG_KEY);
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO nathan_oauth_providers(id,client_id,secret_cipher,config,secret_fields,updated_at,updated_by) " +
        "VALUES (?,?,NULL,?,?,unixepoch(),?) ON CONFLICT(id) DO UPDATE SET " +
        "client_id=excluded.client_id,secret_cipher=NULL,config=excluded.config,secret_fields=excluded.secret_fields," +
        "updated_at=unixepoch(),updated_by=excluded.updated_by"
      ).bind(id, sealed.clientId, sealed.config, sealed.secretFields, actor),
      env.DB.prepare(
        "INSERT INTO nathan_provider_state(id,enabled,updated_at,updated_by) VALUES (?,1,unixepoch(),?) ON CONFLICT(id) DO UPDATE SET " +
        "enabled=1,updated_at=unixepoch(),updated_by=excluded.updated_by,tested_at=NULL,tested_by=NULL,tested_user=NULL,tested_version=NULL"
      ).bind(id, actor),
      env.DB.prepare("UPDATE nathan_provider_test_tickets SET consumed_at=unixepoch() WHERE provider=? AND consumed_at IS NULL").bind(id)
    ]);
  } catch (e) { return fail("failed", e); }
  await audit(env, actor, "oauth_provider_update", id, "succeeded");
  return { id, enabled: true, callbackUrl: callbackUrl(env.NATHAN_ISSUER, id),
    note: "Credentials are encrypted in your D1 database. Run a test sign-in before relying on this provider." };
}

/**
 * Disabling writes only if, afterwards, another enabled provider has a test sign-in by a
 * current administrator against its current credentials, or password or enterprise SSO sign-in
 * is enabled and usable by a current administrator. The check and the write are one
 * conditional statement, so concurrent disables cannot both pass.
 */
const DISABLE_IF_ANOTHER_METHOD_REMAINS =
  "INSERT INTO nathan_provider_state(id,enabled,updated_at,updated_by) SELECT ?1,0,unixepoch(),?2 " +
  "WHERE ?3=1 OR EXISTS (SELECT 1 FROM nathan_provider_state s WHERE s.id<>?1 AND s.enabled=1 " +
  "AND s.tested_version IS NOT NULL AND s.tested_version=json_extract(?4,'$.'||s.id) " +
  "AND s.tested_user IN (SELECT value FROM json_each(?5))) " +
  "ON CONFLICT(id) DO UPDATE SET enabled=0,updated_at=unixepoch(),updated_by=excluded.updated_by";

/** @param {Deps} deps */
export async function setSocialProviderEnabled(env, input, actor, deps) {
  const { audit } = deps;
  const id = input?.id;
  if (!PROVIDER_IDS.includes(id) || typeof input?.enabled !== "boolean") {
    // Never echo attacker-controlled input into the audit target.
    await audit(env, actor, "oauth_provider_state_change", PROVIDER_IDS.includes(id) ? id : "invalid", "rejected_invalid_input");
    throw inputError("Invalid provider state update");
  }
  const action = input.enabled ? "oauth_provider_enable" : "oauth_provider_disable";
  const deny = async (outcome, message) => {
    await audit(env, actor, action, id, outcome);
    throw inputError(message);
  };
  if (input.confirm !== "CONFIRM " + (input.enabled ? "ENABLE " : "DISABLE ") + id)
    return deny("denied_confirmation", "Exact provider confirmation required");
  const providers = await inventory(env);
  const target = providers.find(p => p.id === id);
  if (input.enabled ? !target.values : target.source === "not-configured")
    return deny("denied_not_configured", "No usable credentials for " + PROVIDERS[id].name + ": configure the provider first");
  if (!input.enabled && !target.values) {
    // NATH-17: a configured provider whose credentials cannot be used is no login method anyone has,
    // so turning it off can never remove the administrators' last way in.
    await env.DB.prepare(
      "INSERT INTO nathan_provider_state(id,enabled,updated_at,updated_by) VALUES (?,0,unixepoch(),?) " +
      "ON CONFLICT(id) DO UPDATE SET enabled=0,updated_at=unixepoch(),updated_by=excluded.updated_by"
    ).bind(id, actor).run();
  } else if (input.enabled) {
    await env.DB.prepare(
      "INSERT INTO nathan_provider_state(id,enabled,updated_at,updated_by) VALUES (?,1,unixepoch(),?) " +
      "ON CONFLICT(id) DO UPDATE SET enabled=1,updated_at=unixepoch(),updated_by=excluded.updated_by"
    ).bind(id, actor).run();
  } else {
    const admins = await currentAdmins(env, deps.isAdmin);
    const recovery = await adminRecoveryMethods(env, admins);
    const versions = Object.fromEntries(providers.filter(p => p.version).map(p => [p.id, p.version]));
    const written = await env.DB.prepare(DISABLE_IF_ANOTHER_METHOD_REMAINS)
      .bind(id, actor, recovery.length ? 1 : 0, JSON.stringify(versions), JSON.stringify(admins.map(a => a.id))).run();
    if (!written?.meta?.changes)
      return deny("denied_last_method", "Cannot disable the last login method administrators can use. Another enabled provider needs a " +
        "successful test sign-in by a current Nathan administrator with its current credentials, or password or enterprise SSO sign-in " +
        "must be enabled and usable by an administrator. Run a test sign-in as an administrator first.");
  }
  await audit(env, actor, action, id, "succeeded");
  return { id, enabled: input.enabled };
}

/**
 * Starts a test sign-in for an enabled provider, bound to its current credential version.
 * The admin's browser then signs in through that provider with callbackURL; completion
 * needs the ticket AND callback evidence for the same credential version.
 * @param {Deps} deps
 */
export async function beginProviderTest(env, input, actor, deps) {
  const id = input?.id;
  const refuse = async (target, outcome, message) => {
    await deps.audit(env, actor, "oauth_provider_test_begin", target, outcome);
    throw inputError(message);
  };
  if (!PROVIDER_IDS.includes(id)) await refuse("invalid", "rejected_invalid_input", "Unsupported OAuth provider");
  getProvider(id);
  const [provider] = await inventory(env, id);
  if (!provider.enabled) await refuse(id, "rejected_disabled", "Provider must be configured and enabled before a test sign-in");
  try { await resolve(env, id, provider.values); }
  catch { await refuse(id, "rejected_unusable_credentials", PROVIDERS[id].name + " credentials cannot be used for sign-in"); }
  const ticket = base64url(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.prepare("DELETE FROM nathan_provider_test_tickets WHERE expires_at<unixepoch()-86400").run();
  await env.DB.prepare(
    "INSERT INTO nathan_provider_test_tickets(ticket_hash,provider,admin_user_id,credential_version,expires_at) VALUES (?,?,?,?,unixepoch()+?)"
  ).bind(await digest(ticket), id, actor, provider.version, TICKET_TTL).run();
  await deps.audit(env, actor, "oauth_provider_test", id, "attempted");
  return { id, ticket, callbackURL: "/studio/providers/test-complete?ticket=" + ticket };
}

/** Called from the Better Auth after-hook when a social callback creates a session. */
export async function recordProviderSignIn(env, { providerId, sessionId, userId }) {
  if (!PROVIDER_IDS.includes(providerId) || typeof sessionId !== "string" || typeof userId !== "string") return;
  const [provider] = await inventory(env, providerId);
  if (!provider.version) return;
  await env.DB.prepare("DELETE FROM nathan_provider_signins WHERE created_at<unixepoch()-?").bind(EVIDENCE_TTL).run();
  await env.DB.prepare(
    "INSERT INTO nathan_provider_signins(session_id,provider,user_id,credential_version,created_at) VALUES (?,?,?,?,unixepoch()) " +
    "ON CONFLICT(session_id) DO UPDATE SET provider=excluded.provider,user_id=excluded.user_id," +
    "credential_version=excluded.credential_version,created_at=unixepoch()"
  ).bind(sessionId, providerId, userId, provider.version).run();
}

/**
 * Completes a test sign-in: the single-use, unexpired ticket must match a session that a
 * callback from the same provider created after the ticket was issued, and the ticket, the
 * callback and the provider's current credentials must all have the same version.
 * `adminVerified` says whether the account that signed in is a current administrator; only
 * such a test protects the provider under the last-login-method rule.
 * @param {Deps} deps
 */
export async function completeProviderTest(env, ticket, session, deps) {
  const { audit } = deps;
  if (typeof ticket !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(ticket)) throw Error("Invalid or expired test ticket");
  const claimed = await env.DB.prepare(
    "UPDATE nathan_provider_test_tickets SET consumed_at=unixepoch() WHERE ticket_hash=? AND consumed_at IS NULL " +
    "AND expires_at>=unixepoch() RETURNING provider,admin_user_id,credential_version,created_at"
  ).bind(await digest(ticket)).first();
  if (!claimed) throw Error("Invalid or expired test ticket");
  const fail = async (outcome, message) => {
    await audit(env, claimed.admin_user_id, "oauth_provider_test", claimed.provider, outcome);
    throw Error(message);
  };
  const evidence = session && typeof session.sessionId === "string" ? await env.DB.prepare(
    "SELECT credential_version FROM nathan_provider_signins WHERE session_id=? AND user_id=? AND provider=? AND created_at>=?"
  ).bind(session.sessionId, session.userId, claimed.provider, claimed.created_at).first() : null;
  if (!evidence) return fail("failed", "No sign-in evidence from this provider for the current session");
  const [current] = await inventory(env, claimed.provider);
  if (current.version !== claimed.credential_version || evidence.credential_version !== claimed.credential_version)
    return fail("failed_credentials_changed", "Provider credentials changed since the test started; start a new test");
  await env.DB.prepare(
    "INSERT INTO nathan_provider_state(id,enabled,updated_at,updated_by,tested_at,tested_by,tested_user,tested_version) " +
    "VALUES (?1,1,unixepoch(),?2,unixepoch(),?2,?3,?4) ON CONFLICT(id) DO UPDATE SET " +
    "tested_at=unixepoch(),tested_by=excluded.tested_by,tested_user=excluded.tested_user,tested_version=excluded.tested_version"
  ).bind(claimed.provider, claimed.admin_user_id, session.userId, claimed.credential_version).run();
  const adminVerified = (await currentAdmins(env, deps.isAdmin)).some(a => a.id === session.userId);
  await audit(env, claimed.admin_user_id, "oauth_provider_test", claimed.provider, "succeeded");
  return { id: claimed.provider, tested: true, adminVerified };
}
