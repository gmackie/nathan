/**
 * NATH-24: the published contract of the Identity Studio JSON API v1 (`/studio/api/v1/*`).
 *
 * This module imports nothing but zod, so the Studio SPA (NATH-26) and fleet clients (NATH-27) can
 * share it. It holds the response envelope, the stable error codes and one input schema per action.
 *
 * The schemas describe shape (types, bounds, identifier syntax). The service functions behind each
 * route remain the authority: they repeat every check, look up state, and audit refused attempts.
 * Bodies are loose objects, so a field the schema does not know about passes through unchanged,
 * exactly as the service would see it from the legacy `/studio/api/*` route.
 */
import { z } from "zod";

// ---- Envelope and errors ------------------------------------------------------------------------

/** Stable machine-readable error codes. Messages may change; codes do not. */
export const STUDIO_ERROR_CODES = [
  "unauthenticated",        // 401 no Nathan session
  "cross_origin",           // 403 write without same-origin Origin, or Sec-Fetch-Site: cross-site
  "not_admin",              // 403 signed in, but not a verified, granted administrator
  "enrollment_incomplete",  // 403 admin bootstrap or authenticator enrollment incomplete
  "step_up_required",       // 403 policy requires a passkey verification in the last 15 minutes
  "unsupported_media_type", // 415 write without Content-Type: application/json
  "payload_too_large",      // 413 body over the route's byte limit
  "invalid_json",           // 400 body is not JSON
  "validation_failed",      // 400 input does not match the route's schema (see error.issues)
  "not_found",              // 404 unknown route, or unknown resource on a read
  "method_not_allowed",     // 405 known route, other method (see Allow)
  "operation_rejected",     // 409 the service refused the change (safe message, never input values)
  "unavailable"             // 503 feature not configured (for example no verified domain realm)
] as const;
export type StudioErrorCode = typeof STUDIO_ERROR_CODES[number];

export const studioIssue = z.object({ path: z.string(), code: z.string(), message: z.string() });
export const studioError = z.object({
  code: z.enum(STUDIO_ERROR_CODES),
  message: z.string(),
  issues: z.array(studioIssue).optional()
});
export const studioFailure = z.object({ ok: z.literal(false), error: studioError });
export const studioSuccess = <T extends z.ZodType>(data: T) => z.object({ ok: z.literal(true), data });
export type StudioIssue = z.infer<typeof studioIssue>;
export type StudioErrorBody = z.infer<typeof studioError>;
export type StudioFailure = z.infer<typeof studioFailure>;
export type StudioSuccess<T> = { ok: true; data: T };
export type StudioResponse<T> = StudioSuccess<T> | StudioFailure;

// ---- Shared pieces --------------------------------------------------------------------------------

const text = (max: number) => z.string().max(max);
const confirm = text(600);
/** Application ids (nathan_applications.id). */
export const appId = z.string().regex(/^[a-z][a-z0-9-]{0,62}$/, "Lowercase letters, digits and dashes, starting with a letter");
/** Enterprise SSO / SAML / SCIM connection ids. */
export const connectionId = z.string().regex(/^[a-z][a-z0-9-]{1,62}$/, "Lowercase letters, digits and dashes, 2-63 characters");
export const emailAddress = text(254);
export const userId = text(256);
const fingerprint = text(200);
/** An HTTPS resource identifier (token audience, MCP resource); the service checks the origin rules. */
const resourceIdentifier = text(2048);

/** No input (reads without query parameters). Unknown query parameters are ignored. */
export const noInput = z.looseObject({});

// ---- Administrators -------------------------------------------------------------------------------

export const directoryQuery = z.looseObject({ q: text(254).optional() });
export const adminGrantInput = z.looseObject({ email: emailAddress, id: userId.optional(), confirm });
export const adminRevokeInput = z.looseObject({ id: userId, confirm });

// ---- OAuth clients and protected applications -----------------------------------------------------

export const clientCreateInput = z.looseObject({
  name: z.string().min(1).max(100),
  kind: z.enum(["external", "worker", "gateway", "mcp", "native"]),
  redirectUri: text(2048),
  publicClient: z.boolean().optional()
});
export const clientStatusInput = z.looseObject({
  clientId: z.string().regex(/^[A-Za-z0-9._-]{1,200}$/),
  disabled: z.boolean()
});
export const applicationUpsertInput = z.looseObject({
  id: appId,
  hostname: text(253),
  roles: z.array(z.never()).optional()
});
export const applicationStatusInput = z.looseObject({ id: appId, enabled: z.boolean(), confirm });

// ---- Domain realm ---------------------------------------------------------------------------------

const realmKind = z.enum(["web", "worker", "gateway", "external"]);
export const realmClientInput = z.looseObject({
  hostname: text(253),
  kind: realmKind,
  clientName: z.string().min(1).max(100).optional(),
  callbackPath: text(512).optional(),
  publicClient: z.boolean().optional()
});
export const realmClientBatchInput = z.looseObject({
  confirm: z.literal("REGISTER DOMAIN CLIENTS"),
  hostnames: z.union([text(8192), z.array(text(253)).max(20)]),
  kind: realmKind.optional(),
  callbackPath: text(512).optional(),
  publicClient: z.boolean().optional()
});

// ---- Social sign-in providers ---------------------------------------------------------------------

const providerId = z.string().regex(/^[a-z][a-z0-9-]{0,62}$/);
export const providerUpsertInput = z.looseObject({ id: providerId, fields: z.record(z.string(), z.string().max(8192)) });
export const providerStatusInput = z.looseObject({ id: providerId, enabled: z.boolean(), confirm });
export const providerTestInput = z.looseObject({ id: providerId });

// ---- Enterprise SSO (OIDC), inbound SAML, SAML IdP ------------------------------------------------

export const ssoOidcRegisterInput = z.looseObject({
  providerId: connectionId,
  domain: text(253),
  issuer: text(2048),
  clientId: z.string().min(1).max(512),
  clientSecret: z.string().min(8).max(4096)
});
export const ssoDomainInput = z.looseObject({ providerId: connectionId });

const samlMetadata = { metadataXml: text(150_000).optional(), metadataUrl: text(2048).optional() };
export const samlPreviewInput = z.looseObject({ providerId: connectionId.optional(), ...samlMetadata });
export const samlConnectionCreateInput = z.looseObject({
  providerId: connectionId,
  domain: text(253),
  provisioning: text(64).optional(),
  attributePreset: text(64).optional(),
  ...samlMetadata
});
export const samlStatusInput = z.looseObject({ providerId: connectionId, enabled: z.boolean(), confirm });
export const samlProvisioningInput = z.looseObject({ providerId: connectionId, provisioning: text(64), confirm });
export const samlCertificateAddInput = z.looseObject({ providerId: connectionId, certificate: text(20_000) });
export const samlCertificateRetireInput = z.looseObject({ providerId: connectionId, sha256: fingerprint, confirm });

const spId = z.string().regex(/^[a-z][a-z0-9-]{1,62}$/);
export const samlIdpInput = z.discriminatedUnion("op", [
  z.looseObject({ op: z.literal("sp.preview"), ...samlMetadata }),
  z.looseObject({ op: z.literal("sp.create"), id: spId, confirm }),
  z.looseObject({ op: z.literal("sp.update"), id: spId, confirm }),
  z.looseObject({ op: z.literal("sp.status"), id: spId, enabled: z.boolean(), confirm }),
  z.looseObject({ op: z.literal("key.generate"), bits: z.number().int().optional(), confirm }),
  z.looseObject({ op: z.literal("key.activate"), sha256: fingerprint, confirm }),
  z.looseObject({ op: z.literal("key.retire"), sha256: fingerprint, confirm })
]);

// ---- SCIM -----------------------------------------------------------------------------------------

export const scimConnectionCreateInput = z.looseObject({
  id: connectionId,
  domain: text(253),
  organizationId: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/).optional()
});
export const scimStatusInput = z.looseObject({ id: connectionId, enabled: z.boolean(), confirm });
export const scimRotateInput = z.looseObject({ id: connectionId, confirm });
export const scimConnectionQuery = z.looseObject({
  id: connectionId,
  reviewState: text(32).optional(),
  reviewOffset: z.string().regex(/^\d{1,9}$/).optional()
});
export const scimOutboxQuery = z.looseObject({ id: connectionId });
export const scimSettingsInput = z.looseObject({ id: connectionId, linking: z.boolean(), jit: z.boolean(), confirm });
export const scimMappingInput = z.discriminatedUnion("op", [
  z.looseObject({ op: z.literal("map"), connection: connectionId, refType: z.enum(["id", "externalId"]), ref: z.string().min(1).max(256), group: text(64), confirm }),
  z.looseObject({ op: z.literal("unmap"), connection: connectionId, group: text(64), confirm })
]);
export const scimUserInput = z.discriminatedUnion("op", [
  z.looseObject({ op: z.literal("approve"), connection: connectionId, review: text(200), confirm }),
  z.looseObject({ op: z.literal("dismiss"), connection: connectionId, review: text(200), confirm }),
  z.looseObject({ op: z.literal("keep-active"), connection: connectionId, scimId: text(200), confirm }),
  z.looseObject({ op: z.literal("unlink"), connection: connectionId, scimId: text(200), confirm })
]);
export const scimOutboxInput = z.looseObject({
  op: z.literal("skip"),
  connection: connectionId,
  kind: z.enum(["User", "Group"]),
  id: text(64),
  seq: z.number().int().nonnegative(),
  confirm
});

// ---- Roles and RBAC -------------------------------------------------------------------------------

const key = text(200);
const description = text(200).nullable().optional();
export const rbacQuery = z.looseObject({ app: appId });
export const rbacGroupQuery = z.looseObject({ id: text(64) });
export const rbacInput = z.discriminatedUnion("op", [
  z.looseObject({ op: z.literal("access_mode"), app: appId, accessMode: text(64), confirm: confirm.optional() }),
  z.looseObject({ op: z.literal("permission.upsert"), app: appId, key, description }),
  z.looseObject({ op: z.literal("permission.delete"), app: appId, key }),
  z.looseObject({ op: z.literal("role.upsert"), app: appId, key, description, permissions: z.array(key).max(500) }),
  z.looseObject({ op: z.literal("role.delete"), app: appId, key, confirm }),
  z.looseObject({ op: z.literal("group.upsert"), id: text(64), name: z.string().min(1).max(100), description }),
  z.looseObject({ op: z.literal("group.delete"), id: text(64), confirm }),
  z.looseObject({ op: z.literal("member.add"), group: text(64), email: emailAddress }),
  z.looseObject({ op: z.literal("member.remove"), group: text(64), userId: userId.optional(), email: emailAddress.optional() }),
  z.looseObject({ op: z.literal("grant.create"), app: appId, role: key, principalType: z.enum(["user", "group"]),
    email: emailAddress.optional(), group: text(64).optional() }),
  z.looseObject({ op: z.literal("grant.revoke"), app: appId, id: text(200) }),
  z.looseObject({ op: z.literal("sync"), app: appId, manifest: z.record(z.string(), z.unknown()),
    prune: z.boolean().optional(), dryRun: z.boolean().optional(), confirm: confirm.optional(), confirmPrune: confirm.optional() })
]);
export const directoryClientInput = z.looseObject({ name: z.string().min(1).max(100), confirm });

// ---- Access tokens --------------------------------------------------------------------------------

export const tokenInput = z.discriminatedUnion("op", [
  z.looseObject({ op: z.literal("audience.register"), identifier: resourceIdentifier, app: z.union([appId, z.literal(""), z.null()]).optional() }),
  z.looseObject({ op: z.literal("audience.remove"), identifier: resourceIdentifier, confirm }),
  z.looseObject({ op: z.literal("audience.link"), identifier: resourceIdentifier, clientId: text(200) }),
  z.looseObject({ op: z.literal("audience.unlink"), identifier: resourceIdentifier, clientId: text(200) }),
  z.looseObject({ op: z.literal("client.kind"), clientId: text(200), kind: z.enum(["agent", "auto"]), confirm }),
  z.looseObject({ op: z.literal("machine.create"), name: z.string().min(1).max(100), audience: resourceIdentifier,
    kind: z.enum(["machine", "agent"]).optional(), confirm })
]);

// ---- Remote MCP servers ---------------------------------------------------------------------------

export const mcpScopeEntry = z.looseObject({
  scope: text(200),
  label: text(200).optional(),
  description: text(500).optional(),
  group: text(100).optional(),
  requires: z.array(text(200)).optional(),
  sensitive: z.boolean().optional(),
  adminOnly: z.boolean().optional()
});
/** Scope metadata keyed by scope, as the service (validateResourceConfig) and the CLI send it. */
export const mcpScopeCatalog = z.record(z.string().max(200), mcpScopeEntry.omit({ scope: true }));
export const mcpInput = z.discriminatedUnion("op", [
  z.looseObject({ op: z.literal("resource.register"), identifier: resourceIdentifier, app: appId, name: text(200).optional(),
    full: text(200).nullable().optional(), aliases: z.record(z.string(), z.unknown()).optional(),
    scopes: z.union([mcpScopeCatalog, z.array(mcpScopeEntry).max(200)]).optional() }),
  z.looseObject({ op: z.literal("resource.status"), identifier: resourceIdentifier, enabled: z.boolean(), confirm }),
  z.looseObject({ op: z.literal("resource.remove"), identifier: resourceIdentifier, confirm }),
  z.looseObject({ op: z.literal("grant.revoke"), grantId: text(100), confirm })
]);

// ---- Admission and invitations --------------------------------------------------------------------

export const admissionInput = z.discriminatedUnion("op", [
  z.looseObject({ op: z.literal("mode"), mode: z.enum(["invitation-only", "self-service"]), confirm }),
  z.looseObject({ op: z.literal("invite"), email: emailAddress, days: z.number().int().min(1).max(30).optional() }),
  z.looseObject({ op: z.literal("reissue"), email: emailAddress, days: z.number().int().min(1).max(30).optional(), confirm }),
  z.looseObject({ op: z.literal("revoke"), id: text(64), confirm }),
  z.looseObject({ op: z.literal("dismiss-upgrade-notice") })
]);

// ---- Security policy ------------------------------------------------------------------------------

export const securityPolicyTightenInput = z.looseObject({
  setting: z.enum(["both-authenticators", "recent-passkey"]),
  confirm
});

export type AdminGrantInput = z.infer<typeof adminGrantInput>;
export type ClientCreateInput = z.infer<typeof clientCreateInput>;
export type ClientStatusInput = z.infer<typeof clientStatusInput>;
export type RbacInput = z.infer<typeof rbacInput>;
export type AdmissionInput = z.infer<typeof admissionInput>;
export type TokenInput = z.infer<typeof tokenInput>;
export type McpInput = z.infer<typeof mcpInput>;
