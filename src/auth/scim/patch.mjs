/**
 * NATH-11: RFC 7644 §3.5.2 PATCH for the attributes Nathan stages, with the request shapes Okta and
 * Microsoft Entra ID actually send. Pure functions over plain values: the Durable Object computes the
 * next state, compares it with the current one and only writes (and bumps the revision) on a change,
 * so a replayed PATCH is a no-op.
 *
 * Quirks handled:
 * - op names are case-insensitive (Entra sends "Replace", "Add", "Remove");
 * - booleans may arrive as the strings "True"/"False" (Entra);
 * - replace/add without a path carries an object of attributes, whose keys may be dotted
 *   sub-attribute paths such as "name.givenName" (Entra) or include id/schemas/meta (Okta);
 * - filtered paths: emails[type eq "work"].value (Entra), members[value eq "<id>"] (Okta);
 * - Entra removes group members with path "members" and a value array instead of a filter.
 * Attributes Nathan does not store (name, title, enterprise extension, ...) are accepted and ignored.
 */
import { SCIM_PATCH } from "./validation.mjs";

export class ScimError extends Error {
  /** @param {number} status @param {string} scimType @param {string} detail */
  constructor(status, scimType, detail) {
    super(detail);
    this.status = status;
    this.scimType = scimType;
  }
}
/** @param {string} detail */
const invalidValue = detail => new ScimError(400, "invalidValue", detail);
/** @param {string} detail */
const invalidPath = detail => new ScimError(400, "invalidPath", detail);
/** @param {string} detail */
const invalidSyntax = detail => new ScimError(400, "invalidSyntax", detail);

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RESOURCE_ID = /^[0-9a-f-]{36}$/i;
const ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user";
const MAX_OPERATIONS = 100;
/** Core User attributes Nathan accepts but does not store (lowercase, RFC 7643 §4.1). */
const IGNORED_USER = new Set(["name", "nickname", "profileurl", "title", "usertype", "preferredlanguage", "locale", "timezone",
  "phonenumbers", "addresses", "ims", "photos", "roles", "entitlements", "x509certificates", "password", "groups"]);
/** Keys of a pathless value object that describe the resource rather than change it. */
const RESOURCE_KEYS = new Set(["id", "schemas", "meta"]);

/** JSON booleans, or Entra's "True"/"False" strings. @param {unknown} value */
export function scimBoolean(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string" && /^(true|false)$/i.test(value)) return value.toLowerCase() === "true";
  throw invalidValue("active must be a boolean");
}

/** @param {any} body */
function operations(body) {
  if (!body || typeof body !== "object" || !Array.isArray(body.schemas) || !body.schemas.includes(SCIM_PATCH))
    throw invalidSyntax("Invalid SCIM PatchOp payload");
  const ops = body.Operations;
  if (!Array.isArray(ops) || ops.length < 1 || ops.length > MAX_OPERATIONS) throw invalidSyntax("PatchOp needs 1 to 100 Operations");
  return ops.map(op => {
    if (!op || typeof op !== "object") throw invalidSyntax("Invalid PATCH operation");
    const name = String(op.op ?? "").toLowerCase();
    if (!["add", "replace", "remove"].includes(name)) throw invalidSyntax("PATCH op must be add, replace or remove");
    if (op.path !== undefined && (typeof op.path !== "string" || op.path.length < 1 || op.path.length > 300))
      throw invalidPath("Invalid PATCH path");
    return { op: name, path: op.path, value: op.value };
  });
}
/** Strips the enterprise extension URN prefix and lowercases (attribute names are case-insensitive). @param {string} path */
function normalize(path) {
  const lower = path.toLowerCase();
  if (lower === ENTERPRISE || lower.startsWith(ENTERPRISE + ":")) return "#enterprise";
  return lower;
}
/** @param {unknown} email */
function emailValue(email) {
  if (typeof email !== "string" || email.length > 254 || !EMAIL.test(email)) throw invalidValue("Invalid email address");
  return email.toLowerCase();
}
/** @param {any} entry */
function emailEntry(entry) {
  if (!entry || typeof entry !== "object") throw invalidValue("Invalid SCIM emails");
  return { value: emailValue(entry.value), type: entry.type === "work" ? "work" : "other", primary: entry.primary === true };
}
/** @param {{value:string,type:string,primary:boolean}[]} emails */
function boundedEmails(emails) {
  const seen = new Set();
  const unique = emails.filter(e => !seen.has(e.value) && seen.add(e.value));
  if (unique.length > 10) throw invalidValue("Too many emails");
  return unique;
}

/**
 * @typedef {{ userName: string, externalId: string, displayName: string, emails: {value:string,type:string,primary:boolean}[], active: boolean }} StagedUser
 * @param {StagedUser} current @param {any} body @returns {StagedUser}
 */
export function applyUserPatch(current, body) {
  const next = { ...current, emails: current.emails.map(e => ({ ...e })) };
  /** @param {string} op @param {string} rawPath @param {unknown} value */
  const apply = (op, rawPath, value) => {
    const path = normalize(rawPath);
    if (path === "#enterprise" || IGNORED_USER.has(path.split(".")[0].split("[")[0])) return;
    if (path === "active") {
      if (op === "remove") throw invalidValue("active cannot be removed");
      next.active = scimBoolean(value);
    } else if (path === "username") {
      if (op === "remove") throw invalidValue("userName is required");
      emailValue(value); // validates; userName keeps the directory's spelling
      next.userName = /** @type {string} */ (value);
    } else if (path === "displayname") {
      if (op === "remove") { next.displayName = next.userName; return; }
      if (typeof value !== "string" || value.length > 256) throw invalidValue("Invalid displayName");
      next.displayName = value;
    } else if (path === "externalid") {
      if (op === "remove" || value !== current.externalId)
        throw new ScimError(409, "mutability", "Immutable directory externalId cannot change without a reviewed migration");
    } else if (path === "emails") {
      if (op === "remove") {
        if (Array.isArray(value)) { const drop = new Set(value.map(v => emailEntry(v).value)); next.emails = next.emails.filter(e => !drop.has(e.value)); }
        else next.emails = [];
        return;
      }
      if (!Array.isArray(value)) throw invalidValue("emails must be an array");
      const entries = value.map(emailEntry);
      next.emails = boundedEmails(op === "replace" ? entries : [...next.emails, ...entries]);
    } else {
      const filtered = /^emails\[type eq "(work|home|other)"\](?:\.(value|primary))?$/.exec(path);
      if (!filtered) throw invalidPath("Unsupported User attribute path");
      const [, type, sub] = filtered, index = next.emails.findIndex(e => e.type === (type === "work" ? "work" : "other"));
      if (op === "remove") { if (index >= 0 && sub !== "primary") next.emails.splice(index, 1); return; }
      if (sub === "primary") { if (index >= 0) next.emails[index].primary = scimBoolean(value); return; }
      const address = sub === "value" ? emailValue(value) : emailEntry(value).value;
      if (index >= 0) next.emails[index].value = address;
      else next.emails.push({ value: address, type: type === "work" ? "work" : "other", primary: next.emails.length === 0 });
      next.emails = boundedEmails(next.emails);
    }
  };
  for (const { op, path, value } of operations(body)) {
    if (path !== undefined) { apply(op, path, value); continue; }
    if (op === "remove") throw new ScimError(400, "noTarget", "remove requires a path");
    if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidValue("A PATCH without a path needs an object value");
    for (const [key, item] of Object.entries(value)) if (!RESOURCE_KEYS.has(key.toLowerCase())) apply(op, key, item);
  }
  if (!EMAIL.test(next.userName) || next.userName.length > 254) throw invalidValue("SCIM userName must be a valid email");
  return next;
}

/** @param {unknown} members */
function memberIds(members) {
  if (!Array.isArray(members) || members.length > 1000) throw invalidValue("members must be an array of up to 1000 entries");
  return members.map(m => {
    if (!m || typeof m !== "object" || typeof m.value !== "string" || !RESOURCE_ID.test(m.value)) throw invalidValue("Invalid SCIM group member IDs");
    return m.value.toLowerCase();
  });
}
/**
 * @typedef {{ displayName: string, externalId: string|null, members: string[] }} StagedGroup
 * @param {StagedGroup} current @param {any} body @returns {StagedGroup}
 */
export function applyGroupPatch(current, body) {
  let displayName = current.displayName, externalId = current.externalId;
  const members = new Set(current.members);
  /** @param {string} op @param {string} rawPath @param {unknown} value */
  const apply = (op, rawPath, value) => {
    const path = rawPath.toLowerCase();
    if (path === "displayname") {
      if (op === "remove") throw invalidValue("displayName is required");
      if (typeof value !== "string" || value.length < 1 || value.length > 256) throw invalidValue("Invalid displayName");
      displayName = value;
    } else if (path === "externalid") {
      if (op === "remove" || typeof value !== "string" || value.length < 1 || value.length > 256 || /[\x00-\x1f\x7f]/.test(value))
        throw invalidValue("Invalid group externalId");
      if (externalId !== null && externalId !== value)
        throw new ScimError(409, "mutability", "A group's externalId cannot change once set; group mappings depend on it");
      externalId = value;
    } else if (path === "members") {
      if (op === "remove") {
        if (value === undefined || value === null) members.clear();
        else for (const id of memberIds(value)) members.delete(id);
      } else {
        const ids = memberIds(value);
        if (op === "replace") members.clear();
        for (const id of ids) members.add(id);
      }
    } else {
      const filtered = /^members\[value eq "([0-9a-f-]{36})"\]$/.exec(path);
      if (!filtered || op !== "remove") throw invalidPath("Unsupported Group attribute path");
      members.delete(filtered[1]);
    }
  };
  for (const { op, path, value } of operations(body)) {
    if (path !== undefined) { apply(op, path, value); continue; }
    if (op === "remove") throw new ScimError(400, "noTarget", "remove requires a path");
    if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidValue("A PATCH without a path needs an object value");
    for (const [key, item] of Object.entries(value)) if (!RESOURCE_KEYS.has(key.toLowerCase())) apply(op, key, item);
  }
  if (members.size > 1000) throw invalidValue("Groups are limited to 1000 members");
  return { displayName, externalId, members: [...members].sort() };
}

/** @param {StagedUser} a @param {StagedUser} b */
export const sameUser = (a, b) => a.userName === b.userName && a.externalId === b.externalId && a.displayName === b.displayName &&
  a.active === b.active && JSON.stringify(a.emails) === JSON.stringify(b.emails);
/** @param {StagedGroup} a @param {StagedGroup} b */
export const sameGroup = (a, b) => a.displayName === b.displayName && a.externalId === b.externalId &&
  JSON.stringify([...a.members].sort()) === JSON.stringify([...b.members].sort());
