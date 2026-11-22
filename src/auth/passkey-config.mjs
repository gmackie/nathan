/**
 * Instance naming (NATH-43). NATHAN_INSTANCE_NAME is what people see this identity provider called:
 * the issuer label authenticator apps show for TOTP, Better Auth's appName, and by default the passkey
 * relying-party name that iCloud Keychain, Google Password Manager and security-key prompts show (it
 * is stored inside each passkey when created). "gmacko" for id.gmac.io; default "Nathan".
 * NATHAN_PASSKEY_RP_NAME overrides the passkey name only. The passkey rpID stays the issuer hostname:
 * it cannot change once passkeys exist.
 */
function displayName(env, key) {
  const raw = typeof env?.[key] === "string" ? env[key].trim() : "";
  if (!raw) return null;
  if (raw.length > 64 || /[\u0000-\u001f\u007f<>:]/.test(raw)) throw new Error(key + " must be 1-64 printable characters without < > or :");
  return raw;
}
export function instanceName(env) {
  return displayName(env, "NATHAN_INSTANCE_NAME") ?? "Nathan";
}
export function passkeyRpName(env) {
  return displayName(env, "NATHAN_PASSKEY_RP_NAME") ?? instanceName(env);
}
