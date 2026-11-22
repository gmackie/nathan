/**
 * The passkey relying-party name: what iCloud Keychain, Google Password Manager and security-key
 * prompts show, and what is stored inside each passkey when it is created. Instance configuration
 * (NATHAN_PASSKEY_RP_NAME, e.g. "gmacko" for id.gmac.io; NATH-43), defaulting to "Nathan".
 * The relying-party ID stays the issuer hostname: it cannot change once passkeys exist.
 */
export function passkeyRpName(env) {
  const raw = typeof env?.NATHAN_PASSKEY_RP_NAME === "string" ? env.NATHAN_PASSKEY_RP_NAME.trim() : "";
  if (!raw) return "Nathan";
  if (raw.length > 64 || /[\u0000-\u001f\u007f<>]/.test(raw)) throw new Error("NATHAN_PASSKEY_RP_NAME must be 1-64 printable characters");
  return raw;
}
