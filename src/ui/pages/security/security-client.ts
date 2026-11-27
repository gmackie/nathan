/**
 * NATH-38: the browser calls /security makes, moved out of the old inline script in
 * src/auth/security-ui.ts. The requests, bodies and WebAuthn conversions are unchanged; every
 * fetch is same-origin with credentials: 'same-origin'. Runs only in the `security` island.
 */

export interface BootstrapStatus {
  configured?: boolean;
  state?: string;
  isInitialAdmin?: boolean;
  isAdministrator?: boolean;
  managementHost?: boolean;
  managementTotp?: boolean;
  passkeys?: number;
  totpVerified?: boolean;
  ready?: boolean;
  sessionReady?: boolean;
  requirements?: { passkey?: boolean; totp?: boolean; stepUp?: "none" | "passkey" | "passkey-or-totp" };
  warning?: string;
}

export interface BootstrapComplete {
  complete?: boolean;
  note?: string;
}

export interface TotpEnrollment {
  totpURI?: string;
  backupCodes?: string[];
}

/** The module matrix POST /security/api/totp-qr returns: `rows` of "0"/"1" strings. */
export interface QrMatrix {
  size: number;
  rows: string[];
}

export interface PasskeySummary {
  id?: string;
  name?: string | null;
  deviceType?: string;
  backedUp?: boolean;
  createdAt?: string;
}

type Json = Record<string, unknown>;

export async function api<T = Json>(path: string, method = "GET", body?: unknown): Promise<T> {
  const res = await fetch("/api/auth" + path, {
    method, credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined
  });
  const json = await res.json() as Json;
  if (!res.ok) throw Error(String(json.message || json.error || "Request failed"));
  return json as T;
}

export function unwrap<T>(response: T | { data: T }): T {
  return ((response as { data?: T }).data || response) as T;
}

export function decode(value: string): Uint8Array<ArrayBuffer> {
  const str = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(str, c => c.charCodeAt(0));
}

export function encode(value: ArrayBuffer): string {
  let s = ""; for (const b of new Uint8Array(value)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function bootstrapStatus(): Promise<BootstrapStatus> {
  const resp = await fetch("/security/api/bootstrap", { credentials: "same-origin" });
  if (!resp.ok) throw Error("Cannot load administrator setup requirements");
  return await resp.json() as BootstrapStatus;
}

export async function completeBootstrap(): Promise<BootstrapComplete> {
  const response = await fetch("/security/api/bootstrap/complete", {
    method: "POST", credentials: "same-origin",
    headers: { Origin: location.origin }
  });
  const body = await response.json() as Json;
  if (!response.ok) throw Error(String(body.error || "Enrollment is incomplete"));
  return body as BootstrapComplete;
}

export async function enableTotp(password: string): Promise<TotpEnrollment> {
  return unwrap(await api<TotpEnrollment>("/two-factor/enable", "POST", password ? { password, method: "totp" } : { method: "totp" }));
}

export async function verifyTotp(code: string): Promise<void> {
  await api("/two-factor/verify-totp", "POST", { code, trustDevice: false });
}

/** null when the QR is unavailable; the page then says to enter the key manually. */
export async function totpQr(uri: string): Promise<QrMatrix | null> {
  const res = await fetch("/security/api/totp-qr", {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", Origin: location.origin }, body: JSON.stringify({ uri })
  });
  if (!res.ok) return null;
  const { size, rows } = await res.json() as QrMatrix;
  if (!Number.isInteger(size) || size <= 0 || size > 177 || !Array.isArray(rows) || rows.length !== size) return null;
  if (!rows.every(row => typeof row === "string" && row.length === size && /^[01]*$/.test(row))) return null;
  return { size, rows };
}

/** The secret from an otpauth URI ("" if none), and the same key grouped in fours for reading. */
export function totpSecret(uri: string): { secret: string; grouped: string } {
  let secret = "";
  try { secret = new URL(uri).searchParams.get("secret") || ""; } catch { /* manual entry shows nothing */ }
  return { secret, grouped: secret.replace(/(.{4})/g, "$1 ").trim() };
}

/** The SVG path for a QR matrix with a 4-module quiet zone; `full` is the viewBox side. */
export function qrPath({ size, rows }: QrMatrix): { full: number; d: string } {
  const q = 4, full = size + 2 * q;
  let d = "";
  rows.forEach((row, y) => { for (let x = 0; x < row.length; x++) if (row[x] === "1") d += "M" + (x + q) + " " + (y + q) + "h1v1h-1z"; });
  return { full, d };
}

interface RegisterOptions { publicKey?: PublicKeyCredentialCreationOptions; [key: string]: unknown }
interface AuthenticateOptions { publicKey?: PublicKeyCredentialRequestOptions; [key: string]: unknown }
type Wire<T> = Omit<T, "challenge"> & { challenge: string | BufferSource };

/**
 * Registers a passkey. A YubiKey or other roaming security key asks for a cross-platform
 * authenticator; an empty attachment lets the browser offer its built-in passkey store first.
 */
export async function addPasskey(attachment: "" | "cross-platform", name: string): Promise<void> {
  if (!window.PublicKeyCredential) throw Error("WebAuthn is not available in this browser");
  const options = unwrap(await api<RegisterOptions>("/passkey/generate-register-options" + (attachment ? "?authenticatorAttachment=" + attachment : "")));
  const publicKey = (options.publicKey || options) as unknown as Wire<PublicKeyCredentialCreationOptions> & { user: { id: string | BufferSource } };
  publicKey.challenge = decode(publicKey.challenge as string);
  publicKey.user.id = decode(publicKey.user.id as string);
  if (publicKey.excludeCredentials) publicKey.excludeCredentials = publicKey.excludeCredentials.map(c => ({ ...c, id: decode(c.id as unknown as string) }));
  const credential = await navigator.credentials.create({ publicKey: publicKey as PublicKeyCredentialCreationOptions }) as PublicKeyCredential | null;
  if (!credential) throw Error("Passkey creation was cancelled");
  const attestation = credential.response as AuthenticatorAttestationResponse;
  const response = {
    id: credential.id, rawId: encode(credential.rawId), type: "public-key",
    response: {
      clientDataJSON: encode(attestation.clientDataJSON),
      attestationObject: encode(attestation.attestationObject),
      transports: attestation.getTransports ? attestation.getTransports() : []
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
  await api("/passkey/verify-registration", "POST", { response, name });
}

/** A fresh passkey authentication ceremony (administrator step-up). */
export async function passkeyStepUp(): Promise<void> {
  if (!window.PublicKeyCredential) throw Error("WebAuthn is not available in this browser");
  const options = unwrap(await api<AuthenticateOptions>("/passkey/generate-authenticate-options"));
  const publicKey = (options.publicKey || options) as unknown as Wire<PublicKeyCredentialRequestOptions>;
  publicKey.challenge = decode(publicKey.challenge as string);
  if (publicKey.allowCredentials) publicKey.allowCredentials =
    publicKey.allowCredentials.map(c => ({ ...c, id: decode(c.id as unknown as string) }));
  const credential = await navigator.credentials.get({ publicKey: publicKey as PublicKeyCredentialRequestOptions }) as PublicKeyCredential | null;
  if (!credential) throw Error("Passkey sign-in was cancelled");
  const assertion = credential.response as AuthenticatorAssertionResponse;
  const response = {
    id: credential.id, rawId: encode(credential.rawId), type: "public-key",
    response: {
      clientDataJSON: encode(assertion.clientDataJSON),
      authenticatorData: encode(assertion.authenticatorData),
      signature: encode(assertion.signature),
      userHandle: assertion.userHandle ? encode(assertion.userHandle) : undefined
    }, clientExtensionResults: credential.getClientExtensionResults()
  };
  await api("/passkey/verify-authentication", "POST", { response });
}

export async function listPasskeys(): Promise<PasskeySummary[]> {
  const keys = unwrap(await api<PasskeySummary[] | { data: PasskeySummary[] }>("/passkey/list-user-passkeys"));
  return Array.isArray(keys) ? keys : [];
}
