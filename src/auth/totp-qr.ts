import { encode } from "uqr";

/**
 * QR module matrix for a TOTP enrollment URI (staging feedback, 2026-11-22). The security page draws
 * it as inline SVG, so its CSP (img-src 'none', nonce-only scripts) is unchanged, and the secret never
 * goes to a third-party QR service. The URI only travels back to the server that generated it.
 * Signed-in, same-origin JSON only; the URI is never logged or cached.
 */
const TOTP_URI = /^otpauth:\/\/totp\/[^\s]{1,480}$/;

export async function totpQrResponse(request: Request, origin: string, signedIn: boolean): Promise<Response> {
  const fail = (status: number, error: string) =>
    Response.json({ error }, { status, headers: { "Cache-Control": "no-store" } });
  if (request.headers.get("Origin") !== origin || request.headers.get("Sec-Fetch-Site") === "cross-site")
    return fail(403, "Cross-origin request denied");
  if (!signedIn) return fail(401, "Authenticated session required");
  if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json") return fail(415, "JSON required");
  const raw = await request.text();
  if (raw.length > 1024) return fail(400, "Invalid TOTP URI");
  let uri: unknown;
  try { uri = (JSON.parse(raw) as { uri?: unknown })?.uri; } catch { return fail(400, "Invalid JSON"); }
  if (typeof uri !== "string" || !TOTP_URI.test(uri)) return fail(400, "Invalid TOTP URI");
  const { size, data } = encode(uri, { ecc: "M", border: 0 });
  return Response.json({ size, rows: data.map(row => row.map(dark => (dark ? "1" : "0")).join("")) },
    { headers: { "Cache-Control": "no-store" } });
}
