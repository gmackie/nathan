/**
 * The signed OAuth authorization query the sign-in page must send with every sign-in request.
 *
 * When an app sends a browser to /api/auth/oauth2/authorize without a session, Better Auth's
 * OAuth provider redirects to /sign-in with the authorization parameters plus `ba_param` (the
 * names it signed) and `sig`. A sign-in request carrying them as `oauth_query` lets Better Auth
 * resume that authorization once the session exists; without it the browser lands on "/".
 * Mirrors buildSignedOAuthQuery in @better-auth/oauth-provider's client plugin, which Nathan's
 * sign-in page does not load. The signature is verified server-side; this only selects.
 *
 * Self-contained (no free variables). NATH-38: bundled into the sign-in island (src/ui/islands/sign-in.ts).
 */
export function signedOAuthQuery(search) {
  const params = new URLSearchParams(search);
  if (!params.has("sig")) return undefined;
  const names = params.getAll("ba_param");
  if (!names.length) return undefined;
  const signed = new Set(names);
  const kept = new URLSearchParams();
  for (const [key, value] of params.entries())
    if (key === "sig" || key === "ba_param" || signed.has(key)) kept.append(key, value);
  return kept.toString();
}
