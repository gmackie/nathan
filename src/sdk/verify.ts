import { createRemoteJWKSet, jwtVerify } from "jose";

export type NathanPrincipal = { sub: string; scopes: string[]; issuer: string; audience: string };
export type NathanVerifierOptions = {
  issuer: string;
  audience: string;
  requiredScopes?: string[];
};
export function createNathanTokenVerifier(options: NathanVerifierOptions) {
  const issuer = new URL(options.issuer);
  if (issuer.protocol !== "https:") throw Error("Issuer must be HTTPS");
  const jwks = createRemoteJWKSet(new URL(issuer.origin + "/api/auth/jwks"));
  return async (request: Request): Promise<NathanPrincipal | null> => {
    const header = request.headers.get("Authorization");
    if (!header?.startsWith("Bearer ")) return null;
    const token = header.slice(7);
    if (token.length > 16000) return null;
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer: options.issuer, audience: options.audience,
        algorithms: ["RS256", "ES256", "EdDSA"],
        clockTolerance: 30
      });
      if (typeof payload.sub !== "string" || typeof payload.scope !== "string") return null;
      const scopes = payload.scope.split(" ");
      if (options.requiredScopes?.some(s => !scopes.includes(s))) return null;
      return { sub: payload.sub, scopes, issuer: String(payload.iss), audience: options.audience };
    } catch { return null; }
  };
}
