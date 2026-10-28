import { createNathanTokenVerifier, type NathanVerifierOptions } from "./verify";

export function createNathanGuard(options: NathanVerifierOptions) {
  const verify = createNathanTokenVerifier(options);
  return async function guard(
    request: Request,
    handler: (request: Request, principal: NonNullable<Awaited<ReturnType<typeof verify>>>) => Promise<Response>
  ): Promise<Response> {
    const principal = await verify(request);
    if (!principal) return Response.json({ error: "unauthorized" }, {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Bearer error="invalid_token"',
        "Cache-Control": "no-store"
      }
    });
    return handler(request, principal);
  };
}
