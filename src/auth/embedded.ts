import type { AuthEnv } from "./env";
import { handleNathanRequest, runNathanMaintenance, NathanService as StandaloneService } from "./runtime";
import { isMcpOAuthPath, MCP_RETURN_COOKIE } from "./mcp-oauth";
import { SAML_RESUME_COOKIE } from "./saml-idp";
import { parseCookie } from "../shared/security.mjs";

export { getAppPrincipal, NathanVerifier, NathanScimDirectory } from "./runtime";
export type { AppPrincipal } from "./runtime";
export type { AuthEnv } from "./env";

const namespaces = [
  "/api/auth", "/studio", "/security", "/sign-in", "/saml/idp", "/scim/v2", "/directory", "/mcp-oauth", "/__nathan/ui"
];
const exactPaths = new Set([
  "/consent", "/mcp", "/__nathan/healthz", "/.well-known/oauth-authorization-server/api/auth",
  "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"
]);

function ownsPath(path: string): boolean {
  return exactPaths.has(path) || isMcpOAuthPath(path) || namespaces.some(prefix => path === prefix || path.startsWith(prefix + "/"));
}

// Older standalone installations can omit these flags for legacy bootstrap. A new
// app installation defaults to verified owner enrollment and a recent passkey.
function mountedEnv(env: AuthEnv): AuthEnv {
  return {
    ...env,
    NATHAN_BOOTSTRAP_REQUIRED: env.NATHAN_BOOTSTRAP_REQUIRED === "false" ? "false" : "true",
    NATHAN_ADMIN_STEPUP_REQUIRED: env.NATHAN_ADMIN_STEPUP_REQUIRED === "false" ? "false" : "true"
  };
}

export class NathanService extends StandaloneService {
  constructor(ctx: ExecutionContext, env: AuthEnv) {
    super(ctx, mountedEnv(env));
  }
}

export default {
  fetch: (request: Request, env: AuthEnv) => handleNathanRequest(request, mountedEnv(env)),
  scheduled: (_: ScheduledController, env: AuthEnv) => runNathanMaintenance(env)
};

type AppWorker<E, Q, Cf, Props> = ExportedHandler<E, Q, Cf, Props> & Required<Pick<ExportedHandler<E, Q, Cf, Props>, "fetch">>;

/** Mount Nathan on its protocol and UI routes. The host owns other routes and its Worker events. */
export function withNathan<E extends AuthEnv, Q = unknown, Cf = unknown, Props = unknown>(
  app: AppWorker<E, Q, Cf, Props>
): AppWorker<E, Q, Cf, Props> {
  return {
    ...app,
    fetch(request, env, ctx) {
      const path = new URL(request.url).pathname;
      if (ownsPath(path)) return handleNathanRequest(request, mountedEnv(env));
      if (path === "/" && request.method === "GET") {
        const cookie = request.headers.get("Cookie");
        if (parseCookie(cookie, MCP_RETURN_COOKIE) || parseCookie(cookie, SAML_RESUME_COOKIE)) {
          return handleNathanRequest(request, mountedEnv(env), () => app.fetch(request, env, ctx));
        }
      }
      return app.fetch(request, env, ctx);
    },
    scheduled(controller, env, ctx) {
      ctx.waitUntil(runNathanMaintenance(env));
      return app.scheduled?.(controller, env, ctx);
    }
  };
}
