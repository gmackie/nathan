# Mount Nathan in a Cloudflare Worker

Use this mode when an application owns its users, sessions, passkeys, and Kumo Identity Studio. Better Auth runs inside the application's Worker. Each installation has its own HTTPS origin, identity D1, administrator, and secrets. For several applications sharing one account directory and sign-in session, deploy one standalone Nathan issuer and register each application as an OIDC client. [Standalone OIDC guide](https://git.forgegraf.com/gmackie/nathan/src/branch/main/docs/oidc.md)

## Install the Worker package

From the Nathan checkout on Node 22, run `npm ci` and `npm run pack:worker`. Copy `dist/nathan-worker-0.1.0.tgz` to your application's `vendor/` directory, then run this in the application repository.

```sh
npm install ./vendor/nathan-worker-0.1.0.tgz
npm install --save-dev wrangler typescript @cloudflare/workers-types
```

The tarball contains the Worker runtime, the Kumo assets, TypeScript declarations, identity migrations, and the owner bootstrap command. Pin the tarball and lockfile in your application's deployment process.

## Mount the runtime

```ts
import { getAppPrincipal, withNathan, type AuthEnv } from "@nathan/worker";
export { NathanService, NathanVerifier, NathanScimDirectory } from "@nathan/worker";

interface Env extends AuthEnv {
  APPLICATION_ID: string;
}

export default withNathan<Env>({
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === "/me") {
      const user = await getAppPrincipal(request, env, env.APPLICATION_ID);
      const headers = { "Cache-Control": "no-store" };
      if (!user) return new Response("Sign-in and application access required", { status: 403, headers });
      return Response.json(user, { headers });
    }
    if (path === "/") return new Response("Library");
    return new Response("Not found", { status: 404 });
  }
});
```

Supply the application ID from trusted deployment configuration. A principal contains `sub`, `email`, `applicationId`, `roles`, and `permissions`. Nathan checks the host-only session and evaluates current access in D1 on each call. An expired session, a disabled or unknown application, a blocked user, or a request to a different origin returns `null`.

## Configure D1 and the issuer

Create a dedicated database with `npx wrangler d1 create library-identity`. Merge these settings into your app's Wrangler configuration, replacing the database ID, hostname, and administrator email. Bind application data under a separate name if the app also uses D1.

```jsonc
{
  "name": "library",
  "main": "src/worker.ts",
  "compatibility_date": "2026-10-27",
  "compatibility_flags": ["nodejs_compat"],
  "workers_dev": false,
  "preview_urls": false,
  "d1_databases": [{
    "binding": "DB",
    "database_name": "library-identity",
    "database_id": "REPLACE_WITH_D1_UUID",
    "migrations_dir": "node_modules/@nathan/worker/migrations"
  }],
  "durable_objects": { "bindings": [{ "name": "SCIM_DIRECTORY", "class_name": "NathanScimDirectory" }] },
  "migrations": [{ "tag": "nathan-scim-v1", "new_sqlite_classes": ["NathanScimDirectory"] }],
  "triggers": { "crons": ["0 * * * *"] },
  "vars": {
    "APPLICATION_ID": "library",
    "NATHAN_ISSUER": "https://library.example.com",
    "NATHAN_INSTANCE_NAME": "Library",
    "NATHAN_ADMIN_EMAILS": "owner@example.com",
    "NATHAN_SECURITY_PROFILE": "business",
    "NATHAN_BOOTSTRAP_REQUIRED": "true",
    "NATHAN_ADMIN_STEPUP_REQUIRED": "true",
    "NATHAN_INSTALL_ACTIVE": "false",
    "ENABLE_PASSWORD": "false",
    "ENTERPRISE_SSO": "false"
  }
}
```

Keep existing Durable Object migration history when adding the SCIM class. The cron runs Nathan's cleanup and the host's scheduled handler. Choose a cadence that suits both. Use an identity install per origin. Code on that origin and code with its Worker bindings belong to the same trust boundary.

1. Apply the identity schema with `npx wrangler d1 migrations apply library-identity --remote`. Use the matching tarball's migrations before deploying each upgrade.
2. For a new Worker, deploy privately with the inactive configuration above before attaching a public route. Use `npx wrangler secret put` to set `BETTER_AUTH_SECRET` (a fresh high-entropy secret of at least 32 characters) and `NATHAN_CONFIG_KEY` (32 random bytes encoded as base64url). Keep the values in your secret manager.
3. Configure the first verified sign-in method. For Google, register `https://library.example.com/api/auth/callback/google` as the exact callback and set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` as Worker secrets. Studio can manage further providers after bootstrap. Configuration also supports password sign-in with verified email delivery, enterprise SSO, instance naming, and the existing admission and admin assurance policies. [Provider setup](https://git.forgegraf.com/gmackie/nathan/src/branch/main/docs/providers.md)
4. Create `nathan.config.json` in the app repository for the owner command, using the same **account, database, host, and owner** as Wrangler.

```json
{
  "name": "library", "hostname": "library.example.com",
  "accountId": "REPLACE_WITH_32_HEX_CLOUDFLARE_ACCOUNT_ID",
  "database": { "type": "d1", "name": "library-identity" },
  "securityProfile": "business", "adminEmails": ["owner@example.com"], "applications": []
}
```

5. Supply a D1 Edit token for this account via `CLOUDFLARE_API_TOKEN` in your shell's secret environment. Run `npx nathan-worker-admin init` to see the target, then `npx nathan-worker-admin init --apply`. This reserves the owner email. New users are invitation-only by default.
6. Set `NATHAN_INSTALL_ACTIVE` to `"true"`, attach your exact application domain, and deploy the app Worker. Sign in at `/sign-in` as the reserved owner through the configured provider. Run `npx nathan-worker-admin promote --apply`, enroll a passkey and TOTP at `/security`, complete initial setup, and sign in with the passkey. Open `/studio`. Owner promotion checks the verified identity and records the change in the same database operation.
7. In Studio, register the protected application with the ID from `APPLICATION_ID`, configure role grants or the desired access mode, and explicitly enable it. Sign in and open `/me` to verify the application sees the expected principal.

## HTTP routes and service-binding RPC

Nathan handles `/api/auth`, `/sign-in`, `/consent`, `/security`, `/studio`, `/saml/idp`, `/scim/v2`, `/directory`, `/mcp`, `/mcp-oauth`, `/connections`, its OAuth metadata, and `/__nathan/ui` assets. The app owns its home page, `/healthz`, and business routes. A pending MCP or SAML sign-in can resume at `/`. Nathan health is available at `/__nathan/healthz`. OIDC discovery is at `/api/auth/.well-known/openid-configuration`.

To call Nathan from another Worker in the account, bind the named entrypoint on the Worker that owns the identity installation.

```jsonc
"services": [{ "binding": "IDENTITY", "service": "library", "entrypoint": "NathanService" }]
```

```ts
import type { NathanService } from "@nathan/worker";

interface PeerEnv {
  IDENTITY: Service<NathanService>;
}

async function discovery(env: PeerEnv) {
  return env.IDENTITY.handle(new Request("https://library.example.com/api/auth/.well-known/openid-configuration"));
}
```

`NathanService.handle(request)` accepts the full HTTP request and returns the original response, including status, redirect location, and cookies. It serves Nathan's protocol and management routes in both deployment modes. Use the canonical HTTPS origin. Forward the original credentials and browser origin for user actions. Studio writes require a verified administrator, the configured passkey assurance, a same-origin JSON request, and the route's normal validation and confirmation. The audit actor is the signed-in administrator. For read-only app authorization, bind `NathanVerifier` with deployment props `{ "applicationId": "library" }` and call `getPrincipal(cookie)`. [Studio API](https://git.forgegraf.com/gmackie/nathan/src/branch/main/docs/studio-api.md)

Bind the full service to trusted peer code that may carry users' credentials. RPC has no edge-verified client IP. Nathan discards IP forwarding headers supplied by a peer, so its calls share the unknown-address rate limit. Public HTTPS requests retain Cloudflare's edge IP attribution.
