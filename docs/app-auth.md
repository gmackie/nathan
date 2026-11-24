# Standalone application sign-in

The ClassCheck web Worker renders the browser pages and calls a separately installed Nathan Worker over the `NathanAppAuth` service binding. Each environment has its own D1 database, keys, management Access audience and client registrations. Configure the binding with `props: { applicationId: "classcheck" }`. Nathan also checks the installed application ID, its enabled registry entry and the exact public origin.

| Environment | OIDC issuer | Management |
| --- | --- | --- |
| Staging | `https://beta.classcheck.io/api/auth` | `https://id-stg.classcheck.io` |
| Production | `https://classcheck.io/api/auth` | `https://id.classcheck.io` |

The web client registers exactly `/auth/callback` on its ClassCheck origin, requires S256 PKCE, and authenticates at the token endpoint with HTTP Basic. The resource is the same origin followed by `/api`. Each request to the named fetch binding uses the public ClassCheck origin. The API checks the registered client-to-resource link. The consumer preserves separate Set-Cookie fields, host-only scope, the original same-origin browser Origin and Sec-Fetch-Site, and the client IP supplied by its trusted Cloudflare edge. Pass narrowly selected Nathan cookies and use manual redirect handling.

| Private request | ClassCheck behavior |
| --- | --- |
| GET `/api/auth/.well-known/openid-configuration`, `/api/auth/jwks` | Read issuer metadata and signing keys through the server binding. |
| GET `/api/auth/oauth2/authorize` | Start a registered authorization with state, nonce, exact callback, resource and S256. Render the ClassCheck page selected by the redirect or JSON URL. |
| POST `/sign-in/context` | Submit JSON with the signed `oauth_query`. A valid response provides the registered client name, scopes, login hint and enterprise SSO configuration for the sign-in or consent page. |
| POST `/sign-in/email/request` | Submit `email` and the signed `oauth_query`. Preserve the `__Host-nathan-email` cookie. The neutral 202 reply includes a `flowId`. |
| POST `/sign-in/email/verify` | Submit `{flowId,code}` from the six-digit form or the fragment of the same-browser link on `/sign-in/email`. Clear the fragment before making the request. For `twoFactorRedirect`, collect the enrolled authenticator and submit `{flowId,totp}`. Follow the validated continuation and preserve the Nathan session cookie. |
| POST `/api/auth/oauth2/consent` | Submit `{accept,oauth_query}` using the signed query on the ClassCheck consent page. An approved subset in `scope` must include `openid` so the callback receives a verified identity. |
| POST `/api/auth/oauth2/token` | Exchange a grant using form encoding and the same resource. Verify ID-token signature, issuer, audience, expiration and nonce, then match UserInfo subject before applying verified email. |
| GET `/api/auth/oauth2/userinfo` | Send the issued ClassCheck resource access token. |
| POST `/api/auth/oauth2/revoke`, `/api/auth/sign-out` | Revoke the applicable grant with the registered client and clear the Nathan session and ClassCheck session. |

The app binding exposes protocol operations. ClassCheck handles credential entry, consent, errors and redirects. A scanned email link performs no server-side verification on GET. A recipient on another device enters the digits in the original tab. Operators establish their management identity behind Access, then enroll an authenticator and passkey on the management origin. Public app sign-in cannot claim an operator invitation.
