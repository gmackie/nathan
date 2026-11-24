# ClassCheck tokens, UserInfo and logout

| Environment | Issuer | API resource | Web client logout return |
| --- | --- | --- | --- |
| Staging | `https://beta.classcheck.io/api/auth` | `https://beta.classcheck.io/api` | `https://beta.classcheck.io/sign-in` |
| Production | `https://classcheck.io/api/auth` | `https://classcheck.io/api` | `https://classcheck.io/sign-in` |

Use the stage's private `NathanAppAuth` binding for discovery, JWKS, authorization, token exchange, UserInfo and logout. The issuer and resource use the public ClassCheck origin. Register each client explicitly, link it to its stage's resource, and send the exact `resource` during authorization, code exchange and refresh.

## Resolve a sign-in

1. Verify the ID token against the stage's JWKS with EdDSA, the exact issuer and the web client ID as audience. Verify expiration and match the nonce to the authorization request. The public-subject client's `sub` is the immutable Nathan user ID. Resolve the stage's verified `(iss, sub)` to the previously provisioned ClassCheck user ID.
2. Send the access token as a bearer credential to `GET /api/auth/oauth2/userinfo` over the binding. Match the returned `sub` to the verified ID token. The `email` scope supplies `email` and `email_verified` here. The `profile` scope supplies available name and picture fields. Account links always use the verified issuer and subject.
3. For API requests, require an RFC 9068 access token with header `typ: at+jwt`, EdDSA signature, a trusted `kid`, the stage's exact issuer, its API resource in `aud`, and a current validity window. The maximum access token lifetime is 900 seconds. With `openid`, the audience also contains the issuer's `/oauth2/userinfo` URL. Check the expected `client_id`, `principal_kind` and granted scopes for the operation. A user token includes `sid` and a Nathan user `sub`. A client-credentials token has `principal_kind: machine` for a standard machine client, and its subject is the client ID. Resolve the stage's `(iss, client_id)` through the registered ClassCheck district mapping.

ClassCheck owns the school and guardian authorization decisions. A Nathan access token can carry app role hints and a `nathan_amr` value based on the actual sign-in. The verified-email UserInfo attribute and email sign-in method confer no administrative authority. Nathan management uses its own origin and passkey step-up.

## RP-initiated logout

Configure the web client with public subjects, `enableEndSession=true` and the stage's exact logout return from the table. Discovery advertises `end_session_endpoint` when an enabled, resource-linked client has that registration. Obtain a fresh ID token after enabling logout so the hint contains the Nathan session ID.

The ClassCheck server calls `POST /api/auth/oauth2/end-session` on the binding. Set `Content-Type: application/x-www-form-urlencoded`, forward the original same-origin `Origin` and Nathan browser cookies, and put `client_id`, `id_token_hint`, `post_logout_redirect_uri` and optional `state` in the body. Use each parameter once. Keep the ID token server-side. The return must match the registered URL byte-for-byte. State is limited to 2,048 UTF-16 code units and excludes control characters.

Nathan verifies the signed hint using its local signing keys and matches the client, subject and session ID to the live browser session. A signed ID token issued within the configured session lifetime may serve as a logout hint after its ordinary expiration. Success returns HTTP 200, `Cache-Control: no-store`, and JSON `{"url":"<registered return>"}` with any state encoded as a query parameter. Forward each Nathan `Set-Cookie` clearance separately. ClassCheck clears its local session and renders the return page. Rejected requests return an error without a success URL. A temporary storage error returns HTTP 503.

For first-party web sign-out, ClassCheck can continue its same-origin `POST /api/auth/sign-out`, revoke the applicable grant and expire its local session. Both forms of logout queue signed notifications for registered receivers of the ending session, including JWT-only grants. Hinted logout also confirms participation for its initiating RP. Each notification carries the affected session ID and the subject that RP received. Delivery starts after the session has been deleted. Nathan retries transient delivery failures through its scheduled queue. The receiver verifies the signature, stage issuer, client audience, event, expiry and replay ID, then revokes the matching ClassCheck sessions idempotently.
