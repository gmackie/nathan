# Inbound enterprise SAML

Nathan can let a company's own identity provider (IdP) sign its people in to Nathan over SAML 2.0. Nathan is the **service provider (SP)**: it receives signed assertions from Okta, Microsoft Entra ID, Google Workspace or another SAML 2.0 IdP and then acts as the OIDC issuer for your applications as usual. Nathan acting as a SAML *IdP* for downstream apps is a separate, later feature (NATH-12).

> **Status (NATH-10):** source, unit tests and workerd runtime tests are complete. Signed logins and every rejection case below are tested against the built Worker in workerd with a test IdP. Not yet verified: real Okta, Entra or Google tenants; DNS TXT verification against live DNS from a deployed Worker; staging. Treat a connection as untested until you have signed in through it on staging.

## Prerequisites

- The identity Worker is deployed with `ENTERPRISE_SSO=true`. Without it, the SAML endpoints and the Studio tab refuse to work.
- You are a Nathan administrator with completed enrollment and a passkey sign-in within the last 15 minutes. Every SAML change is admin-only and audited.
- You can publish a DNS TXT record in the company's email domain.

## Values to give the IdP administrator

Each connection has its own ID (for example `acme-okta`, lowercase letters, digits and dashes). With Nathan at `https://login.example.com` and connection ID `acme-okta`, the values are:

| IdP field | Value |
|---|---|
| SP entity ID / Audience URI / Identifier | `https://login.example.com/api/auth/sso/saml2/sp/metadata?providerId=acme-okta` |
| ACS URL / Single sign-on URL / Reply URL / Recipient / Destination | `https://login.example.com/api/auth/sso/saml2/sp/acs/acme-okta` |
| SP metadata URL (after the connection exists) | same as the entity ID |
| Binding Nathan uses for AuthnRequests | HTTP-Redirect (unsigned AuthnRequest) |
| Binding for the response | HTTP-POST to the ACS URL |
| NameID format | `EmailAddress`, value = the user's primary email |
| Signing | Assertion signed, RSA-SHA256 (SHA-1 is rejected) |
| Sign-on URL / start URL (optional) | `https://login.example.com/sign-in` |
| Default RelayState, IdP-initiated SSO | leave empty; IdP-initiated SSO is rejected |

Identity Studio shows these values with copy buttons as soon as you type the connection ID (**Enterprise SAML** tab).

### Attributes

Nathan reads the email from the `email` attribute (or the IdP's default email claim for the Entra preset) and falls back to the NameID. Names are optional.

| Preset | email | first name | last name |
|---|---|---|---|
| Okta, Google Workspace, Other | `email` | `firstName` | `lastName` |
| Microsoft Entra ID | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `…/claims/givenname` | `…/claims/surname` |

## Okta

1. Okta Admin Console → **Applications → Create App Integration → SAML 2.0**.
2. **Single sign-on URL**: the ACS URL. Tick **Use this for Recipient URL and Destination URL**.
3. **Audience URI (SP Entity ID)**: the SP entity ID.
4. **Name ID format**: EmailAddress. **Application username**: Email.
5. **Show Advanced Settings**: Response *Unsigned* or *Signed*, **Assertion Signature: Signed**, Signature Algorithm **RSA-SHA256**, Digest **SHA256**, Assertion Encryption **Unencrypted**.
6. **Attribute Statements**: `email` → `user.email`, `firstName` → `user.firstName`, `lastName` → `user.lastName`.
7. Assign users or groups. Because IdP-initiated SSO is not accepted, hide the app tile (**Do not display application icon to users**) or point users to `https://login.example.com/sign-in`.
8. On the app's **Sign On** tab, copy the **Metadata URL** (`https://<org>.okta.com/app/<app-id>/sso/saml/metadata`) for Nathan.

## Microsoft Entra ID

1. Entra admin center → **Enterprise applications → New application → Create your own application** → *Integrate any other application you don't find in the gallery*.
2. **Single sign-on → SAML → Basic SAML Configuration**:
   - **Identifier (Entity ID)**: the SP entity ID (remove the default).
   - **Reply URL (Assertion Consumer Service URL)**: the ACS URL.
   - **Sign on URL**: `https://login.example.com/sign-in` (optional).
   - Leave **Relay State** and **Logout Url** empty.
3. **Attributes & Claims**: keep the defaults (Unique User Identifier = `user.userprincipalname` or better `user.mail`, emailaddress, givenname, surname). Choose the **Microsoft Entra ID** preset in Nathan.
4. **SAML Certificates**: Signing Option *Sign SAML assertion* (or response and assertion), Signing Algorithm **SHA-256**.
5. Copy the **App Federation Metadata Url** (`https://login.microsoftonline.com/<tenant>/federationmetadata/2007-06/federationmetadata.xml?appid=<app-id>`).
6. **Users and groups**: assign who may sign in.

Entra's metadata also contains a WS-Federation `RoleDescriptor` and an enveloped metadata signature. Nathan ignores both. It pins the signing certificates listed under `IDPSSODescriptor` and shows their fingerprints. Compare those fingerprints with the **Thumbprint** in Entra (Entra shows SHA-1 thumbprints; Nathan shows SHA-256, so compare in a certificate viewer if needed).

## Google Workspace

1. Admin console → **Apps → Web and mobile apps → Add app → Add custom SAML app**.
2. On **Google Identity Provider details**, choose **Download metadata** (Option 1). Google offers no metadata URL; paste the XML into Nathan.
3. **Service provider details**: **ACS URL** = the ACS URL, **Entity ID** = the SP entity ID, **Start URL** empty, **Signed response** optional, **Name ID format** EMAIL, **Name ID** *Basic Information > Primary email*.
4. **Attribute mapping**: *Primary email* → `email`, *First name* → `firstName`, *Last name* → `lastName`.
5. Turn **User access** ON for the organizational units that should sign in.

## Creating and enabling a connection in Identity Studio

1. **Enterprise SAML** tab: enter the connection ID, the company's email domain, the IdP preset and the provisioning mode.
2. Paste the metadata URL or the metadata XML and choose **Check metadata**. Nathan validates without saving:
   - one `EntityDescriptor` with an `entityID`; no DTD; `validUntil` (if present) in the future; at most 100 KiB;
   - an HTTPS **HTTP-Redirect** `SingleSignOnService` (HTTP-POST is also read, but Nathan sends AuthnRequests with HTTP-Redirect, so POST-only metadata is rejected);
   - 1–4 signing certificates (`use="signing"` or no `use`), each RSA ≥ 2048 bits, signed with SHA-256/384/512 or RSASSA-PSS, currently valid; a certificate that expires within 30 days produces a warning;
   - a signed metadata document must not use SHA-1. Its signature itself is not verified: the pinned certificates are what Nathan trusts.
   Metadata URLs must be HTTPS public DNS names; Nathan does not follow redirects and stops after 5 seconds or 100 KiB.
3. **Create disabled connection**. Nathan registers the provider with the Better Auth SSO plugin server-side, using a canonical metadata document it rebuilds from the validated values (not the pasted XML), its own per-connection SP entity ID as issuer and audience, and signed assertions required. The response contains the DNS TXT record to publish, for example `_better-auth-token-acme-okta.acme.example`.
4. Publish the TXT record, then **Verify DNS ownership**. (**Request new TXT challenge** issues a fresh token. Only the administrator who created the connection can request or verify, because the plugin scopes these calls to the creator.)
5. **Enable connection** and type the confirmation `CONFIRM ENABLE SAML acme-okta`. Enabling is refused until the domain is verified and at least one certificate is valid.
6. Test from a private window: `https://login.example.com/sign-in` → **Sign in with SSO** → a user address in the domain.

Disable with `CONFIRM DISABLE SAML <id>`. A disabled connection's ACS and SSO routing are closed at once. Existing Nathan sessions are not revoked by disabling; revoke them separately if needed.

## Account provisioning and linking

- **Invitation only** (default): SAML sign-in works only for people who already have a Nathan account with an address in the verified domain. No account is created.
- **Just-in-time**: Nathan creates an account on first sign-in, only for an address inside the connection's verified domain (or its subdomains). Its email is marked verified, because the domain owner proved DNS control and its IdP signed the address.
- An IdP can never create or link an account for an address outside its verified domain.
- Existing accounts are linked only when the domain is verified and the address is inside it. The IdP's own `email_verified`-style attributes are never trusted.
- A SAML session never grants admin rights on its own. Administrators still need Nathan enrollment and a recent passkey step-up.

Change the mode with **Apply provisioning mode** and `CONFIRM PROVISIONING <mode> <id>`.

## Certificate rotation

1. When the IdP creates its next signing certificate, paste it into **Next signing certificate** and choose **Trust next certificate**. Nathan now accepts assertions signed by either certificate (at most three at a time).
2. Make the new certificate active in the IdP (Okta: *Activate*; Entra: *Make certificate active*; Google: switch certificates in the app).
3. Sign in once to confirm, then **Retire certificate** with the old certificate's SHA-256 fingerprint and `CONFIRM RETIRE CERTIFICATE <id>`. The only remaining certificate cannot be retired.

Studio lists every certificate with its expiry and warns 30 days ahead and after expiry. Nathan does not refuse logins signed by an expired but still pinned certificate (several IdPs keep signing with an expired certificate, so enforcing expiry at login causes outages). Retire expired certificates promptly.

Rotation rewrites the plugin's stored configuration. A sign-in that was in flight during the change fails and has to be restarted.

## What Nathan checks on every SAML response

Enforced by the Better Auth SSO plugin (samlify) and Nathan, and tested in workerd:

- The connection exists in Nathan, is enabled and its domain is verified (otherwise the ACS answers 404).
- A valid XML signature over the assertion by a pinned certificate. Unsigned, tampered or foreign-key responses fail. SHA-1 and MD5 signature or digest methods are rejected by Nathan before the plugin runs (the plugin's own `onDeprecated` check only covers the HTTP-Redirect `SigAlg` parameter).
- Issuer equals the IdP entity ID; Audience equals Nathan's SP entity ID; Recipient/Destination equal the ACS URL.
- `NotBefore`/`NotOnOrAfter` are present and valid with 2 minutes of clock skew.
- `InResponseTo` matches an AuthnRequest Nathan issued for this connection within 5 minutes, and is single-use. Responses without `InResponseTo` (IdP-initiated) are rejected.
- Each assertion ID is accepted once (replay protection).
- Only one assertion per response; at most 256 KiB.

Raw Better Auth SSO management endpoints (`/api/auth/sso/register`, `update-provider`, `delete-provider`, `providers`, `get-provider`, `verify-domain`, `request-domain-verification`) stay blocked. `/api/auth/sign-in/sso` only accepts an explicit `providerId` that names a usable connection. The sign-in page uses `/sign-in/sso/start`, which routes an email domain to its most specific enabled SAML connection (or else a verified enterprise OIDC provider).

## Not supported (yet)

- IdP-initiated SSO (rejected by design).
- Encrypted assertions, signed AuthnRequests and SP signing keys.
- SAML single logout.
- Automatic metadata refresh from the IdP. Rotate certificates as described above.
- Deleting a connection from Studio (disable it instead).
- More than ten SSO providers created by one administrator (the plugin's default `providersLimit`).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `No enterprise sign-in is configured for this email domain` | No enabled connection with a verified domain matches the address. |
| ACS answers 404 `SAML connection unavailable` | Connection disabled, unknown, or its domain is not verified. |
| ACS answers 400 about SHA-1/MD5 | The IdP signs with SHA-1. Switch it to RSA-SHA256. |
| Redirect with `error=invalid_saml_response` or `unsolicited_response` | Wrong audience/ACS values in the IdP, an IdP-initiated login, or a sign-in older than 5 minutes. |
| Redirect with `error=unable_to_create_user` | Invitation-only connection and the person has no Nathan account, or the address is outside the verified domain. |
| `sso_provider_changed_during_authentication` | A certificate was rotated during the sign-in; start again. |
