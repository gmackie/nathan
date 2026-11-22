# Nathan as a SAML identity provider

Downstream applications that speak SAML 2.0 (AWS IAM Identity Center, Salesforce, Grafana or any other SAML service provider, "SP") can sign people in through Nathan. Nathan is the **identity provider (IdP)**. This is the reverse of [inbound enterprise SAML](saml.md), where a company's IdP signs people in to Nathan.

Nathan stays authentication plus minimal RBAC. Every SP is bound to one Nathan application, and the application's roles and access ([rbac.md](rbac.md), NATH-13) decide who may sign in: deny by default.

> **Status (NATH-12):** source, unit tests and workerd runtime tests are complete. An independent SP library (samlify's `ServiceProvider`, in Node) creates the AuthnRequests and validates Nathan's signed Responses against the built Worker in workerd, and every refusal case below is tested. Not yet verified: real AWS IAM Identity Center, Salesforce and Grafana tenants, and a deployed staging Worker. Treat an SP as untested until you have signed in to it on staging.

## Values to give the SP administrator

With Nathan at `https://login.example.com`:

| SP field | Value |
|---|---|
| IdP entity ID / Issuer | `https://login.example.com/saml/idp` |
| IdP metadata URL | `https://login.example.com/saml/idp/metadata` (also served at the entity ID) |
| Single sign-on URL (HTTP-Redirect and HTTP-POST) | `https://login.example.com/saml/idp/sso` |
| Signing certificate | in the metadata, or copy it from Identity Studio |
| Response binding | HTTP-POST to the SP's registered ACS URL |
| Signatures | Assertion always signed; Response also signed if you tick **Also sign the Response**. RSA-SHA256, SHA-256 digest, exclusive canonicalization |
| NameID | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` (default) or `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| Single logout URL | none (not supported) |

The metadata says `WantAuthnRequestsSigned="false"` because signing is required per SP, not globally. An SP that refuses to sign when that flag is false can still be registered without **Require signed AuthnRequests**.

## Before the first SP: generate the signing key

Identity Studio → **SAML applications** → **Generate signing key**, confirm with `CONFIRM GENERATE SAML IDP KEY`. Nathan generates an RSA key (2048 bits by default; 3072 and 4096 are offered) inside the Worker, makes a self-signed SHA-256 certificate valid for three years, and stores the private key encrypted under `NATHAN_CONFIG_KEY` (AES-GCM, AAD `nathan:saml-idp-key:v1:<key id>`). The private key is never returned by any API or shown in Studio. Without `NATHAN_CONFIG_KEY` no key can be generated or used, and sign-ins answer 503.

The metadata endpoint answers 404 until a key exists.

## Registering a service provider

All Studio operations need an administrator with completed enrollment and a passkey sign-in within the last 15 minutes, the exact confirmation text, and are audited (`saml_idp_sp_create`, `saml_idp_sp_update`, `saml_idp_sp_enable`, `saml_idp_sp_disable`, `saml_idp_sp_metadata_preview`, with `attempted`/`succeeded`/`failed`).

1. Register the Nathan application first (**Protected applications**) and grant its roles (**Roles and access**). The SP signs in only people that application allows. An application in `any_signed_in` mode lets every signed-in user in.
2. Optional: paste the SP's metadata or its HTTPS metadata URL and choose **Read metadata into the form**. Nathan reads one `EntityDescriptor` with one `SPSSODescriptor` (no DTD, at most 100 KiB; a URL must be HTTPS with a public DNS name, redirects are not followed, 5 second timeout). It pre-fills the entity ID, the HTTP-POST ACS URLs (the default one first, each with its metadata `index`), whether the SP signs AuthnRequests and its signing certificates. Nothing is saved; the preview is audited with the host (or `pasted`), never the document or URL path.
3. Fill in or review:
   - **SP ID** (lowercase letters, digits, dashes), **display name**, **bound Nathan application** (required).
   - **SP entity ID**: the Audience Nathan puts in every assertion.
   - **ACS URLs**: exact `https://` URLs, one per line, at most eight; the first is the default when a request names none. No wildcards, credentials, fragments or IP addresses. Nathan compares them as exact strings and never posts to an unregistered URL. A line may start with the URL's `AssertionConsumerServiceIndex` (`1 https://sp.example.com/acs`); the metadata preview fills these in from the SP's `index` attributes. Without indexes the URLs are numbered 0, 1, ... in the order given. Indexes are unique, 0 to 65535.
   - **NameID**: *persistent* (default) gives each user a random opaque identifier per SP, stored in D1 and stable across secret rotation; it reveals nothing about the user and differs between SPs. *Email* sends the user's verified primary email; choose it only when the SP matches users by email (AWS IAM Identity Center, often Salesforce).
   - **Attributes**: `AttributeName=source` lines. Sources: `email` (verified primary email), `name`, `roles` (the user's roles in the bound application), `permissions` (their permissions there), `groups` (only the user's groups that hold a role in the bound application), `persistent_id`. Attribute names that look like URIs get `NameFormat` `uri`, others `basic`.
   - **Require signed AuthnRequests** with the SP's signing certificate (PEM; RSA ≥ 2048, SHA-2, currently valid; up to three for rotation).
   - **Also sign the Response**: some SPs (Salesforce can) require it.
   - **Require a passkey sign-in**: see [Assurance](#assurance).
   - **Allow IdP-initiated sign-in** and an optional default RelayState: see [IdP-initiated sign-in](#idp-initiated-sign-in).
4. **Create disabled SP** (`CONFIRM CREATE SAML SP <id>`), configure the SP side, then **Enable SP** (`CONFIRM ENABLE SAML SP <id>`). **Update SP** (`CONFIRM UPDATE SAML SP <id>`) changes a live SP; **Disable SP** stops new sign-ins at once (sessions already established at the SP are the SP's).

## AWS IAM Identity Center

IAM Identity Center matches the SAML NameID against the user name of a user that already exists in Identity Center. Nathan does not push users to AWS (no outbound SCIM yet), so create the users in Identity Center with their Nathan email addresses as user names.

1. AWS console → **IAM Identity Center → Settings → Identity source → Actions → Change identity source → External identity provider**.
2. Under **Service provider metadata**, download the metadata file (or copy the **IAM Identity Center ACS URL**, of the form `https://<region>.signin.aws.amazon.com/platform/saml/acs/<id>`, and the **IAM Identity Center issuer URL**).
3. In Nathan, register the SP from that metadata (or enter the issuer URL as SP entity ID and the ACS URL), **NameID: Email**, attribute `email=email` (optional), bound to an application such as `aws`. AWS does not sign AuthnRequests; leave **Require signed AuthnRequests** off. Because the requests are unsigned, a user who is already signed in to Nathan confirms each AWS sign-in on Nathan's *Continue to … as …?* page (see [Confirmation for unsigned requests](#confirmation-for-unsigned-requests)).
4. Back in AWS, under **Identity provider metadata**, upload Nathan's metadata (`https://login.example.com/saml/idp/metadata`, saved as a file) or enter the sign-in URL, issuer URL and certificate from the table above. Review and type **ACCEPT**.
5. Enable the SP in Nathan, then sign in through the AWS access portal URL. Assign AWS accounts and permission sets in Identity Center as usual; Nathan's application roles decide only who may sign in to the portal.

Direct per-account IAM SAML federation (`https://signin.aws.amazon.com/saml`) is not supported: it needs IdP-initiated responses with `https://aws.amazon.com/SAML/Attributes/Role` ARN pairs, which Nathan does not emit.

## Salesforce

1. Salesforce Setup → **Identity → Single Sign-On Settings → Edit**, tick **SAML Enabled**, save. Choose **New** (or **New from Metadata URL** with `https://login.example.com/saml/idp/metadata`).
2. Settings:
   - **Issuer**: `https://login.example.com/saml/idp`. **Identity Provider Certificate**: Nathan's certificate.
   - **Request Signature Method**: RSA-SHA256. **Assertion Decryption Certificate**: Assertion not encrypted.
   - **SAML Identity Type**: *Assertion contains the Federation ID from the User object*; **SAML Identity Location**: *Identity is in the NameIdentifier element of the Subject statement*.
   - **Identity Provider Login URL**: `https://login.example.com/saml/idp/sso`. **Service Provider Initiated Request Binding**: HTTP Redirect (HTTP POST also works).
   - **Entity ID**: your My Domain URL, for example `https://acme.my.salesforce.com`.
3. Save. Salesforce shows the **Login URL** (the ACS URL, `https://acme.my.salesforce.com?so=00D…`) and offers its metadata. Nathan accepts that spelling without the root slash and matches it exactly.
4. In Nathan: entity ID = the Salesforce Entity ID, ACS = the Login URL, **NameID: Email**, and set each Salesforce user's **Federation ID** to their Nathan email. Salesforce signs SP-initiated AuthnRequests: paste its request-signing certificate (Setup → Certificate and Key Management) and tick **Require signed AuthnRequests**. Tick **Also sign the Response** if your org requires it.
5. Under **My Domain → Authentication Configuration**, add the new SAML configuration as a login option. Test from a private window.

## Grafana

SAML is a Grafana Enterprise and Grafana Cloud feature. Grafana's SP always has its own key pair.

```ini
[auth.saml]
enabled = true
certificate_path = /etc/grafana/saml.crt
private_key_path = /etc/grafana/saml.key
idp_metadata_url = https://login.example.com/saml/idp/metadata
# Optional: Grafana then signs its AuthnRequests; register its certificate in Nathan.
signature_algorithm = rsa-sha256
assertion_attribute_name = displayName
assertion_attribute_login = email
assertion_attribute_email = email
assertion_attribute_role = role
role_values_viewer = viewer
role_values_editor = editor
role_values_admin = admin
allow_idp_initiated = false
```

In Nathan: entity ID `https://grafana.example.com/saml/metadata`, ACS `https://grafana.example.com/saml/acs` (or read them from that metadata URL), NameID *persistent*, attributes `email=email`, `displayName=name`, `role=roles`, bound to an application `grafana` whose role keys are `viewer`, `editor` and `admin`. With `signature_algorithm` set, tick **Require signed AuthnRequests** and paste Grafana's `saml.crt`. Grafana's requested NameID format (transient by default) is ignored; see below.

## What Nathan checks on every AuthnRequest

Learned from inbound SAML ([saml.md](saml.md), threat model T24), where three guard bypasses came from parser differentials. Refusals show a Nathan error page (no Response is sent to the SP), and are audited as `saml_idp_request_rejected` with the SP (or `unknown`) and the code only, at most one row per SP, code and minute:

- **One parser.** The query (HTTP-Redirect) or form body (HTTP-POST) is parsed once by Nathan's own parser, and exactly those values are processed. Each of `SAMLRequest`, `RelayState`, `SigAlg`, `Signature` appears at most once; unknown parameters, malformed `%` escapes, empty pairs and invalid UTF-8 are refused (`saml_duplicate_parameter`, `saml_unknown_parameter`, `saml_noncanonical_encoding`). A GET must have no body (`saml_body_not_allowed`); a POST must be form-encoded (`saml_form_required`) and carry no query.
- Bounded decoding: strict base64, at most 16 KiB of query (414), 200 KB of form (413), 64 KiB of inflated XML. Form bodies are read with a byte limit: a body without `Content-Length` (chunked) is cut off as soon as it passes 200 KB, never buffered in full. The same applies to the Studio API (160 KB). At most 120 SSO requests per client IP and minute (`saml_rate_limited`, 429). No DTD, well-formed XML, SHA-1/MD5 anywhere refused (`saml_weak_algorithm`), unique `ID` attributes, exactly one `Issuer`, no `Subject`.
- The Issuer is a registered SP (`saml_unknown_sp`) and enabled (`saml_sp_disabled`).
- `AssertionConsumerServiceURL` matches a registered ACS URL exactly, or `AssertionConsumerServiceIndex` equals the registered index of one (the SP metadata's `index` value, not its position in the list), else the default ACS is used (`saml_acs_mismatch`). `ProtocolBinding`, if present, is HTTP-POST.
- `Destination`, if present, is Nathan's SSO URL; signed requests must carry it (`saml_destination_mismatch`).
- Signatures (`saml_signature_required`, `saml_bad_signature`): when the SP requires signing, an unsigned request is refused. HTTP-Redirect signatures are verified over the octets exactly as received (`SAMLRequest`, `RelayState`, `SigAlg`), RSA-SHA256/384/512 only. A POSTed request needs one enveloped signature with one Reference to the root element, only enveloped-signature and exclusive c14n transforms; Nathan then processes the bytes the signature covers, not the surrounding document. A signature that is present is verified even when not required.
- `IssueInstant` at most 5 minutes old (2 minutes clock skew), and each request `ID` is accepted once per SP (`saml_stale_request`, `saml_replayed_request`; replay cache in D1, 15 minutes).

Not honoured: `NameIDPolicy` (the administrator's NameID choice wins, so an SP cannot ask for an email where you chose a pairwise ID), `RequestedAuthnContext` (Nathan asserts only what it verified, see below), `Scoping`, `Extensions`. `ForceAuthn="true"` requires a Nathan session created after the request (older sessions are sent to sign in again). `IsPassive="true"` without a usable session ends with an error page instead of a sign-in prompt, and so does an unsigned `IsPassive` request that would need the confirmation below (`saml_passive_requires_confirmation`).

Every refusal page names its reason code in parentheses, for example `(saml_acs_mismatch)`.

## Who gets an assertion

The request is stored as a pending sign-in, and the browser gets a signed, random, single-use handle in a `__Host-nathan-saml-idp` cookie (10 minutes, `HttpOnly`, `SameSite=Lax`, only its SHA-256 is stored). Nathan redirects to `/saml/idp/continue`, a top-level GET, so the session cookie arrives even when the SP posted the request cross-site. Without a session the browser goes to `/sign-in`, and after any sign-in Nathan's start page resumes the pending request. A missing, altered or wrong-length handle is refused (`saml_resume_missing`, `saml_resume_invalid`), as are an expired and a used one (`saml_resume_expired`, `saml_resume_used`).

### Confirmation for unsigned requests

An SP's entity ID is public, so any web page can send a browser to `/saml/idp/sso` with an unsigned AuthnRequest for that SP and a RelayState of its choosing. If the browser already had a Nathan session, Nathan would otherwise post a signed assertion to the SP without the user doing anything, which amounts to IdP-initiated sign-in for an SP that never allowed it.

So when a request **has no valid SP signature naming Nathan's SSO URL as `Destination`**, and the Nathan session **existed before the request** (no sign-in happened during this flow), Nathan shows its own page: *Continue to &lt;SP display name&gt; as &lt;email&gt;?*, with the host the sign-in will go to. The page has no script, cannot be framed (`frame-ancestors 'none'`), uses a nonce-only CSP and `Referrer-Policy: same-origin`, and shows no RelayState.

- **Continue** is a same-origin form POST to `/saml/idp/continue` carrying a random token. The token is single use, valid for 5 minutes, bound to this pending request and to the session that was shown the page; only its SHA-256 is stored. A cross-site POST or one without `Origin` (`saml_cross_site_request`), a token from another page or session (`saml_confirmation_invalid`), an expired confirmation (`saml_confirmation_expired`) and a replay (`saml_resume_used`) are refused.
- **Cancel** ends the pending request and sends nothing to the SP (audited as `denied:cancelled`).
- No confirmation is asked for a request with a valid signature and Nathan as `Destination` (only the SP holds its key), or when the user signed in to Nathan during this flow (the session is newer than the request). To spare users the extra click, register the SP's signing certificate (and tick **Require signed AuthnRequests** when the SP always signs).

Then, at issuance:

- the SP is still enabled and the ACS still registered;
- the user exists, is not banned (Better Auth ban, `banExpires` honoured), is not deprovisioned by SCIM without an administrator override (NATH-11/19), is not a provisional account awaiting admission (NATH-16), and has a verified email address;
- NATH-13's evaluator allows the user for the bound application (an unknown or disabled application, or no grant, denies);
- the SP's passkey requirement is met with verified evidence for this session.

Every outcome is audited as `saml_idp_assertion` with the user as actor, the SP as target, and `issued`, `issued:idp_initiated` or `denied:<reason>` (for example `denied:no_access:no_grant`). Assertion content, NameIDs and attribute values are never logged.

## The Response

- Issuer `https://<host>/saml/idp`, `Destination` and `Recipient` = the ACS URL, `InResponseTo` = the request ID, `Audience` = the SP entity ID, bearer `SubjectConfirmation`, `NotBefore` 60 seconds before and `NotOnOrAfter` 4 minutes after issuance (5 minutes in total).
- Assertion signed (and the Response too when configured) with the active key: RSA-SHA256, SHA-256 digest, exclusive canonicalization, by xml-crypto with a WebCrypto signer. The certificate is in `KeyInfo`. No custom canonicalization code.
- Delivered by an auto-submitting HTML form to the exact ACS URL, with a nonce-only Content-Security-Policy whose `form-action` allows only the ACS origin, `Referrer-Policy: same-origin`, `Cache-Control: no-store` and no framing.

> **Staging check:** some browsers apply `form-action` to redirects that follow the form submission. If an SP's ACS redirects to another origin (AWS's ACS sends you on to the access portal), confirm on staging that the redirect is not blocked.

## Assurance

`AuthnContextClassRef` is `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified` unless Nathan holds verified evidence that this session was created by a passkey assertion, in which case it is `urn:nathan:acr:passkey` and `AuthnInstant` is the time of that assertion (the same evidence as the `nathan_acr` token claim, NATH-15). Nathan never claims MFA or an AAL from enrolled factors. **Require a passkey sign-in** refuses an assertion for a session without that evidence and asks the user to sign in with their passkey.

## IdP-initiated sign-in

Off by default. Unsolicited responses (no `InResponseTo`) are easier to misuse: the SP cannot tie the response to a request it made, so anyone who gets a user to open the link logs them in, and a stolen response is valid for any SP session start within its lifetime. When you enable it for an SP, Nathan offers `https://login.example.com/saml/idp/start/<sp id>`: a signed-in user sees a confirmation page and must press a button (a same-origin POST; cross-site posts are refused). The Response goes to the default ACS URL with the configured default RelayState. Enable it only for SPs that need it and accept unsolicited responses.

## Key rotation

1. **Generate signing key** while a key is active: the new key becomes *next* and is published in the metadata next to the active one. Nathan keeps signing with the active key.
2. Make every SP trust the new certificate: SPs that refresh metadata pick it up; for others, add the certificate by hand (Salesforce, AWS: upload the new metadata or certificate).
3. After at least 24 hours of overlap, **Activate next key** with its SHA-256 fingerprint and `CONFIRM ACTIVATE SAML IDP KEY`. Activation is refused earlier, and while a previous key still exists. The old key becomes *previous* and stays published.
4. Once every SP works with the new key, **Retire key** with the old fingerprint and `CONFIRM RETIRE SAML IDP KEY`. It leaves the metadata and its encrypted private key is deleted. The active key cannot be retired; a *next* key can be retired to cancel a rotation.

Studio warns 60 days before the active certificate expires. Key operations are audited as `saml_idp_key_generate`, `saml_idp_key_activate` and `saml_idp_key_retire`.

## Not supported (yet)

- Single logout (no SLO endpoint is published). Signing out of Nathan does not sign the user out of SPs.
- Encrypted assertions, the HTTP-Artifact binding, and SOAP/ECP.
- SAML error Responses to the SP: refusals are shown on Nathan's error page.
- Honouring `RequestedAuthnContext` or `NameIDPolicy`; constant or per-user custom attributes (AWS IAM role ARNs).
- Per-SP metadata, signed metadata, and automatic refresh of SP metadata.
- Outbound SCIM provisioning to SPs.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Metadata URL answers 404 | No signing key yet. Generate one. |
| `saml_unknown_sp` | The SP's entity ID differs from the one registered (watch trailing slashes). |
| `saml_sp_disabled` | Enable the SP in Studio. |
| `saml_acs_mismatch` | The SP sent an ACS URL that is not registered character for character. Add that exact URL. |
| `saml_signature_required` / `saml_bad_signature` | The SP must sign, signs with another key, or signs with SHA-1. Update the SP certificate in Nathan or switch the SP to RSA-SHA256. |
| `saml_stale_request` / `saml_replayed_request` | The sign-in link was old or reused (browser back button). Start again from the application. |
| "Continue to &lt;SP&gt; as &lt;you&gt;?" page | The SP sent an unsigned request and you were already signed in to Nathan. Continue if you just started signing in to that application, otherwise Cancel. Register the SP's signing certificate to skip it. |
| `saml_passive_requires_confirmation` | The SP sent an unsigned `IsPassive` request; Nathan cannot ask for confirmation silently. Sign in from the application without passive mode, or have the SP sign its requests. |
| `saml_resume_expired` / `saml_resume_used` / `saml_resume_invalid` | The pending sign-in expired (10 minutes), was already completed, or its cookie was altered. Start again from the application. |
| `saml_acs_mismatch` with an index | The SP asked for an `AssertionConsumerServiceIndex` that is not registered. Check the indexes in Studio against the SP metadata. |
| "Access denied" page | The user has no role in the bound application (`denied:no_access:no_grant` in the audit log). Grant one under Roles and access. |
| "Passkey sign-in required" | The SP requires a passkey sign-in; sign in to Nathan with a passkey. |
| The SP rejects the signature after a rotation | It has not loaded the new certificate. Re-import Nathan's metadata there. |
