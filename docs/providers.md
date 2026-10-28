# Social OAuth and enterprise SSO wizard

The intended setup wizard discovers the identity hostname and shows provider-specific callback URLs. OAuth application credentials are collected in masked prompts and stored in **Cloudflare Workers Secrets**, never in repository files.

## Google

\`\`\`sh
node scripts/nathan.mjs providers guide google
node scripts/nathan.mjs providers add google --apply
\`\`\`

Open [Google Auth Platform](https://console.cloud.google.com/auth/clients), create an OAuth Web application and configure the consent screen. Copy the exact redirect URL printed by Nathan, for example:

\`\`\`
https://auth.example.com/api/auth/callback/google
\`\`\`

Provide the Client ID and masked Client Secret. Nathan writes both as Worker secrets and does not persist them in its manifest.

## GitHub

\`\`\`sh
node scripts/nathan.mjs providers guide github
node scripts/nathan.mjs providers add github --apply
\`\`\`

Create an OAuth App at [GitHub Developer Settings](https://github.com/settings/developers). Configure the authorization callback exactly:

\`\`\`
https://auth.example.com/api/auth/callback/github
\`\`\`

Validate callback URLs and the first sign-in after setup.

## Enterprise SSO

Better Auth's SSO plugin supports enterprise OIDC and SAML **as inbound identity sources**. The code enables the plugin via \`ENTERPRISE_SSO=true\`; the admin UI must eventually provide safe provider registration, metadata validation, certificate rotation, domain verification and account-linking policies. **This interface is not yet implemented**. Nathan serving as a SAML IdP downstream is a separate future feature.

## Multi-factor authentication

Passkeys and TOTP are enabled at the Better Auth plugin level. The login UI must provide enrollment, challenge and recovery flows. Remember that successful upstream OAuth authentication is not equivalent to NIST AAL2: the IdP must verify the actual evidence before asserting an AAL claim.
