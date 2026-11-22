/**
 * The single registry for Nathan's guided social login providers (NATH-9).
 *
 * Identity Studio, the hosted installer and the CLI all read provider metadata, callback
 * URLs, setup steps and credential validation from here, and the identity Worker builds its
 * Better Auth `socialProviders` config from it. None of these services offers an API to
 * create OAuth clients, so the registry carries everything else an administrator needs.
 *
 * Email trust: a provider email is kept only when the provider itself asserts it is verified.
 * Anything else becomes a non-routable placeholder (RFC 6761 `.invalid`), so an unverified or
 * absent email can never link to, squat on, or be mistaken for a real Nathan account.
 */

export const PROVIDER_IDS = ["google", "github", "apple", "discord", "twitch", "twitter"];

/** Better Auth's OAuth callback route under the issuer's /api/auth base path. */
export const CALLBACK_PATH_PREFIX = "/api/auth/callback/";

/**
 * Exact callback (redirect) URL a provider console must be given.
 * Self-contained on purpose: the hosted installer embeds this function's source verbatim,
 * so the browser computes the same URL as the Worker and the CLI.
 * @param {string} host identity hostname or https origin, e.g. "login.example.com"
 * @param {string} id provider id
 */
export function callbackUrl(host, id) {
  var h = String(host == null ? "" : host).trim().toLowerCase();
  if (h.indexOf("https://") === 0) h = h.slice(8);
  if (h.charAt(h.length - 1) === "/") h = h.slice(0, -1);
  if (h.length > 253 || !/^(localhost|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?)(:[0-9]{1,5})?$/.test(h))
    throw new Error("Invalid identity hostname");
  if (["google", "github", "apple", "discord", "twitch", "twitter"].indexOf(id) < 0)
    throw new Error("Unsupported social provider");
  return "https://" + h + "/api/auth/callback/" + id;
}

const CLIENT_SECRET = (pattern, hint, extra = {}) => ({
  name: "clientSecret", label: "Client secret", secret: true, min: 20, max: 200, pattern, hint, ...extra
});

/** Provider definitions. `pattern` strings are shared with the browser forms. */
export const PROVIDERS = {
  google: {
    id: "google", name: "Google",
    consoleUrl: "https://console.cloud.google.com/auth/clients/create",
    docsUrl: "https://developers.google.com/identity/protocols/oauth2/web-server",
    scopes: ["openid", "email", "profile"],
    responseMode: "query",
    steps: [
      "Open Google Auth Platform → Clients → Create client, and choose application type “Web application”.",
      "Under “Authorized redirect URIs” add the callback URL below exactly. Leave “Authorized JavaScript origins” empty.",
      "On Branding and Audience, set the app name and support email. External apps stay in Testing (listed test users only) until you publish them.",
      "Create the client, then copy its Client ID and Client secret into Nathan."
    ],
    fields: [
      { name: "clientId", label: "Client ID", secret: false, min: 20, max: 200,
        pattern: "^[0-9]+-[a-z0-9]+\\.apps\\.googleusercontent\\.com$", hint: "Ends with .apps.googleusercontent.com" },
      CLIENT_SECRET("^[A-Za-z0-9_-]{20,100}$", "Usually starts with GOCSPX-")
    ],
    emailTrust: "Google's ID token email is used only when its email_verified claim is true.",
    gotchas: ["While the consent screen is in Testing, only listed test users can sign in."],
    legacyEnv: ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]
  },
  github: {
    id: "github", name: "GitHub",
    consoleUrl: "https://github.com/settings/applications/new",
    docsUrl: "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app",
    scopes: ["read:user", "user:email"],
    responseMode: "query",
    steps: [
      "Open GitHub → Settings → Developer settings → OAuth Apps → New OAuth App (use your organization's settings for an organization-owned app).",
      "Set Homepage URL to your identity origin and “Authorization callback URL” to the callback URL below exactly. Leave Device Flow off.",
      "Register the application, then choose “Generate a new client secret”.",
      "Copy the Client ID and the new client secret into Nathan. GitHub shows the secret only once."
    ],
    fields: [
      { name: "clientId", label: "Client ID", secret: false, min: 16, max: 40,
        pattern: "^[A-Za-z0-9.]{16,40}$", hint: "For example Ov23li… (OAuth App) or Iv… (GitHub App)" },
      CLIENT_SECRET("^[0-9a-f]{40}$", "40 lowercase hexadecimal characters", { min: 40, max: 40 })
    ],
    emailTrust: "Only the account's primary email, and only when GitHub marks it verified. A public profile email is ignored.",
    gotchas: ["A GitHub App needs the “Email addresses” read-only account permission for Nathan to see the primary email."],
    legacyEnv: ["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"]
  },
  apple: {
    id: "apple", name: "Apple",
    consoleUrl: "https://developer.apple.com/account/resources/identifiers/list/serviceId",
    docsUrl: "https://developer.apple.com/help/account/configure-app-capabilities/configure-sign-in-with-apple-for-the-web",
    scopes: ["name", "email"],
    responseMode: "form_post",
    steps: [
      "In Certificates, Identifiers & Profiles, make sure an App ID has the “Sign in with Apple” capability (this is the primary App ID).",
      "Identifiers → + → Services IDs: register an identifier such as com.example.login. This Services ID is Nathan's Client ID.",
      "Enable “Sign in with Apple” on the Services ID → Configure: choose the primary App ID, add your identity hostname under Domains and Subdomains, and add the callback URL below under Return URLs.",
      "Keys → + : enable “Sign in with Apple”, configure it with the same primary App ID, register it and download the .p8 file. Apple lets you download it only once. Note the Key ID.",
      "Copy your Team ID from Membership details, then paste the Services ID, Team ID, Key ID and the .p8 file contents into Nathan."
    ],
    fields: [
      { name: "clientId", label: "Services ID", secret: false, min: 3, max: 150,
        pattern: "^[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$", hint: "Reverse-DNS identifier, e.g. com.example.login" },
      { name: "teamId", label: "Team ID", secret: false, min: 10, max: 10, pattern: "^[A-Z0-9]{10}$", hint: "10 characters, from Membership details" },
      { name: "keyId", label: "Key ID", secret: false, min: 10, max: 10, pattern: "^[A-Z0-9]{10}$", hint: "10 characters, shown with the key" },
      { name: "privateKey", label: "Private key (.p8)", secret: true, multiline: true, file: ".p8", min: 200, max: 1200,
        pattern: "^-----BEGIN PRIVATE KEY-----\\n[A-Za-z0-9+/=\\n]+\\n-----END PRIVATE KEY-----$",
        hint: "Paste the whole AuthKey_XXXXXXXXXX.p8 file, including the BEGIN and END lines" }
    ],
    emailTrust: "Apple's ID token email is used only when email_verified is true (Hide My Email relay addresses are verified relay addresses).",
    gotchas: [
      "Apple posts the response back (response_mode=form_post), so the callback must be reachable by a cross-site POST.",
      "Apple sends the user's name only on the very first authorization.",
      "Return URLs must be HTTPS on a registered domain; localhost and IP addresses are rejected.",
      "To email Hide My Email (privaterelay.appleid.com) addresses you must register your sending domain under Sign in with Apple for Email Communication.",
      "Nathan mints the client secret from the .p8 key for at most one hour at a time; rotating the key in Apple's console requires updating it here."
    ],
    legacyEnv: null
  },
  discord: {
    id: "discord", name: "Discord",
    consoleUrl: "https://discord.com/developers/applications",
    docsUrl: "https://discord.com/developers/docs/topics/oauth2",
    scopes: ["identify", "email"],
    responseMode: "query",
    steps: [
      "Open the Discord Developer Portal → Applications → New Application and give it a name.",
      "Open OAuth2 → Redirects → Add Redirect, paste the callback URL below exactly and save.",
      "Copy the Client ID, then choose “Reset Secret” to reveal a client secret.",
      "Paste both into Nathan. Do not enable “Public Client”."
    ],
    fields: [
      { name: "clientId", label: "Client ID", secret: false, min: 17, max: 20, pattern: "^[0-9]{17,20}$", hint: "Numeric application ID" },
      CLIENT_SECRET("^[A-Za-z0-9_-]{32,64}$", "32 characters", { min: 32, max: 64 })
    ],
    emailTrust: "Discord's email is used only when the account's verified flag is true.",
    gotchas: ["Discord users can sign up with unverified emails; those accounts get a placeholder email in Nathan and never link by email."],
    legacyEnv: null
  },
  twitch: {
    id: "twitch", name: "Twitch",
    consoleUrl: "https://dev.twitch.tv/console/apps/create",
    docsUrl: "https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/",
    scopes: ["openid", "user:read:email"],
    responseMode: "query",
    steps: [
      "Open the Twitch Developer Console → Applications → Register Your Application (two-factor authentication must be on).",
      "Add the callback URL below under OAuth Redirect URLs, choose a category, and set Client Type to “Confidential”.",
      "Create the application, open Manage, copy the Client ID and choose “New Secret”.",
      "Paste both into Nathan. Nathan requests the email and email_verified ID-token claims."
    ],
    fields: [
      { name: "clientId", label: "Client ID", secret: false, min: 30, max: 30, pattern: "^[a-z0-9]{30}$", hint: "30 lowercase letters and digits" },
      CLIENT_SECRET("^[a-z0-9]{30}$", "30 lowercase letters and digits", { min: 30, max: 30 })
    ],
    emailTrust: "Twitch's email is used only when the email_verified ID-token claim, which Nathan explicitly requests, is true.",
    gotchas: ["The redirect URL must match exactly, including the absence of a trailing slash."],
    legacyEnv: null
  },
  twitter: {
    id: "twitter", name: "X",
    consoleUrl: "https://developer.x.com/en/portal/projects-and-apps",
    docsUrl: "https://docs.x.com/resources/fundamentals/authentication/oauth-2-0/authorization-code",
    scopes: ["users.read", "tweet.read", "users.email", "offline.access"],
    responseMode: "query",
    steps: [
      "Open the X Developer Portal → Projects & Apps, open your app and choose User authentication settings → Set up.",
      "Set App permissions to Read and turn on “Request email from users” (this needs Terms of Service and Privacy Policy URLs).",
      "Choose Type of App “Web App, Automated App or Bot” (a confidential client).",
      "Add the callback URL below as the Callback URI / Redirect URL, set Website URL to your identity origin, and save.",
      "Copy the OAuth 2.0 Client ID and Client Secret into Nathan (not the API Key and Secret, which are for OAuth 1.0a)."
    ],
    fields: [
      { name: "clientId", label: "OAuth 2.0 Client ID", secret: false, min: 20, max: 64, pattern: "^[A-Za-z0-9_-]{20,64}$", hint: "From Keys and tokens → OAuth 2.0 Client ID and Client Secret" },
      CLIENT_SECRET("^[A-Za-z0-9_-]{40,100}$", "About 50 characters", { min: 40, max: 100 })
    ],
    emailTrust: "X returns a confirmed email only when the app has email access. Without one, Nathan stores a non-routable placeholder and never links X accounts by email.",
    gotchas: [
      "Email access needs “Request email from users”, which X grants only with Terms of Service and Privacy Policy URLs.",
      "X always uses PKCE; Nathan sends an S256 code challenge."
    ],
    legacyEnv: null
  }
};

/** Name of the optional Worker secret holding one provider's credential bundle as JSON (CLI path). */
export function envBundleName(id) {
  return "NATHAN_PROVIDER_" + String(id).toUpperCase();
}

/**
 * An error whose message is safe to show an administrator: it names providers and fields
 * but never contains a submitted value.
 */
export function inputError(message) {
  const e = new Error(message);
  e.publicMessage = message;
  return e;
}

function hasProvider(id) {
  return typeof id === "string" && PROVIDER_IDS.includes(id);
}
export function getProvider(id) {
  if (!hasProvider(id)) throw inputError("Unsupported social provider");
  return PROVIDERS[id];
}
export function displayName(id) {
  return hasProvider(id) ? PROVIDERS[id].name : String(id);
}
export function secretFieldNames(id) {
  return getProvider(id).fields.filter(f => f.secret).map(f => f.name);
}
export function publicFieldNames(id) {
  return getProvider(id).fields.filter(f => !f.secret).map(f => f.name);
}

function normalize(field, value) {
  if (field.multiline) return value.replace(/\r\n?/g, "\n").trim();
  return value.trim();
}
/**
 * Validates and normalises one provider's credentials. Accepts `{fields:{...}}`, or the
 * flat legacy shape `{id, clientId, clientSecret}`. Unknown keys are dropped. Error
 * messages name the field but never echo a value.
 */
export function validateProviderCredentials(id, input) {
  const provider = getProvider(id);
  if (!input || typeof input !== "object" || Array.isArray(input)) throw inputError("Provider credentials are required");
  const source = input.fields && typeof input.fields === "object" && !Array.isArray(input.fields) ? input.fields : input;
  const values = {};
  for (const field of provider.fields) {
    const raw = Object.prototype.hasOwnProperty.call(source, field.name) ? source[field.name] : undefined;
    if (typeof raw !== "string" || raw.length > 16384) throw inputError(provider.name + " " + field.label + " is missing or invalid");
    const value = normalize(field, raw);
    if (value.length < field.min || value.length > field.max || !new RegExp(field.pattern).test(value))
      throw inputError(provider.name + " " + field.label + " has the wrong format" + (field.hint ? " (" + field.hint + ")" : ""));
    values[field.name] = value;
  }
  return values;
}

/** Public guide for one provider; contains no credential values. */
export function providerGuide(id, host) {
  const p = getProvider(id);
  return {
    id: p.id, name: p.name, consoleUrl: p.consoleUrl, docsUrl: p.docsUrl,
    callbackUrl: callbackUrl(host, p.id), responseMode: p.responseMode, scopes: [...p.scopes],
    steps: [...p.steps], gotchas: [...p.gotchas], emailTrust: p.emailTrust,
    fields: p.fields.map(f => ({ ...f }))
  };
}
export function providerGuides(host) {
  return PROVIDER_IDS.map(id => providerGuide(id, host));
}
/** Data the hosted installer page embeds: the registry and the callback function's source. */
export function installerRegistry() {
  return {
    callbackUrlSource: callbackUrl.toString(),
    providers: PROVIDER_IDS.map(id => {
      const p = PROVIDERS[id];
      return { id: p.id, name: p.name, consoleUrl: p.consoleUrl, steps: [...p.steps], gotchas: [...p.gotchas],
        emailTrust: p.emailTrust, responseMode: p.responseMode, fields: p.fields.map(f => ({ ...f })) };
    })
  };
}

/** Non-routable, stable address for a provider account without a provider-verified email. */
export function placeholderEmail(id, subject) {
  const local = String(subject ?? "").replace(/[^A-Za-z0-9._-]/g, "-").replace(/^[.-]+|[.-]+$/g, "").slice(0, 64) || "unknown";
  return local + "@" + id + ".placeholder.invalid";
}
const verifiedOnly = (id, subject, email, verified) =>
  verified === true && typeof email === "string" && email.includes("@")
    ? { emailVerified: true }
    : { email: placeholderEmail(id, subject), emailVerified: false };

/**
 * Better Auth account linking. No provider is trusted by name, so implicit linking happens
 * only when the provider asserts a verified email AND the existing Nathan user's email is
 * verified. Different-email linking and profile overwrite on link stay off.
 */
export const ACCOUNT_LINKING = Object.freeze({
  enabled: true, trustedProviders: [], requireLocalEmailVerified: true,
  allowDifferentEmails: false, updateUserInfoOnLink: false
});

async function githubUserInfo(token, fetcher) {
  const headers = { Authorization: "Bearer " + token.accessToken, "User-Agent": "nathan-idp", Accept: "application/vnd.github+json" };
  const profileResponse = await fetcher("https://api.github.com/user", { headers });
  if (!profileResponse.ok) return null;
  const profile = await profileResponse.json();
  if (!profile || (typeof profile.id !== "number" && typeof profile.id !== "string")) return null;
  let primary = null;
  const emailsResponse = await fetcher("https://api.github.com/user/emails", { headers });
  if (emailsResponse.ok) {
    const emails = await emailsResponse.json().catch(() => null);
    if (Array.isArray(emails)) primary = emails.find(e => e && e.primary === true && e.verified === true && typeof e.email === "string") || null;
  }
  return {
    user: {
      name: profile.name || profile.login || "",
      image: profile.avatar_url,
      ...(primary ? { email: primary.email, emailVerified: true } : { email: placeholderEmail("github", profile.id), emailVerified: false })
    },
    data: profile
  };
}

/**
 * Builds Better Auth `socialProviders` from resolved credentials. Every provider gets
 * `{clientId, clientSecret}` (Apple's is the minted client-secret JWT) plus the mapping that
 * enforces the email trust rule. Nothing here changes sign-up policy, so whatever admission
 * rule Nathan applies to new users applies identically to every provider.
 * @param {Record<string,{clientId:string,clientSecret:string}>} resolved
 * @param {{fetch?: typeof fetch}} [options]
 */
export function buildSocialProviders(resolved, options = {}) {
  const fetcher = options.fetch || ((input, init) => fetch(input, init));
  const out = {};
  for (const id of PROVIDER_IDS) {
    const c = resolved && Object.prototype.hasOwnProperty.call(resolved, id) ? resolved[id] : null;
    if (!c || typeof c.clientId !== "string" || typeof c.clientSecret !== "string") continue;
    // Nathan's sign-in uses only the redirect flow. Direct ID-token sign-in/linking would
    // accept a leaked provider ID token for Nathan's client id without state, PKCE or nonce.
    const base = { clientId: c.clientId, clientSecret: c.clientSecret, disableIdTokenSignIn: true };
    if (id === "google") out.google = { ...base,
      mapProfileToUser: p => verifiedOnly("google", p.sub, p.email, p.email_verified) };
    else if (id === "github") out.github = { ...base,
      getUserInfo: token => githubUserInfo(token, fetcher) };
    else if (id === "apple") out.apple = { ...base,
      mapProfileToUser: p => verifiedOnly("apple", p.sub, p.email, p.email_verified === true || p.email_verified === "true") };
    else if (id === "discord") out.discord = { ...base,
      mapProfileToUser: p => verifiedOnly("discord", p.id, p.email, p.verified) };
    else if (id === "twitch") out.twitch = { ...base,
      claims: ["email", "email_verified", "preferred_username", "picture"],
      mapProfileToUser: p => verifiedOnly("twitch", p.sub, p.email, p.email_verified) };
    else if (id === "twitter") out.twitter = { ...base,
      // Better Auth sets data.email only from X's confirmed_email field.
      mapProfileToUser: p => verifiedOnly("twitter", p?.data?.id, p?.data?.email, Boolean(p?.data?.email)) };
  }
  return out;
}
