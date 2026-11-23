/**
 * NATH-38: the hosted end-user pages in stock Kumo (sign-in, OIDC consent, MCP consent and
 * connections, SAML IdP pages). Security properties of the old String.raw pages, in the new form:
 * no inline script (islands only, nonce + SRI), script-src 'none' where nothing runs, exact
 * form-action, escaping, fixed reason codes, and the appearance hook (empty = stock Kumo).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { rewriteTags } from "../src/ui/csp-styles.ts";

assert.ok(existsSync("src/ui/generated/ui-manifest.json"), "run `node scripts/build-ui.mjs` first (npm test does)");
await mkdir(".nathan/test-ui", { recursive: true });
const outfile = ".nathan/test-ui/hosted-pages.mjs";
await build({
  entryPoints: ["tests/fixtures/hosted-pages.ts"], outfile, bundle: true, platform: "node", format: "esm",
  jsx: "automatic", packages: "external", logLevel: "error", logOverride: { "module-level-directive": "silent" }
});
const ui = await import(pathToFileURL(outfile).href + "?" + Date.now());

const csp = r => r.headers.get("content-security-policy");
const tags = html => {
  const out = [];
  rewriteTags(html, tag => { out.push({ name: tag.name, attrs: Object.fromEntries(tag.attributes.map(a => [a.name, a.value])) }); });
  return out;
};
/** Every <script>: only the importmap and SRI-pinned same-origin island modules, all nonce'd, none inline. */
function assertIslandScripts(response, html, islands) {
  const nonce = /'nonce-([^']+)'/.exec(csp(response))[1];
  const scripts = [...html.matchAll(/<script\b([^>]*)>([^]*?)<\/script>/g)];
  for (const [, attrs] of scripts) assert.match(attrs, new RegExp('nonce="' + nonce.replace(/[+/=]/g, "\\$&") + '"'));
  const modules = scripts.filter(([, attrs]) => !/type="importmap"/.test(attrs));
  assert.deepEqual(modules.map(([, , body]) => body), modules.map(() => ""), "no inline code");
  assert.deepEqual(modules.map(([, attrs]) => /src="([^"]+)"/.exec(attrs)[1]), islands.map(id => ui.UI_MANIFEST.islands[id].src));
  for (const [, attrs] of modules) assert.match(attrs, /integrity="sha384-/);
  assert.match(csp(response), /script-src 'self' 'nonce-/);
}
const common = response => {
  const c = csp(response);
  for (const d of ["default-src 'none'", "img-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"]) assert.ok(c.includes(d), d);
  assert.equal(response.headers.get("Referrer-Policy"), "same-origin");
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(response.headers.get("X-Frame-Options"), "DENY");
};

// ---- Sign-in ---------------------------------------------------------------------------------

test("sign-in: providers with icons, passkey, SSO and password, behaviour only in the sign-in island", async () => {
  const response = ui.signInPage(["google", "github"], true, true, { issuer: "id.example.com" });
  const html = await response.text();
  common(response);
  assert.match(csp(response), /form-action 'self';/);
  assertIslandScripts(response, html, ["sign-in"]);
  assert.doesNotMatch(html, /\sstyle=|\son[a-z]+=/i);
  for (const name of ["Google", "GitHub"]) assert.ok(html.includes("Continue with " + name), name);
  const all = tags(html);
  const providers = all.filter(t => t.name === "button" && t.attrs["data-provider"]);
  assert.deepEqual(providers.map(t => t.attrs["data-provider"]), ["google", "github"]);
  assert.ok(providers.every(t => "disabled" in t.attrs && "data-needs-script" in t.attrs), "nothing looks usable before its script runs");
  assert.ok(providers.every(t => /\bnathan-block\b/.test(t.attrs.class)), "full-width provider buttons");
  assert.ok(all.some(t => t.name === "button" && "data-passkey" in t.attrs));
  // Password and SSO forms post (never GET, so a password can never land in a URL) to Nathan itself.
  for (const form of all.filter(t => t.name === "form")) {
    assert.equal(form.attrs.method, "post"); assert.equal(form.attrs.action, "/sign-in");
  }
  assert.ok(all.some(t => t.name === "input" && t.attrs.name === "password" && t.attrs.type === "password"));
  assert.ok(all.some(t => t.name === "form" && "data-two-factor" in t.attrs && "hidden" in t.attrs), "TOTP challenge hidden until asked for");
  assert.ok(html.includes("Identity provider: id.example.com (Nathan)"), "issuer footer");
});

test("sign-in: password and SSO only when enabled; an unknown provider gets the generic icon, escaped", async () => {
  const html = await ui.signInPage(["x\"<y"], false, false).text();
  assert.doesNotMatch(html, /name="password"|data-sso/);
  assert.ok(!html.includes("x\"<y") && html.includes("Continue with x&quot;&lt;y"));
});

test("sign-in island keeps the signed oauth_query on every request and follows d.url", () => {
  const src = ui.UI_MANIFEST.islands["sign-in"].src;
  const js = readFileSync(".nathan/ui-assets" + src, "utf8");
  for (const path of ["/sign-in/social", "/sign-in/email", "/two-factor/verify-totp", "/passkey/verify-authentication", "/sign-in/sso/start"])
    assert.ok(js.includes(path), path);
  assert.equal((js.match(/oauth_query/g) ?? []).length, 1, "one withOAuth helper");
  assert.match(js, /typeof \w+\.url\s*===?\s*"string"/, "land(d) follows the resumed authorization's d.url");
  assert.match(js, /errorCallbackURL:\s*"\/sign-in"/);
  assert.match(js, /credentials:\s*"same-origin"/);
  assert.doesNotMatch(js, /innerHTML|insertAdjacentHTML|document\.write/, "messages use textContent");
  assert.match(js, /ba_param/, "signedOAuthQuery is bundled into the island");
});

test("sign-in explains a refused sign-in on the server, with its reason code; malformed codes are not echoed", async () => {
  const known = await ui.signInPage([], false, false, { error: "ACCOUNT_NOT_ADMITTED" }).text();
  assert.ok(known.includes(ui.SIGN_IN_ERRORS.ACCOUNT_NOT_ADMITTED + " (ACCOUNT_NOT_ADMITTED)"));
  assert.match(known, /<div data-sign-in-error="" role="alert">/, "shown, not hidden");
  assert.ok((await ui.signInPage([], false, false, { error: "SOMETHING_ELSE" }).text()).includes("Sign-in failed (SOMETHING_ELSE)."));
  for (const bad of ["<script>", "a b", "x".repeat(65), ""]) assert.equal(ui.signInErrorMessage(bad), null, bad);
  const hostile = await ui.signInPage([], false, false, { error: "<img src=x>" }).text();
  assert.ok(!hostile.includes("<img") && !hostile.includes("&lt;img"));
});

// ---- Appearance hook -------------------------------------------------------------------------

test("no appearance is stock Kumo: no appearance CSS, no plate; gmacko's appearance restyles but cannot touch fixed text", async () => {
  const stock = await ui.signInPage(["github"], true, false, { issuer: "id.gmac.io" }).text();
  assert.doesNotMatch(stock, /data-nathan-appearance|nathan-plate|--nathan-/);
  const empty = await ui.signInPage(["github"], true, false, { issuer: "id.gmac.io", appearance: ui.resolveAppearance() }).text();
  const unNonce = h => h.replace(/nonce="[^"]+"/g, 'nonce=""');
  assert.ok(unNonce(empty) === unNonce(stock), "an empty appearance is byte-for-byte stock (apart from the nonce)");

  const gmacko = ui.resolveAppearance(JSON.parse(readFileSync("docs/appearance/gmacko.json", "utf8")));
  const response = ui.signInPage(["github"], true, false, { issuer: "id.gmac.io", appearance: gmacko });
  const html = await response.text();
  const nonce = /'nonce-([^']+)'/.exec(csp(response))[1];
  assert.ok(html.includes('<style nonce="' + nonce + '" data-nathan-appearance>[data-theme="nathan"]{--nathan-plate:#2041D9'), "appearance CSS in a nonce'd block");
  assert.match(html, /<div class="nathan-hosted nathan-hosted-left"><div class="nathan-plate" aria-hidden="true">/);
  assert.ok(html.includes(">gmacko</span>"), "wordmark");
  assert.ok(html.includes("Identity provider: id.gmac.io (Nathan)"), "the issuer footer stays");
  // Passkey is gmacko's primary method: the passkey button is the only primary one.
  const primary = tags(html).filter(t => t.name === "button" && /emphasis-bg/.test(t.attrs.class ?? "") && !("data-totp" in t.attrs));
  assert.equal(primary.length, 1); assert.ok("data-passkey" in primary[0].attrs);

  const consent = await ui.consentPage(true, "app-1", "openid email", { issuer: "id.gmac.io", appearance: gmacko }).text();
  assert.ok(consent.includes("app-1 → id.gmac.io") && consent.includes("Requested scopes: openid email"), "route line and scope text stay");
});

test("primaryMethod picks one primary action among the enabled methods, falling back to passkey", async () => {
  const pick = async (layout, providers = ["github"], password = true) => {
    const a = ui.resolveAppearance({ layout });
    const html = await ui.signInPage(providers, password, false, { appearance: a }).text();
    return tags(html).filter(t => t.name === "button" && /emphasis-bg/.test(t.attrs.class ?? "") && !("data-totp" in t.attrs))
      .map(t => t.attrs["data-provider"] ?? ("data-passkey" in t.attrs ? "passkey" : "email"));
  };
  assert.deepEqual(await pick({ primaryMethod: "provider:github" }), ["github"]);
  assert.deepEqual(await pick({ primaryMethod: "email" }), ["email"]);
  assert.deepEqual(await pick({}), ["passkey"], "passkey by default");
  assert.deepEqual(await pick({ primaryMethod: "provider:google" }), ["passkey"], "a provider that is not enabled is never primary");
  assert.deepEqual(await pick({ primaryMethod: "email" }, [], false), ["passkey"], "email without passwords falls back");
  const icons = await ui.signInPage(["github"], false, false, { appearance: ui.resolveAppearance({ layout: { socialButtonsVariant: "iconButton" } }) }).text();
  assert.match(icons, /aria-label="Continue with GitHub"/, "icon-only buttons keep an accessible name");
});

// ---- OIDC consent ----------------------------------------------------------------------------

test("OIDC consent: the request in the heading, scope text, Allow/Deny only via the consent island", async () => {
  const response = ui.consentPage(true, "Example <app>", "openid profile email", { issuer: "id.example.com" });
  const html = await response.text();
  common(response);
  assertIslandScripts(response, html, ["oauth-consent"]);
  assert.match(html, /<h1 class="nathan-title">Example &lt;app&gt; wants to access your account<\/h1>/);
  assert.ok(html.includes("Requested scopes: openid profile email"));
  assert.ok(html.includes("Example &lt;app&gt; → id.example.com"), "route line");
  const buttons = tags(html).filter(t => t.name === "button");
  assert.deepEqual(buttons.map(t => t.attrs["data-consent"]), ["allow", "deny"]);
  const js = readFileSync(".nathan/ui-assets" + ui.UI_MANIFEST.islands["oauth-consent"].src, "utf8");
  assert.match(js, /\/api\/auth\/oauth2\/consent/); assert.match(js, /oauth_query/); assert.match(js, /credentials:\s*"same-origin"/);
});

test("OIDC consent refuses an unverified request with a reason code and no script", async () => {
  const response = ui.consentPage(false, "x", "openid");
  assert.equal(response.status, 400);
  assert.match(csp(response), /script-src 'none'/); assert.match(csp(response), /form-action 'none'/);
  assert.ok((await response.text()).includes("(oauth_consent_invalid)"));
});

// ---- MCP -------------------------------------------------------------------------------------

const entry = (scope, extra = {}) => ({ scope, label: "Label " + scope, description: "", group: "g", requires: [], sensitive: false, adminOnly: false, ...extra });
function mcpView(over = {}) {
  const entries = [entry("n:read"), entry("n:write", { requires: ["n:read"] }), entry("n:export", { sensitive: true, group: "bulk" })];
  return {
    ticket: "tick\"et", clientName: "Bad <b>client</b>", clientId: "nmcp_1", redirectOrigin: "http://127.0.0.1:33418",
    resourceName: "Notes", resource: "https://notes.example/mcp", email: "a@example.test", entries,
    byScope: new Map(entries.map(e => [e.scope, e])), full: "n:full", offered: new Set(entries.map(e => e.scope)),
    checked: new Set(["n:write"]), unavailable: [], issuer: "id.example.com", ...over
  };
}

test("MCP consent: script-free form, exact callback origin in form-action, native checkboxes with the true state", async () => {
  const response = ui.mcpConsentPage(mcpView());
  const html = await response.text();
  common(response);
  assert.match(csp(response), /script-src 'none'/);
  assert.match(csp(response), /form-action 'self' http:\/\/127\.0\.0\.1:33418;/);
  assert.doesNotMatch(html, /<script/);
  assert.ok(!html.includes("<b>client") && html.includes("Bad &lt;b&gt;client&lt;/b&gt;"), "client-chosen name escaped");
  assert.ok(html.includes('name="ticket" value="tick&quot;et"'));
  const boxes = tags(html).filter(t => t.name === "input" && t.attrs.type === "checkbox");
  assert.deepEqual(boxes.map(b => [b.attrs.value, "checked" in b.attrs]), [["n:full", false], ["n:read", false], ["n:write", true], ["n:export", false]]);
  assert.ok(!html.includes('role="checkbox"'), "no script-drawn checkbox");
  assert.match(html, />sensitive<\/span>/);
  const form = tags(html).find(t => t.name === "form");
  assert.equal(form.attrs.method, "post"); assert.equal(form.attrs.action, "/mcp-oauth/authorize");
  assert.ok(html.includes("n:full</code>") && html.includes("Sensitive permissions are never included"), "the Full access warning is fixed text");
});

test("MCP consent and connections refuse a non-loopback http or non-origin callback in form-action", () => {
  assert.throws(() => ui.mcpConsentPage(mcpView({ redirectOrigin: "http://evil.example" })), /form-action/);
  assert.throws(() => ui.mcpConsentPage(mcpView({ redirectOrigin: "https://app.example/cb" })), /form-action/);
  assert.ok(ui.mcpConsentPage(mcpView({ redirectOrigin: "https://app.example" })));
});

test("MCP connections and error pages run no script and escape", async () => {
  const v = { ...mcpView(), grantId: "g1", createdAt: 0, expiresAt: 86400, effective: [] };
  const page = ui.connectionsPage("a<@example.test", "csrf1", [v], { ok: false, message: "<bad>" });
  const html = await page.text();
  assert.match(csp(page), /script-src 'none'/); assert.match(csp(page), /form-action 'self';/);
  assert.ok(html.includes("Usable now: nothing (you no longer hold any of these permissions)."));
  assert.ok(html.includes('name="csrf" value="csrf1"') && html.includes('name="grant" value="g1"'));
  assert.ok(!html.includes("<bad>") && !html.includes("a<@"));
  const error = ui.mcpErrorPage("Consent expired", "Already <answered>.", 400);
  assert.equal(error.status, 400);
  assert.match(csp(error), /script-src 'none'/);
  const text = await error.text();
  assert.ok(text.includes("Already &lt;answered&gt;.") && text.includes("Nothing was granted."));
});

// ---- SAML IdP --------------------------------------------------------------------------------

test("SAML refusal: RefusalPage with the reason code, no script, no form target", async () => {
  const r = ui.samlRefusalPage("Sign in first", "Sign in <now>.", "saml_sign_in_required", { status: 401, signIn: true });
  assert.equal(r.status, 401);
  common(r);
  assert.match(csp(r), /script-src 'none'/); assert.match(csp(r), /form-action 'none'/);
  assert.equal(r.headers.get("Pragma"), "no-cache");
  const html = await r.text();
  assert.ok(html.includes("Sign in &lt;now&gt;. (saml_sign_in_required)"));
  assert.match(html, /href="\/sign-in"/);
  assert.equal(ui.samlRefusalPage("Nope", "x", "saml_x").status, 403, "403 by default");
});

test("SAML confirmation pages: same-origin POST, no script; auto-POST: only the SRI-pinned auto-post island", async () => {
  const confirm = ui.ssoConfirmPage({ spName: "G <P> & \"O\"", email: "j@x", acsHost: "sp.example", token: "tok_1", issuer: "id.example.com" });
  const html = await confirm.text();
  assert.match(csp(confirm), /script-src 'none'/); assert.match(csp(confirm), /form-action 'self';/);
  assert.ok(html.includes("Continue to G &lt;P&gt; &amp; &quot;O&quot; as j@x?"));
  const form = tags(html).find(t => t.name === "form");
  assert.equal(form.attrs.action, "/saml/idp/continue");
  assert.ok(tags(html).some(t => t.name === "input" && t.attrs.name === "confirm" && t.attrs.value === "tok_1"));

  const start = await ui.idpInitiatedPage({ spId: "grafana", spName: "Grafana", email: "j@x" }).text();
  assert.equal(tags(start).find(t => t.name === "form").attrs.action, "/saml/idp/start/grafana");

  const post = ui.autoPostPage({ acsUrl: "https://sp.example/acs?a=1", samlResponse: "PHM+", relayState: "r\"<", spName: "SP", issuer: "id.example.com" });
  const postHtml = await post.text();
  assertIslandScripts(post, postHtml, ["auto-post"]);
  assert.match(csp(post), /form-action https:\/\/sp\.example;/);
  assert.equal(post.headers.get("Pragma"), "no-cache");
  assert.ok(!postHtml.includes("r\"<"));
});

test("form-action accepts a loopback http callback origin (RFC 8252) and nothing else over http", async () => {
  const { formActionSource } = await import("../src/ui/headers.ts");
  for (const ok of ["http://127.0.0.1:33418", "http://localhost:8080", "http://[::1]:9000", "https://app.example"])
    assert.equal(formActionSource(ok), ok);
  for (const bad of ["http://app.example", "http://127.0.0.1:1/cb", "http://127.0.0.2", "javascript:alert(1)", "http://localhost.evil.example"])
    assert.throws(() => formActionSource(bad), /form-action/, bad);
});

// ---- Independent review 2026-11-23 ---------------------------------------------------------------

test("form-action: https needs an exact DNS host, http only exact loopback origins", async () => {
  const { formActionSource } = await import("../src/ui/headers.ts");
  for (const ok of ["https://sp.example.com", "https://sp.example.com:8443", "http://127.0.0.1:33418", "http://localhost:8080", "http://[::1]:5000"])
    assert.equal(formActionSource(ok), ok, ok);
  for (const bad of ["https://*", "https://*.evil.com", "http://evil.com", "http://127.0.0.2:1", "http://localhost.evil.com", "http://127.0.0.1:1/cb", "https://a_b.example"])
    assert.throws(() => formActionSource(bad), /form-action/, bad);
});

test("MCP dynamic registration refuses format characters in client_name", async () => {
  const { parseRegistration } = await import("../src/shared/mcp-scopes.mjs");
  assert.throws(() => parseRegistration({ client_name: "Notes\u202Etxe.exe", redirect_uris: ["https://c.example.com/cb"] }), /client_name/);
  assert.throws(() => parseRegistration({ client_name: "Na\u200Bthan", redirect_uris: ["https://c.example.com/cb"] }), /client_name/);
  assert.equal(parseRegistration({ client_name: "Notes desktop", redirect_uris: ["https://c.example.com/cb"] }).client_name, "Notes desktop");
});

test("MCP consent: fixed heading; the route line is the callback host, never the client-chosen name", async () => {
  const html = await ui.mcpConsentPage(mcpView({ clientName: "id.example.com", redirectOrigin: "https://app.example", issuer: "login.example.test" })).text();
  assert.match(html, /<h1[^>]*>Connect an MCP client<\/h1>/);
  assert.ok(html.includes("app.example → login.example.test"), "route line from the validated callback host");
  assert.ok(!html.includes("id.example.com → "), "the client name is not the route line");
  assert.ok(html.includes("“id.example.com”"), "the client name is quoted in the body");
  assert.match(html, /not verified by Nathan/);
});

test("every redirect URI MCP registration accepts yields a form-action the consent page can send", async () => {
  const { validateRedirectUri, parseRegistration } = await import("../src/shared/mcp-scopes.mjs");
  const { formActionSource } = await import("../src/ui/headers.ts");
  const candidates = ["https://app.example.com/cb", "https://app.example.com:8443/cb?x=1", "http://127.0.0.1:33418/cb", "http://localhost/cb",
    "http://[::1]:5000/cb", "https://[2001:db8::1]/cb", "https://a_b.example.com/cb", "https://example.com./cb", "https://a!b.example/cb",
    "https://a$b.example/cb", "https://xn--bcher-kva.example/cb", "https://1.2.3.4/cb"];
  for (const uri of candidates) {
    if (validateRedirectUri(uri) === null) continue;
    assert.doesNotThrow(() => formActionSource(new URL(uri).origin), uri);
  }
  for (const bad of ["https://[2001:db8::1]/cb", "https://a_b.example.com/cb", "https://example.com./cb"])
    assert.equal(validateRedirectUri(bad), null, bad);
  assert.throws(() => parseRegistration({ client_name: "x", redirect_uris: ["https://a_b.example.com/cb"] }, new Set()), /redirect/i);
});

test("client_name refuses invisible and separator characters, and is normalized", async () => {
  const { parseRegistration } = await import("../src/shared/mcp-scopes.mjs");
  const reg = name => parseRegistration({ client_name: name, redirect_uris: ["https://c.example.com/cb"] }, new Set());
  for (const bad of ["a b", "a b", "a\u0085b", "́abc", "a͏b", "aㅤb", "a\uD800b", "ab"])
    assert.throws(() => reg(bad), /invisible|control/, JSON.stringify(bad));
  assert.equal(reg("Notes   desktop ").client_name, "Notes desktop");
  assert.equal(reg("Café").client_name, "Café");
});

test("SAML ACS URLs need the same DNS host form-action accepts", async () => {
  const { checkAcsUrl } = await import("../src/auth/saml-idp-protocol.mjs");
  for (const bad of ["https://a_b.example.com/acs", "https://example.com./acs"]) assert.throws(() => checkAcsUrl(bad), /hostname|canonical/, bad);
  assert.equal(checkAcsUrl("https://sp.example.com/acs"), "https://sp.example.com/acs");
});
