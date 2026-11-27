/**
 * NATH-39: Identity Studio as a Kumo SPA. The shell is server-rendered with renderPage (CSP-safe:
 * no style=, nonce'd styles and scripts, SRI on every module) and hosts one island; the SPA talks
 * only to /studio/api/v1; every confirmation phrase is exact; one-time secrets are never logged
 * or stored. `npm test` runs scripts/build-ui.mjs beforehand.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";

assert.ok(existsSync("src/ui/generated/ui-manifest.json"), "run `node scripts/build-ui.mjs` first (npm test does)");
await mkdir(".nathan/test-ui", { recursive: true });
const outfile = ".nathan/test-ui/studio-ui.mjs";
await build({
  entryPoints: ["tests/fixtures/studio-ui.tsx"], outfile, bundle: true, platform: "node", format: "esm",
  jsx: "automatic", packages: "external", logLevel: "error", logOverride: { "module-level-directive": "silent" }
});
const ui = await import(pathToFileURL(outfile).href + "?" + Date.now());

const tags = html => {
  const out = [];
  ui.rewriteTags(html, tag => { out.push({ name: tag.name, attrs: Object.fromEntries(tag.attributes.map(a => [a.name, a.value])) }); });
  return out;
};
const nonceOf = response => /'nonce-([^']+)'/.exec(response.headers.get("content-security-policy"))[1];

function studioSources() {
  const files = [];
  const walk = dir => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p); else if (/\.(ts|tsx)$/.test(e.name)) files.push(p);
    }
  };
  walk("src/ui/pages/studio");
  files.push("src/ui/islands/studio.tsx");
  return files.map(f => ({ file: f, text: readFileSync(f, "utf8") }));
}

// ---- The shell under renderPage ------------------------------------------------------------------

test("the Studio shell renders under renderPage: one island with SRI, nonce'd scripts and styles, no style=", async () => {
  const response = ui.studioPage("admin@example.com");
  const html = await response.text();
  const nonce = nonceOf(response);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-security-policy"),
    "default-src 'none'; connect-src 'self'; img-src 'none'; style-src 'self' 'nonce-" + nonce + "'; script-src 'self' 'nonce-" + nonce + "'; " +
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  assert.equal(response.headers.get("referrer-policy"), "same-origin", "same-origin keeps the Origin header the API checks on writes");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.doesNotMatch(html, /\sstyle=/i, "no style= attribute anywhere");
  assert.doesNotMatch(html, /\son[a-z]+=/i, "no inline event handlers");
  assert.match(html, /<title>Identity Studio · Nathan<\/title>/);

  const all = tags(html);
  const scripts = all.filter(t => t.name === "script");
  for (const s of scripts) assert.equal(s.attrs.nonce, nonce, "every script carries the page nonce");
  const modules = scripts.filter(s => s.attrs.type === "module");
  const island = ui.UI_MANIFEST.islands.studio;
  assert.ok(island, "the studio island is in the built manifest");
  assert.deepEqual(modules.map(m => [m.attrs.src, m.attrs.integrity]), [[island.src, island.integrity]], "exactly one island module, pinned with SRI");
  const inline = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)].filter(m => m[2]);
  assert.equal(inline.length, 1, "the only inline script is the import map");
  assert.match(inline[0][1], /type="importmap"/);
  const map = JSON.parse(inline[0][2]);
  for (const asset of [island, ...island.imports]) assert.equal(map.integrity[asset.src], asset.integrity, "import map pins " + asset.src);
  const preloads = all.filter(t => t.name === "link" && t.attrs.rel === "modulepreload");
  assert.deepEqual(preloads.map(p => [p.attrs.href, p.attrs.integrity]).sort(), island.imports.map(a => [a.src, a.integrity]).sort());
  const styles = all.filter(t => t.name === "style");
  assert.ok(styles.length <= 1 && styles.every(s => s.attrs.nonce === nonce));
  const css = all.find(t => t.name === "link" && t.attrs.rel === "stylesheet");
  assert.deepEqual([css.attrs.href, css.attrs.integrity], [ui.UI_MANIFEST.css.src, ui.UI_MANIFEST.css.integrity]);

  // The island container carries only the administrator's email.
  const container = all.filter(t => t.attrs["data-nathan-island"] === "studio");
  assert.equal(container.length, 1);
  assert.deepEqual(JSON.parse(container[0].attrs["data-props"]), { email: "admin@example.com" });
  // Server-rendered navigation for every panel, with real links.
  for (const group of ui.STUDIO_NAV) for (const p of group.panels) assert.ok(html.includes('href="#/' + p.id + '"'), "nav link for " + p.id);
  assert.match(html, /Overview/);
});

test("the administrator's email is escaped in the markup and in the island props", async () => {
  const hostile = "a\"<script>alert(1)</script>@example.com";
  const html = await ui.studioPage(hostile).text();
  assert.doesNotMatch(html, /<script>alert/);
  const container = tags(html).find(t => t.attrs["data-nathan-island"] === "studio");
  assert.deepEqual(JSON.parse(container.attrs["data-props"]), { email: hostile });
});

test("hash routing follows only known panels", () => {
  assert.equal(ui.panelFromHash("#/scim"), "scim");
  assert.equal(ui.panelFromHash("#/saml-idp"), "saml-idp");
  assert.equal(ui.panelFromHash("#/nope"), null);
  assert.equal(ui.panelFromHash("#adm-mode"), null, "in-page anchors keep the current panel");
  assert.equal(ui.panelFromHash("#/../../x"), null);
  const ids = ui.STUDIO_NAV.flatMap(g => g.panels.map(p => p.id));
  assert.equal(new Set(ids).size, ids.length);
  // Today's Studio areas all have a panel.
  for (const id of ["overview", "admins", "audit", "applications", "roles", "domains", "tokens", "mcp", "users", "admission",
    "providers", "sso", "saml", "saml-idp", "scim"]) assert.ok(ids.includes(id), id);
});

// ---- The SPA's API use and secret handling -------------------------------------------------------

test("the SPA calls only the typed API v1 and never logs, stores or injects HTML", () => {
  assert.equal(ui.STUDIO_API, "/studio/api/v1");
  for (const { file, text } of studioSources()) {
    assert.doesNotMatch(text, /["'`]\/studio\/api\/(?!v1)/, file + " must not call legacy /studio/api/* routes");
    assert.doesNotMatch(text, /dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML|document\.write/, file + ": React text only");
    assert.doesNotMatch(text, /console\.|localStorage|sessionStorage|indexedDB/, file + ": secrets are never logged or stored");
    assert.doesNotMatch(text, /\beval\(|new Function/, file);
  }
  // Every fetch goes through api.ts, except the provider test sign-in, which starts Better Auth's social flow as before.
  const fetches = studioSources().filter(s => /\bfetch\(/.test(s.text)).map(s => s.file.replaceAll("\\", "/")).sort();
  assert.deepEqual(fetches, ["src/ui/pages/studio/api.ts", "src/ui/pages/studio/panels/Providers.tsx"]);
  const providers = readFileSync("src/ui/pages/studio/panels/Providers.tsx", "utf8");
  assert.match(providers, /fetch\("\/api\/auth\/sign-in\/social", \{ method: "POST", credentials: "same-origin"/);
  const api = readFileSync("src/ui/pages/studio/api.ts", "utf8");
  assert.match(api, /credentials: "same-origin"/);
  assert.match(api, /"Content-Type": "application\/json"/);
});

test("results carrying a one-time secret are recognised so they are shown once", () => {
  assert.equal(ui.carriesSecret({ client_id: "x", client_secret: "s" }), true);
  assert.equal(ui.carriesSecret({ id: "acme", bearerToken: "t" }), true);
  assert.equal(ui.carriesSecret({ results: [{ hostname: "a", client: { client_secret: "s" } }] }), true);
  assert.equal(ui.carriesSecret({ id: "x", note: "ok" }), false);
  assert.equal(ui.carriesSecret({ client_secret: "" }), false);
  assert.equal(ui.carriesSecret(null), false);
});

test("timestamps render as UTC", () => {
  assert.equal(ui.when(0 + 1767225600), "2026-01-01 00:00 UTC");
  assert.equal(ui.when("2026-01-01 12:30:00"), "2026-01-01 12:30 UTC");
  assert.equal(ui.when(null), "—");
});

// ---- Exact confirmations -------------------------------------------------------------------------

test("every Studio confirmation sends the exact phrase its service requires", () => {
  const c = ui.confirmations;
  const phrases = [
    [c.admins.grant("a@example.com"), "CONFIRM GRANT ADMIN a@example.com"],
    [c.admins.revoke("u1"), "CONFIRM REVOKE ADMIN u1"],
    [c.policy.tighten("recent-passkey"), "CONFIRM REQUIRE recent-passkey"],
    [c.apps.status("ops", true), "CONFIRM ENABLE ops"],
    [c.apps.status("ops", false), "CONFIRM DISABLE ops"],
    [c.realm.batch(), "REGISTER DOMAIN CLIENTS"],
    [c.providers.status("github", "GitHub", false), "CONFIRM DISABLE github"],
    [c.rbac.anySignedIn("billing"), "CONFIRM ANY SIGNED IN billing"],
    [c.rbac.roleDelete("billing", "editor"), "CONFIRM DELETE ROLE billing/editor"],
    [c.rbac.groupDelete("finance"), "CONFIRM DELETE GROUP finance"],
    [c.rbac.directoryClient("PIP"), "CONFIRM DIRECTORY CLIENT PIP"],
    [c.tokens.audienceRemove("https://gk.example/api"), "CONFIRM REMOVE AUDIENCE https://gk.example/api"],
    [c.tokens.clientKind("c1", "agent"), "CONFIRM MARK AGENT c1"],
    [c.tokens.clientKind("c1", "auto"), "CONFIRM CLASSIFY BY GRANT c1"],
    [c.tokens.machine("Jobs", "https://a"), "CONFIRM MACHINE CLIENT Jobs"],
    [c.mcp.disable("https://n/mcp"), "CONFIRM DISABLE MCP https://n/mcp"],
    [c.mcp.enable("https://n/mcp"), "CONFIRM ENABLE MCP https://n/mcp"],
    [c.mcp.remove("https://n/mcp"), "CONFIRM REMOVE MCP https://n/mcp"],
    [c.mcp.revoke("g1"), "CONFIRM REVOKE g1"],
    [c.admission.mode("self-service"), "CONFIRM ADMISSION self-service"],
    [c.admission.reissue("p@example.com"), "CONFIRM REISSUE INVITATION p@example.com"],
    [c.admission.revoke("i1"), "CONFIRM REVOKE INVITATION i1"],
    [c.scim.manage("acme", "enable"), "CONFIRM ENABLE acme"],
    [c.scim.manage("acme", "disable"), "CONFIRM DISABLE acme"],
    [c.scim.manage("acme", "rotate"), "CONFIRM ROTATE acme"],
    [c.saml.status("acme-okta", true), "CONFIRM ENABLE SAML acme-okta"],
    [c.saml.status("acme-okta", false), "CONFIRM DISABLE SAML acme-okta"],
    [c.saml.provisioning("acme-okta", "just-in-time"), "CONFIRM PROVISIONING just-in-time acme-okta"],
    [c.saml.retire("acme-okta"), "CONFIRM RETIRE CERTIFICATE acme-okta"],
    [c.samlIdp.create("grafana"), "CONFIRM CREATE SAML SP grafana"],
    [c.samlIdp.update("grafana"), "CONFIRM UPDATE SAML SP grafana"],
    [c.samlIdp.status("grafana", true), "CONFIRM ENABLE SAML SP grafana"],
    [c.samlIdp.status("grafana", false), "CONFIRM DISABLE SAML SP grafana"],
    [c.samlIdp.generate(), "CONFIRM GENERATE SAML IDP KEY"],
    [c.samlIdp.activate(), "CONFIRM ACTIVATE SAML IDP KEY"],
    [c.samlIdp.retire(), "CONFIRM RETIRE SAML IDP KEY"]
  ];
  for (const [conf, phrase] of phrases) {
    assert.equal(conf.phrase, phrase);
    assert.ok(conf.title && conf.question, phrase + " states its consequence");
  }
  const sync = c.rbac.sync("billing", true, true);
  assert.equal(sync.confirmPrune, "CONFIRM PRUNE billing");
  assert.equal(sync.phrase, "CONFIRM ANY SIGNED IN billing");
  assert.match(sync.question, /DELETE undeclared code-managed ones/);
  assert.equal(c.rbac.sync("billing", false, false).confirmPrune, undefined);
  // SAML connections and the SAML IdP keep their typed confirmations.
  for (const conf of [c.saml.status("x", true), c.saml.provisioning("x", "m"), c.saml.retire("x"), c.samlIdp.create("x"), c.samlIdp.update("x"),
    c.samlIdp.status("x", false), c.samlIdp.generate(), c.samlIdp.activate(), c.samlIdp.retire()]) assert.equal(conf.typed, true, conf.phrase);
  // Removing access is a destructive action in the dialog.
  for (const conf of [c.admins.revoke("u"), c.mcp.remove("x"), c.rbac.roleDelete("a", "b"), c.scim.manage("x", "rotate"), c.tokens.audienceRemove("x")])
    assert.equal(conf.destructive, true, conf.title);
});

test("the admin policy and admission dialogs say what changes", () => {
  const c = ui.confirmations;
  assert.match(c.policy.tighten("both-authenticators").question, /cannot be weakened from the UI/);
  assert.match(c.admission.mode("self-service").question, /anyone who can sign in/);
  assert.match(c.tokens.clientKind("c", "agent").question, /existing user grants are revoked/);
  assert.match(c.mcp.disable("x").question, /stop working within a minute/);
});

// ---- Server-side wiring ----------------------------------------------------------------------------

test("/studio stays admin-only in the Worker and the legacy string-built Studio is gone", () => {
  const worker = readFileSync("src/auth/worker.ts", "utf8");
  const route = /if \(url\.pathname === "\/studio" && request\.method === "GET"\) \{([\s\S]*?)\n  \}/.exec(worker)[1];
  assert.match(route, /if \(!await isAdmin\(session, env\)\) \{/);
  assert.match(route, /return reject\(403, "Admin session required"\);/);
  assert.match(route, /if \(!await mayAdminister\(env,session!\.user\.id,session!\.session\.id\)\) return Response\.redirect\(issuer\.origin\+"\/security\?setup=admin",302\);/);
  assert.match(route, /return studioPage\(session!\.user\.email\);/);
  assert.match(worker, /import \{ studioPage \} from "\.\.\/ui\/pages\/studio\/StudioPage\.tsx";/);
  for (const gone of ["src/auth/ui.ts", "src/auth/mcp-ui.ts", "src/auth/saml-idp-ui.mjs", "src/auth/rbac-ui.ts", "src/auth/tokens-ui.ts", "src/auth/scim-ui.ts", "src/auth/saml-ui.mjs", "src/auth/admission-ui.ts"])
    assert.equal(existsSync(gone), false, gone + " (string-built Studio section) is removed");
  assert.doesNotMatch(readFileSync("src/auth/provider-ui.mjs", "utf8"), /STUDIO_HTML|STUDIO_SCRIPT|StudioSection|StudioScript/);
});
