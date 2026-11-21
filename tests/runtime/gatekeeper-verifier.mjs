/**
 * Gatekeeper's own identity resolver, from the pinned, unmodified copy in tests/vendor/gatekeeper
 * (see SOURCE.md there for the commit and hashes), wired to a Miniflare instance so Nathan's
 * runtime tests verify its tokens exactly as Gatekeeper would: provider config parsing, JWKS,
 * signature, lifetime, the RFC 9068 profile, per-scope format and the 256-scope limit, kind
 * mapping and the `mfa` rule with `auth_time` freshness.
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createIdentityResolver } from "../vendor/gatekeeper/packages/identity/jwt.ts";

/** The ```json block after `<!-- gatekeeper-provider-entry -->` in docs/gatekeeper.md, parsed. */
export function providerEntryFromDocs(path = "docs/gatekeeper.md") {
  const text = readFileSync(path, "utf8");
  const at = text.indexOf("<!-- gatekeeper-provider-entry -->");
  if (at < 0) throw Error("docs/gatekeeper.md has no gatekeeper-provider-entry marker");
  const block = /```json\n([\s\S]*?)\n```/.exec(text.slice(at));
  if (!block) throw Error("no json block after the marker");
  return JSON.parse(block[1]);
}

/** File → SHA-256 recorded in tests/vendor/gatekeeper/SOURCE.md, and the file's actual hash. */
export function vendoredHashes() {
  const source = readFileSync("tests/vendor/gatekeeper/SOURCE.md", "utf8");
  return [...source.matchAll(/\| `(packages\/[^`]+)` \| `([0-9a-f]{64})` \|/g)].map(([, file, recorded]) => ({
    file, recorded, actual: createHash("sha256").update(readFileSync("tests/vendor/gatekeeper/" + file)).digest("hex")
  }));
}

/**
 * A Gatekeeper resolver for `providers` whose JWKS requests go to the Miniflare instance.
 * `now` is Gatekeeper's clock (milliseconds), for expiry and auth_time checks.
 */
export function gatekeeper(mf, providers, { now } = {}) {
  const resolver = createIdentityResolver([].concat(providers), {
    fetcher: (url, init) => mf.dispatchFetch(String(url), { ...init, signal: undefined }),
    ...(now ? { now } : {})
  });
  return token => resolver.resolve(new Request("https://gatekeeper.example.com/api/decide", { headers: { Authorization: "Bearer " + token } }));
}

/** Rejects unless Gatekeeper refuses the token as invalid credentials. */
export const invalidCredentials = error => error?.code === "InvalidCredentials";
