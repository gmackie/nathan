# Vendored Gatekeeper identity resolver (test-only)

Unmodified copies of Gatekeeper's OIDC access-token resolver and its direct dependencies, so that
`tests/runtime/gatekeeper-tokens.test.mjs` verifies Nathan's tokens with Gatekeeper's real logic
(config parsing, signature, lifetime, RFC 9068 profile, per-scope format and 256-scope limit,
`kindClaim` mapping, `mfa` with `auth_time` freshness) in CI, without a Gatekeeper checkout.

- Repository: `gmackie/gatekeeper`
- Commit: `0e25283826ccb63c6b1b8368924601cedd860e08` (main, 2026-11-21). The five files are
  byte-identical at `673921dc9e58b246041981e6f877226c938970a1`.
- Files (paths as in Gatekeeper):

| File | SHA-256 |
| --- | --- |
| `packages/identity/jwt.ts` | `17b92df81f384fb01bbcd17cac146acb1adeb0ef3e55c6c75ed9ecf32aaa2cf0` |
| `packages/identity/config.ts` | `4f30cd1beccd98da6d0acea81140718155234e2f9be6d1ea3d90eccd9489e87a` |
| `packages/core/model.ts` | `fbe0897611cfedb5cb96a1b8b9cf8b08b0f7f11b582e0a366a681781180c9f6d` |
| `packages/principal/model.ts` | `2fad85940b9bc3a39cb5f79d172b3e9b29453a96e550b1fc50bfc1825ca9008e` |
| `packages/net/bounded.ts` | `51fc5d82c08d579752a7d960ed8838091749a3ed9bdf510aa284278ccaed60a6` |

Do not edit these files. To update, copy the same paths from a newer Gatekeeper commit, update the
commit and hashes here, and run `npm run test:runtime`. `jose` resolves from Nathan's
`node_modules`; Node strips the TypeScript types at import time. The runtime test checks the hashes
above, so an accidental edit fails CI.
