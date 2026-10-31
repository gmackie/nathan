# Plugin architecture

Nathan supports three **proposed** plugin trust classes, tracked in `plugins/catalog.json`. These are not certifications and do not mean the packages have been security reviewed.

1. **Verified:** Pinned Better Auth integrations, with Nathan-maintained UI, migrations, and workerd tests.
2. **Community:** Explicit opt-in only after dependency review, API compatibility checks, and staging tests.
3. **Custom:** User-owned code. Prefer isolated Workers with narrowly scoped service-binding RPC, rather than code executing inside the privileged IdP.

Better Auth server hooks execute with the IdP's privileges. A JSON manifest does not sandbox arbitrary code. Plugin upgrades that change routes or schema require a new build and reviewed migrations. Mutable policy settings may be applied live only when the adapter explicitly supports that.

Installation UX should show version, maintenance status, required Cloudflare bindings, secrets, migrations, risk classification, and rollback plan. Do not enable a plugin simply because its UI toggle is checked; compile it into an approved Worker release and verify the migration first.

The catalog currently documents planned integration choices; it is not a runtime plugin manager. Read `docs/roadmap.md` for actual implementation status.
