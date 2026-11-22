// NATH-37: lets `npm run typecheck` pass before scripts/build-ui.mjs has generated the manifest.
// src/ui/manifest.ts validates the real file at load time.
declare module "*/generated/ui-manifest.json" {
  const manifest: unknown;
  export default manifest;
}
