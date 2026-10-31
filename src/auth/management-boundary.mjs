/**
 * Better Auth's first-party plugins expose powerful management endpoints.
 * Nathan owns admin policy through Identity Studio and MUST NOT expose the raw
 * admin/SSO management endpoints to any signed-in non-privileged user.
 * Server-side auth.api calls from verified Studio handlers continue to work.
 */
export function isRawManagementEndpoint(path) {
  if(typeof path!=="string")return false;
  if(path==="/api/auth/admin"||path.startsWith("/api/auth/admin/"))return true;
  const sso=new Set([
    "/api/auth/sso/register",
    "/api/auth/sso/providers",
    "/api/auth/sso/get-provider",
    "/api/auth/sso/update-provider",
    "/api/auth/sso/delete-provider",
    "/api/auth/sso/verify-domain",
    "/api/auth/sso/request-domain-verification"
  ]);
  return sso.has(path);
}
