import test from "node:test";
import assert from "node:assert/strict";
import {isRawManagementEndpoint} from "../src/auth/management-boundary.mjs";

test("admin and enterprise SSO management routes are never public plugin APIs",()=>{
  for(const p of ["/api/auth/admin","/api/auth/admin/set-role","/api/auth/admin/create-user",
    "/api/auth/admin/impersonate-user","/api/auth/admin/revoke-user-session",
    "/api/auth/sso/register","/api/auth/sso/providers","/api/auth/sso/get-provider",
    "/api/auth/sso/update-provider","/api/auth/sso/delete-provider",
    "/api/auth/sso/verify-domain","/api/auth/sso/request-domain-verification"])
    assert.equal(isRawManagementEndpoint(p),true,p);
});
test("actual identity protocols continue to work",()=>{
  for(const p of ["/api/auth/sso/callback/acme","/api/auth/sso/saml2/sp/acs/acme",
    "/api/auth/oauth2/authorize","/api/auth/sso/sign-in","/api/auth/passkey/verify-authentication",
    "/api/auth/sign-in/social","/api/auth/get-session"])
    assert.equal(isRawManagementEndpoint(p),false,p);
});
