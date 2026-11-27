/**
 * NATH-24: Identity Studio JSON API v1, mounted at /studio/api/v1 (see docs/studio-api.md).
 * One route table; the legacy /studio/api/* routes in worker.ts call the same service functions.
 */
import { createStudioRouter, type StudioRoute } from "./router";
import { routes as status } from "./status";
import { routes as audit } from "./audit";
import { routes as users } from "./users";
import { routes as admins } from "./admins";
import { routes as clients } from "./clients";
import { routes as realm } from "./realm";
import { routes as providers } from "./providers";
import { routes as sso } from "./sso";
import { routes as scim } from "./scim";
import { routes as rbac } from "./rbac";
import { routes as admission } from "./admission";
import { routes as tokens } from "./tokens";
import { routes as mcp } from "./mcp";
import { routes as security } from "./security";

export { STUDIO_API_V1 } from "./router";
export { authorizeStudioRequest, type StudioPrincipal } from "./authorize";

export const STUDIO_API_V1_ROUTES: readonly StudioRoute[] = Object.freeze([
  ...status, ...audit, ...users, ...admins, ...clients, ...realm, ...providers, ...sso,
  ...scim, ...rbac, ...admission, ...tokens, ...mcp, ...security
]);

export const handleStudioApiV1 = createStudioRouter([...STUDIO_API_V1_ROUTES]);
