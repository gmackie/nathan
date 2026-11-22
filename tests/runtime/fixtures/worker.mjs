/** Private upstream Worker used by the runtime tests: it trusts only what the Nathan SDK verifies. */
import { nathan } from "../../../src/sdk/nathan.mjs";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const user = await nathan(request, env);
    if (url.pathname === "/invoices/write") {
      const denied = user.require("invoices:write");
      if (denied) return denied;
      return new Response("written");
    }
    if (!user.authenticated || !user.allowed) return user.forbidden();
    return Response.json({
      via: user.via, sub: user.sub, email: user.email, app: user.app,
      roles: user.roles, permissions: user.permissions,
      canRead: user.can("invoices:read"), canWrite: user.can("invoices:write"), isEditor: user.hasRole("editor"),
      forwarded: Object.fromEntries([...request.headers].filter(([k]) => k.startsWith("x-nathan-") && k !== "x-nathan-principal")),
      cfAccess: [...request.headers.keys()].filter(k => k.startsWith("cf-access-"))
    });
  }
};
