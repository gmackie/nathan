import { getAppPrincipal, withNathan, type AuthEnv } from "@nathan/worker";
export { NathanScimDirectory, NathanService, NathanVerifier } from "@nathan/worker";

export default withNathan<AuthEnv>({
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname === "/me") return Response.json(await getAppPrincipal(request, env, "library"));
    if (pathname === "/" && request.method === "POST") return new Response(request.body);
    return new Response("library " + pathname);
  },
  async scheduled(_controller, env) {
    await env.DB.prepare("INSERT INTO host_events (name) VALUES ('library cron')").run();
  }
});
