/**
 * Test-only remote MCP server Worker (NATH-14): the MCP TypeScript SDK's Web Standards transport in
 * stateless JSON mode behind nathanMcp(). Every request builds a server bound to the caller, and a
 * tool is listed and callable only while the caller's effective scopes allow it. Never deployed.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { nathanMcp } from "../../../src/sdk/mcp.mjs";

const NOTES = [{ id: "n1", title: "Groceries" }, { id: "n2", title: "Plans" }];

export default {
  async fetch(request, env) {
    const mcp = nathanMcp(env, {
      resource: env.MCP_RESOURCE, resourceName: "Notes",
      scopes: ["notes:read", "notes:write", "notes:share", "notes:export"],
      cacheSeconds: Number(env.MCP_CACHE_SECONDS ?? "30")
    });
    const url = new URL(request.url);
    if (url.pathname === "/whoami") {
      return mcp.handle(request, user => Response.json({ sub: user.sub, clientId: user.clientId, scopes: user.scopes, canWrite: user.can("notes:write") }));
    }
    if (url.pathname === "/notes/write") {
      return mcp.handle(request, user => user.require("notes:write") ?? new Response("written"));
    }
    if (url.pathname !== "/mcp" && !mcp.isMetadataRequest(request)) return new Response("not found", { status: 404 });
    return mcp.handle(request, async user => {
      const server = new McpServer({ name: "notes", version: "1.0.0" });
      server.registerTool("whoami", { description: "Who the token speaks for" },
        async () => ({ content: [{ type: "text", text: JSON.stringify({ sub: user.sub, scopes: user.scopes }) }] }));
      if (user.can("notes:read"))
        server.registerTool("notes_list", { description: "List notes" },
          async () => ({ content: [{ type: "text", text: JSON.stringify(NOTES) }] }));
      if (user.can("notes:write"))
        server.registerTool("notes_write", { description: "Write a note" },
          async () => ({ content: [{ type: "text", text: "written" }] }));
      if (user.can("notes:export"))
        server.registerTool("notes_export", { description: "Export every note" },
          async () => ({ content: [{ type: "text", text: JSON.stringify(NOTES) }] }));
      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await server.connect(transport);
      return transport.handleRequest(request);
    });
  }
};
