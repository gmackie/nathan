/** NATH-24 Studio API v1: remote MCP servers and their connections (NATH-14). */
import { mcpOverview, applyMcpOperation } from "../mcp-oauth";
import type { StudioRoute } from "./router";
import { rejected } from "./http";
import { noInput, mcpInput } from "./schemas";

export function mcpRefusalMessage(error: unknown) {
  return error instanceof Error && /^(Invalid|Unknown|Explicit|Give)/.test(error.message) ? error.message : "MCP change rejected";
}

export const routes: StudioRoute[] = [
  { method: "GET", path: "/mcp", action: "mcp.read", input: noInput, run: ({ env }) => mcpOverview(env) },
  { method: "POST", path: "/mcp", action: "mcp.apply", input: mcpInput, maxBytes: 65536,
    refusal: error => rejected(mcpRefusalMessage(error)), run: ({ env, actor }, body) => applyMcpOperation(env, body, actor) }
];
