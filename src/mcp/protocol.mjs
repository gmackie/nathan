/** Stateless MCP 2026-07-28 request validation; no legacy session negotiation. */
export const MCP_VERSION = "2026-07-28";
export const READ_TOOLS = Object.freeze([
  { name: "nathan_status", title: "Nathan status", description: "Read issuer capabilities and configured providers", inputSchema: { type:"object", properties:{}, additionalProperties:false }, annotations:{readOnlyHint:true} },
  { name: "nathan_clients_list", title: "OIDC clients", description: "List OIDC clients without secrets", inputSchema: {type:"object",properties:{},additionalProperties:false},annotations:{readOnlyHint:true} },
  { name: "nathan_users_list", title:"Users", description:"Read recent identity accounts without credentials", inputSchema:{type:"object",properties:{},additionalProperties:false}, annotations:{readOnlyHint:true} },
  { name: "nathan_realm_status", title: "Domain-wide SSO", description: "Read verified base domain, central issuer and coverage", inputSchema:{type:"object",properties:{},additionalProperties:false}, annotations:{readOnlyHint:true} },
  { name: "nathan_realm_clients_list", title: "Registered domain clients", description: "List approved, exact-host OIDC clients without secrets", inputSchema:{type:"object",properties:{},additionalProperties:false}, annotations:{readOnlyHint:true} },
  { name: "nathan_apps_list", title: "Protected applications", description: "List configured gateways and authorization policies", inputSchema:{type:"object",properties:{},additionalProperties:false},annotations:{readOnlyHint:true} },
  { name: "nathan_sso_list", title: "Enterprise SSO", description: "List upstream OIDC/SAML registrations with secrets redacted", inputSchema:{type:"object",properties:{},additionalProperties:false},annotations:{readOnlyHint:true} },
  { name: "nathan_audit_recent", title: "Recent security events", description: "List the last 75 security audit events", inputSchema:{type:"object",properties:{},additionalProperties:false},annotations:{readOnlyHint:true} }
]);
export const WRITE_TOOLS = Object.freeze([
  { name:"nathan_app_set_enabled",title:"Enable/disable protected application",description:"Change application policy after explicit confirmation", inputSchema:{type:"object",properties:{id:{type:"string"},enabled:{type:"boolean"},confirm:{type:"string"}},required:["id","enabled","confirm"],additionalProperties:false},annotations:{destructiveHint:true,readOnlyHint:false} },
  { name:"nathan_client_set_disabled",title:"Enable/disable OAuth client",description:"Change an OAuth client's disabled state after explicit confirmation",inputSchema:{type:"object",properties:{clientId:{type:"string"},disabled:{type:"boolean"},confirm:{type:"string"}},required:["clientId","disabled","confirm"],additionalProperties:false},annotations:{destructiveHint:true,readOnlyHint:false} }
]);
export function isWriteTool(name) { return WRITE_TOOLS.some(t=>t.name===name); }
export function requiredConfirm(name, input) {
  if(name==="nathan_app_set_enabled")return "CONFIRM "+(input.enabled?"ENABLE ":"DISABLE ")+String(input.id);
  if(name==="nathan_client_set_disabled")return "CONFIRM "+(input.disabled?"DISABLE ":"ENABLE ")+String(input.clientId);
  return "";
}
export function decodeMcpRequest(request, body) {
  if (request.method !== "POST") throw new Error("Only POST is supported");
  if (request.headers.get("MCP-Protocol-Version") !== MCP_VERSION) throw new Error("Unsupported MCP protocol version");
  if (!request.headers.get("Content-Type")?.startsWith("application/json")) throw new Error("Content-Type must be application/json");
  if (!body || typeof body!=="object" || Array.isArray(body) || body.jsonrpc!=="2.0" || !Object.hasOwn(body,"id"))
    throw new Error("Invalid JSON-RPC message");
  if (typeof body.method!=="string" || request.headers.get("Mcp-Method")!==body.method)
    throw new Error("Mcp-Method must match JSON-RPC method");
  const meta=body.params?._meta;
  if(!meta || meta["io.modelcontextprotocol/protocolVersion"]!==MCP_VERSION ||
     !meta["io.modelcontextprotocol/clientCapabilities"] ||
     typeof meta["io.modelcontextprotocol/clientCapabilities"]!=="object")
    throw new Error("Missing MCP per-request metadata");
  if(body.method==="tools/call"){
    if(typeof body.params.name!=="string" || request.headers.get("Mcp-Name")!==body.params.name)
      throw new Error("Mcp-Name must match tool name");
  } else if(request.headers.has("Mcp-Name")) {
    throw new Error("Mcp-Name is only supported on tools/call");
  }
  return body;
}
export const mcpResult = (id,result)=>({jsonrpc:"2.0",id,result});
export const mcpError = (id,code,message)=>({jsonrpc:"2.0",id,error:{code,message}});
export function textContent(value){
  return {resultType:"complete",content:[{type:"text",text:JSON.stringify(value)}]};
}
