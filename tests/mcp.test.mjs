import test from "node:test";
import assert from "node:assert/strict";
import {decodeMcpRequest,MCP_VERSION,isWriteTool,requiredConfirm,READ_TOOLS,WRITE_TOOLS} from "../src/mcp/protocol.mjs";
const headers={"Content-Type":"application/json","MCP-Protocol-Version":MCP_VERSION,"Mcp-Method":"tools/call","Mcp-Name":"nathan_status"};
const request=new Request("https://auth.example.com/mcp",{method:"POST",headers});
const msg={jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"nathan_status",arguments:{},_meta:{
  "io.modelcontextprotocol/protocolVersion":MCP_VERSION,"io.modelcontextprotocol/clientCapabilities":{}}}};
test("accepts stateless 2026 MCP calls",()=>assert.equal(decodeMcpRequest(request,msg).method,"tools/call"));
test("rejects MCP request without exact method header",()=>assert.throws(()=>decodeMcpRequest(request,{...msg,method:"tools/list"})));
test("rejects unsupported/absent meta",()=>assert.throws(()=>decodeMcpRequest(request,{...msg,params:{name:"nathan_status"}})));
test("rejects spoofed tool name in header",()=>assert.throws(()=>decodeMcpRequest(request,{...msg,params:{...msg.params,name:"nathan_clients_list"}})));
test("reads are not writes",()=>assert.ok(READ_TOOLS.every(t=>!isWriteTool(t.name))));
test("explicit confirmation includes operation target",()=> {
  assert.equal(requiredConfirm("nathan_app_set_enabled",{enabled:true,id:"dashboard"}),"CONFIRM ENABLE dashboard");
  assert.equal(requiredConfirm("nathan_client_set_disabled",{disabled:true,clientId:"app"}),"CONFIRM DISABLE app");
});
test("tool schemas all have object input",()=>assert.ok([...READ_TOOLS,...WRITE_TOOLS].every(t=>t.inputSchema.type==="object")));
