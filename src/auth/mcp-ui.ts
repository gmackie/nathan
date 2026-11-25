/**
 * NATH-14 Identity Studio section for the remote MCP authorization server. The end-user consent,
 * connections and error pages moved to ./mcp-pages.tsx (NATH-38, stock Kumo, no script).
 */
/**
 * Identity Studio section. Writes go to POST /studio/api/mcp (admin + step-up + same-origin +
 * audit on the server). Output is rendered with textContent only.
 */
export const MCP_STUDIO_HTML = `<h2>Remote MCP servers</h2>
  <p>Protect any Worker as a remote MCP server with Nathan as its authorization server. The server is an application; its permissions are the MCP scopes users tick on the consent page, and a client never gets more than the user's current permissions. Mark scopes that must be ticked on their own as <strong>sensitive</strong>. See <code>docs/remote-mcp.md</code>.</p>
  <button class="secondary" id="mcp-load">Show MCP servers and connections</button><pre id="mcp-overview"></pre>
  <label>Resource (exact https URL of the MCP endpoint)<input id="mcp-id" placeholder="https://notes.example.com/mcp" autocomplete="off"></label>
  <label>Application<input id="mcp-app" placeholder="notes" autocomplete="off"></label>
  <label>Name shown on the consent page<input id="mcp-name" placeholder="Notes"></label>
  <label>Full access marker (optional)<input id="mcp-full" placeholder="notes:full" autocomplete="off"></label>
  <label>Aliases and scope metadata (JSON)<textarea id="mcp-catalog" rows="7" placeholder='{"aliases":{"notes:basic":["notes:read","notes:write"]},"scopes":{"notes:write":{"label":"Write notes","description":"Create and edit notes.","requires":["notes:read"]},"notes:export":{"label":"Export","description":"Download all notes.","sensitive":true}}}'></textarea></label>
  <button id="mcp-save">Register or update MCP server</button>
  <button class="secondary" id="mcp-disable">Disable</button><button class="secondary" id="mcp-enable">Enable</button><button class="secondary" id="mcp-remove">Remove</button>
  <label>Connection (grant) id<input id="mcp-grant" autocomplete="off"></label>
  <button class="secondary" id="mcp-revoke">Revoke connection</button>
  <p id="mcp-status" role="status"></p><pre id="mcp-result"></pre>`;

export const MCP_STUDIO_SCRIPT = `
    (function(){
      const el=id=>document.getElementById(id);
      const id=()=>el('mcp-id').value.trim();
      const show=v=>{el('mcp-result').textContent=JSON.stringify(v,null,2);el('mcp-status').textContent='Saved'};
      async function load(){try{el('mcp-overview').textContent=JSON.stringify(await j('/studio/api/mcp'),null,2)}catch(e){el('mcp-overview').textContent=e.message}}
      async function op(body,question){
        if(question&&!confirm(question))return;
        try{show(await postJson('/studio/api/mcp',body));await load()}catch(e){el('mcp-status').textContent=e.message}
      }
      el('mcp-load').onclick=load;
      el('mcp-save').onclick=()=>{let extra={};
        try{extra=el('mcp-catalog').value.trim()?JSON.parse(el('mcp-catalog').value):{}}catch(e){el('mcp-status').textContent='Catalog JSON is invalid';return}
        op({op:'resource.register',identifier:id(),app:el('mcp-app').value.trim(),name:el('mcp-name').value.trim(),full:el('mcp-full').value.trim()||null,aliases:extra.aliases||{},scopes:extra.scopes||{}})};
      el('mcp-disable').onclick=()=>op({op:'resource.status',identifier:id(),enabled:false,confirm:'CONFIRM DISABLE MCP '+id()},'Stop issuing tokens for '+id()+'? Issued tokens stop working within a minute.');
      el('mcp-enable').onclick=()=>op({op:'resource.status',identifier:id(),enabled:true,confirm:'CONFIRM ENABLE MCP '+id()});
      el('mcp-remove').onclick=()=>op({op:'resource.remove',identifier:id(),confirm:'CONFIRM REMOVE MCP '+id()},'Remove '+id()+' and every connection to it?');
      el('mcp-revoke').onclick=()=>{const g=el('mcp-grant').value.trim();op({op:'grant.revoke',grantId:g,confirm:'CONFIRM REVOKE '+g},'Revoke connection '+g+'?')};
    })();
`;
