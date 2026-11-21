/**
 * NATH-11 Identity Studio section: SCIM lifecycle per connection (linking and just-in-time toggles,
 * SCIM group → Nathan group mappings, link status, last sync and error log). Inserted into
 * studioPage after the SCIM connections section. Writes go to /studio/api/scim/settings and
 * /studio/api/scim/mappings (admin + step-up + same-origin + audit on the server); output is
 * rendered with textContent only.
 */
export const SCIM_LIFECYCLE_HTML = `<h3>Directory lifecycle</h3>
  <p>With linking on, a directory user is linked to an existing Nathan account only when its email is in the connection's <strong>verified</strong> domain and the Nathan account's email is verified. Deactivating or deleting a linked user in the directory blocks the account, ends every Nathan session, revokes its tokens and sends back-channel logout; Nathan gateways deny it within 60 seconds. Reactivation unblocks the account but does not restore sessions. Just-in-time creation (off by default) creates an unverified account for directory users without one.</p>
  <label>Connection ID<input id="scim-life-id" placeholder="acme-workforce" autocomplete="off"></label>
  <button class="secondary" id="scim-life-load">Show link status, mappings and errors</button><pre id="scim-life-view"></pre>
  <label><input type="checkbox" id="scim-life-linking"> Link directory users to Nathan accounts (verified domain and email only)</label>
  <label><input type="checkbox" id="scim-life-jit"> Create accounts just in time for directory users without one</label>
  <button id="scim-life-save">Save lifecycle settings</button>
  <h4>Group mapping</h4>
  <p>A mapped Nathan group's membership is maintained by the directory. Mapping grants nothing by itself: give the group roles in Roles and access. Only empty Identity Studio groups can be mapped.</p>
  <label>SCIM group reference<select id="scim-map-type"><option value="externalId">externalId (Entra object ID, Okta group ID)</option><option value="id">Nathan SCIM id</option></select></label>
  <label>Reference value<input id="scim-map-ref" autocomplete="off"></label>
  <label>Nathan group ID<input id="scim-map-group" placeholder="engineering" autocomplete="off"></label>
  <button id="scim-map">Map group</button><button class="secondary" id="scim-unmap">Remove mapping and its memberships</button>
  <p id="scim-life-status" role="status"></p><pre id="scim-life-result"></pre>`;

export const SCIM_LIFECYCLE_SCRIPT = `
    (function(){
      const el=id=>document.getElementById(id);
      const id=()=>el('scim-life-id').value.trim();
      const done=v=>{el('scim-life-result').textContent=JSON.stringify(v,null,2);el('scim-life-status').textContent='Saved'};
      const fail=e=>{el('scim-life-status').textContent=e.message};
      async function load(){
        try{
          const v=await j('/studio/api/scim/connection?id='+encodeURIComponent(id()));
          el('scim-life-linking').checked=v.connection.linking;el('scim-life-jit').checked=v.connection.jit;
          el('scim-life-view').textContent=JSON.stringify(v,null,2);
        }catch(e){el('scim-life-view').textContent=e.message}
      }
      el('scim-life-load').onclick=load;
      el('scim-life-save').onclick=async()=>{
        const linking=el('scim-life-linking').checked,jit=el('scim-life-jit').checked;
        if(!confirm('Set linking '+(linking?'ON':'OFF')+' and just-in-time creation '+(jit?'ON':'OFF')+' for '+id()+'? Staged directory users are re-applied now.'))return;
        try{done(await postJson('/studio/api/scim/settings',{id:id(),linking,jit,confirm:'CONFIRM SCIM SETTINGS '+id()}));await load()}catch(e){fail(e)}
      };
      el('scim-map').onclick=async()=>{
        const ref=el('scim-map-ref').value.trim(),group=el('scim-map-group').value.trim();
        if(!confirm('Let the directory maintain the members of '+group+' from SCIM group '+ref+'?'))return;
        try{done(await postJson('/studio/api/scim/mappings',{op:'map',connection:id(),refType:el('scim-map-type').value,ref,group,
          confirm:'CONFIRM MAP '+id()+'/'+ref+' TO '+group}));await load()}catch(e){fail(e)}
      };
      el('scim-unmap').onclick=async()=>{
        const group=el('scim-map-group').value.trim();
        if(!confirm('Remove the mapping of '+group+' and every member the directory added?'))return;
        try{done(await postJson('/studio/api/scim/mappings',{op:'unmap',connection:id(),group,confirm:'CONFIRM UNMAP '+group}));await load()}catch(e){fail(e)}
      };
    })();
`;
