/**
 * NATH-13 Identity Studio section: roles and access per application. Inserted into studioPage;
 * every write goes to POST /studio/api/rbac (admin + step-up + same-origin + audit on the server).
 * Output is rendered with textContent only.
 */
export const RBAC_STUDIO_HTML = `<h2>Roles and access</h2>
  <p>Each application declares permission strings (like <code>invoices:write</code>), roles bundle permissions, and roles are granted to users or groups. Nobody gets in by default. Blocked users and disabled applications are always denied. Nathan gateways apply changes within 60 seconds. Conditions and approvals belong in Gatekeeper, which reads these roles from Nathan.</p>
  <label>Application ID<input id="rbac-app" placeholder="billing" autocomplete="off"></label>
  <button class="secondary" id="rbac-load">Load roles and grants</button><pre id="rbac-overview"></pre>
  <h3>Who can sign in</h3>
  <label>Access mode<select id="rbac-mode"><option value="approved">Approved users and groups only (default)</option><option value="any_signed_in">Any signed-in user</option></select></label>
  <button id="rbac-mode-save">Save access mode</button>
  <h3>Permissions</h3>
  <label>Permission key<input id="rbac-perm-key" placeholder="invoices:write" autocomplete="off"></label>
  <label>Description<input id="rbac-perm-desc" placeholder="Create and edit invoices"></label>
  <button id="rbac-perm-save">Save permission</button><button class="secondary" id="rbac-perm-delete">Delete permission</button>
  <h3>Roles</h3>
  <label>Role key<input id="rbac-role-key" placeholder="editor" autocomplete="off"></label>
  <label>Description<input id="rbac-role-desc" placeholder="Edit invoices"></label>
  <label>Permissions (comma-separated)<input id="rbac-role-perms" placeholder="invoices:read,invoices:write"></label>
  <button id="rbac-role-save">Save role</button><button class="secondary" id="rbac-role-delete">Delete role and its grants</button>
  <h3>Grants</h3>
  <label>Role<input id="rbac-grant-role" placeholder="editor"></label>
  <label>Grant to<select id="rbac-grant-type"><option value="user">User (exact email)</option><option value="group">Group (ID)</option></select></label>
  <label>User email or group ID<input id="rbac-grant-who" placeholder="person@example.com or finance"></label>
  <button id="rbac-grant">Grant role</button>
  <label>Grant ID to revoke<input id="rbac-revoke-id" placeholder="from the grants list above"></label>
  <button class="secondary" id="rbac-revoke">Revoke grant</button>
  <h3>Groups</h3>
  <button class="secondary" id="rbac-groups">List groups</button><pre id="rbac-groups-list"></pre>
  <label>Group ID<input id="rbac-group-id" placeholder="finance" autocomplete="off"></label>
  <label>Group name<input id="rbac-group-name" placeholder="Finance team"></label>
  <button id="rbac-group-save">Save group</button><button class="secondary" id="rbac-group-delete">Delete group</button>
  <button class="secondary" id="rbac-group-members">Show members</button>
  <label>Member email<input id="rbac-member-email" type="email" placeholder="person@example.com"></label>
  <button id="rbac-member-add">Add member</button><button class="secondary" id="rbac-member-remove">Remove member</button>
  <h3>Permissions and roles as code</h3>
  <p>Paste the <code>rbac</code> object from <code>nathan.config.json</code>, or run <code>nathan rbac sync &lt;app&gt; --apply</code>. Grants are never part of code.</p>
  <textarea id="rbac-manifest" rows="8" spellcheck="false" placeholder='{"permissions":{"invoices:read":"Read invoices"},"roles":{"viewer":{"permissions":["invoices:read"]}}}'></textarea>
  <label><input type="checkbox" id="rbac-prune"> Delete code-managed roles and permissions that are no longer declared</label>
  <button class="secondary" id="rbac-sync-preview">Preview changes</button><button id="rbac-sync-apply">Apply</button>
  <h3>Gatekeeper directory access</h3>
  <p>Registers a machine client that may read roles, groups and grants with the OAuth client-credentials grant (scope <code>nathan:directory.read</code>). Its secret is shown once.</p>
  <label>Client name<input id="rbac-dir-name" placeholder="Gatekeeper PIP"></label>
  <button id="rbac-dir-create">Register directory client</button>
  <p id="rbac-status" role="status"></p><pre id="rbac-result"></pre>`;

export const RBAC_STUDIO_SCRIPT = `
    (function(){
      const el=id=>document.getElementById(id);
      const app=()=>el('rbac-app').value.trim();
      const show=(value)=>{el('rbac-result').textContent=JSON.stringify(value,null,2);el('rbac-status').textContent='Saved'};
      const fail=e=>{el('rbac-status').textContent=e.message};
      async function op(body,question){
        if(question&&!confirm(question))return;
        try{show(await postJson('/studio/api/rbac',body));if(app())await load()}catch(e){fail(e)}
      }
      async function load(){
        try{
          const d=await j('/studio/api/rbac?app='+encodeURIComponent(app()));
          el('rbac-overview').textContent=JSON.stringify(d,null,2);el('rbac-mode').value=d.app.accessMode;
        }catch(e){el('rbac-overview').textContent=e.message}
      }
      el('rbac-load').onclick=load;
      el('rbac-mode-save').onclick=()=>{
        const mode=el('rbac-mode').value;
        if(mode==='any_signed_in')return op({op:'access_mode',app:app(),accessMode:mode,confirm:'CONFIRM ANY SIGNED IN '+app()},
          'Admit EVERY signed-in user to '+app()+'? Roles still come only from grants.');
        op({op:'access_mode',app:app(),accessMode:mode});
      };
      el('rbac-perm-save').onclick=()=>op({op:'permission.upsert',app:app(),key:el('rbac-perm-key').value.trim(),description:el('rbac-perm-desc').value});
      el('rbac-perm-delete').onclick=()=>op({op:'permission.delete',app:app(),key:el('rbac-perm-key').value.trim()},'Remove this permission from every role?');
      el('rbac-role-save').onclick=()=>op({op:'role.upsert',app:app(),key:el('rbac-role-key').value.trim(),description:el('rbac-role-desc').value,
        permissions:el('rbac-role-perms').value.split(',').map(x=>x.trim()).filter(Boolean)});
      el('rbac-role-delete').onclick=()=>{const key=el('rbac-role-key').value.trim();
        op({op:'role.delete',app:app(),key,confirm:'CONFIRM DELETE ROLE '+app()+'/'+key},'Delete role '+key+' and every grant of it?')};
      el('rbac-grant').onclick=()=>{const type=el('rbac-grant-type').value,who=el('rbac-grant-who').value.trim();
        op({op:'grant.create',app:app(),role:el('rbac-grant-role').value.trim(),principalType:type,...(type==='user'?{email:who}:{group:who})},
          'Grant '+el('rbac-grant-role').value.trim()+' in '+app()+' to '+who+'?')};
      el('rbac-revoke').onclick=()=>op({op:'grant.revoke',id:el('rbac-revoke-id').value.trim()},'Revoke this grant?');
      el('rbac-groups').onclick=async()=>{try{el('rbac-groups-list').textContent=JSON.stringify(await j('/studio/api/rbac/groups'),null,2)}catch(e){fail(e)}};
      el('rbac-group-save').onclick=()=>op({op:'group.upsert',id:el('rbac-group-id').value.trim(),name:el('rbac-group-name').value});
      el('rbac-group-delete').onclick=()=>{const id=el('rbac-group-id').value.trim();
        op({op:'group.delete',id,confirm:'CONFIRM DELETE GROUP '+id},'Delete group '+id+', its memberships and grants?')};
      el('rbac-group-members').onclick=async()=>{try{show(await j('/studio/api/rbac/group?id='+encodeURIComponent(el('rbac-group-id').value.trim())))}catch(e){fail(e)}};
      el('rbac-member-add').onclick=()=>op({op:'member.add',group:el('rbac-group-id').value.trim(),email:el('rbac-member-email').value.trim()});
      el('rbac-member-remove').onclick=()=>op({op:'member.remove',group:el('rbac-group-id').value.trim(),email:el('rbac-member-email').value.trim()},'Remove this member?');
      function manifest(){return JSON.parse(el('rbac-manifest').value||'{}')}
      el('rbac-sync-preview').onclick=async()=>{try{show(await postJson('/studio/api/rbac',{op:'sync',app:app(),manifest:manifest(),prune:el('rbac-prune').checked,dryRun:true}))}catch(e){fail(e)}};
      el('rbac-sync-apply').onclick=()=>{let m;try{m=manifest()}catch(e){return fail(e)}
        const prune=el('rbac-prune').checked;
        op({op:'sync',app:app(),manifest:m,prune,confirmPrune:prune?'CONFIRM PRUNE '+app():undefined,
          confirm:m.accessMode==='any_signed_in'?'CONFIRM ANY SIGNED IN '+app():undefined},
          'Apply these permissions and roles to '+app()+(prune?' and DELETE undeclared code-managed ones':'')+'?')};
      el('rbac-dir-create').onclick=async()=>{const name=el('rbac-dir-name').value.trim();
        if(!confirm('Register directory client '+name+'? Its secret is shown once.'))return;
        try{show(await postJson('/studio/api/directory/clients',{name,confirm:'CONFIRM DIRECTORY CLIENT '+name}))}catch(e){fail(e)}};
    })();
`;
