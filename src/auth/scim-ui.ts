/**
 * NATH-11 Identity Studio section: SCIM lifecycle per connection (linking and just-in-time toggles,
 * SCIM group → Nathan group mappings, link status, last sync and error log), administrator reviews
 * (directory changes that touch a Nathan administrator), keep active / unlink, and the reconciliation
 * outbox. Inserted into studioPage after the SCIM connections section. Writes go to
 * /studio/api/scim/{settings,mappings,users,outbox} (admin + fresh step-up + same-origin + exact
 * confirmation + audit on the server); output is rendered with textContent only.
 *
 * As everywhere in Studio, the exact confirmation string is built by the page after the browser's
 * confirm() dialog: that dialog is the human check, so each one states the consequence of the change.
 */
export const SCIM_LIFECYCLE_HTML = `<h3>Directory lifecycle</h3>
  <p>With linking on, a directory user is linked to an existing Nathan account only when its email is in the connection's <strong>verified</strong> domain and the Nathan account's email is verified. Deactivating or deleting a linked user in the directory blocks the account, ends every Nathan session, revokes its tokens and sends back-channel logout; Nathan gateways deny it within 60 seconds. Reactivation unblocks the account but does not restore sessions. Just-in-time creation (off by default) creates an unverified account for directory users without one.</p>
  <p><strong>Administrators are never linked or deprovisioned by the directory alone.</strong> A directory change that would link or block a Nathan administrator (admin role, admin grant, the bootstrap owner, or an address in NATHAN_ADMIN_EMAILS), or re-link an account that was deleted, waits under Administrator reviews below. The last administrator is never deprovisioned by SCIM.</p>
  <label>Connection ID<input id="scim-life-id" placeholder="acme-workforce" autocomplete="off"></label>
  <button class="secondary" id="scim-life-load">Show link status, reviews, mappings and errors</button><pre id="scim-life-view"></pre>
  <label><input type="checkbox" id="scim-life-linking"> Link directory users to Nathan accounts (verified domain and email only)</label>
  <label><input type="checkbox" id="scim-life-jit"> Create accounts just in time for directory users without one</label>
  <button id="scim-life-save">Save lifecycle settings</button>
  <h4>Group mapping</h4>
  <p>A mapped Nathan group's membership is maintained by the directory. Mapping grants nothing by itself: give the group roles in Roles and access. Only empty Identity Studio groups can be mapped.</p>
  <label>SCIM group reference<select id="scim-map-type"><option value="externalId">externalId (Entra object ID, Okta group ID)</option><option value="id">Nathan SCIM id</option></select></label>
  <label>Reference value<input id="scim-map-ref" autocomplete="off"></label>
  <label>Nathan group ID<input id="scim-map-group" placeholder="engineering" autocomplete="off"></label>
  <button id="scim-map">Map group</button><button class="secondary" id="scim-unmap">Remove mapping and its memberships</button>
  <h4>Administrator reviews</h4>
  <p>Load the connection above, then pick a pending review by its ID. Approving applies the directory's change once; dismissing keeps the account as it is until the directory sends a new change.</p>
  <label>Review ID<input id="scim-review-id" autocomplete="off"></label>
  <button id="scim-review-approve">Approve</button><button class="secondary" id="scim-review-dismiss">Dismiss</button>
  <h4>Directory user overrides</h4>
  <p>Keep active unblocks a user the directory deprovisioned; Nathan keeps that decision through replays and resyncs until the directory sends a new deactivation or deletion. Unlink detaches the directory user from its Nathan account for good.</p>
  <label>Directory user (SCIM id)<input id="scim-user-id" autocomplete="off"></label>
  <button class="secondary" id="scim-keep-active">Keep active (unblock)</button><button class="secondary" id="scim-unlink">Unlink</button>
  <h4>Reconciliation outbox</h4>
  <p>Directory changes are applied to Nathan in order. If one can never be applied, the connection answers 503 to every later change. Review the head entry here and skip it only if you will handle that change by hand.</p>
  <button class="secondary" id="scim-outbox-load">Show outbox head</button><button class="secondary" id="scim-outbox-skip">Skip the failing head entry</button>
  <pre id="scim-outbox-view"></pre>
  <p id="scim-life-status" role="status"></p><pre id="scim-life-result"></pre>`;

export const SCIM_LIFECYCLE_SCRIPT = `
    (function(){
      const el=id=>document.getElementById(id);
      const id=()=>el('scim-life-id').value.trim();
      let view=null,outbox=null;
      const done=v=>{el('scim-life-result').textContent=JSON.stringify(v,null,2);el('scim-life-status').textContent='Saved'};
      const fail=e=>{el('scim-life-status').textContent=e.message};
      async function load(){
        try{
          const v=await j('/studio/api/scim/connection?id='+encodeURIComponent(id()));
          view=v;
          el('scim-life-linking').checked=v.connection.linking;el('scim-life-jit').checked=v.connection.jit;
          el('scim-life-view').textContent=JSON.stringify(v,null,2);
        }catch(e){el('scim-life-view').textContent=e.message}
      }
      el('scim-life-load').onclick=load;
      el('scim-life-save').onclick=async()=>{
        const linking=el('scim-life-linking').checked,jit=el('scim-life-jit').checked;
        if(!confirm('Set linking '+(linking?'ON':'OFF')+' and just-in-time creation '+(jit?'ON':'OFF')+' for '+id()+'?\\n\\nEvery staged directory user is re-applied now: matching users are linked, and linked users the directory deactivated or deleted are blocked and lose every session and token (administrators wait for review).'))return;
        try{done(await postJson('/studio/api/scim/settings',{id:id(),linking,jit,confirm:'CONFIRM SCIM SETTINGS '+id()}));await load()}catch(e){fail(e)}
      };
      el('scim-map').onclick=async()=>{
        const ref=el('scim-map-ref').value.trim(),group=el('scim-map-group').value.trim();
        if(!confirm('Let the directory maintain the members of '+group+' from SCIM group '+ref+'?\\n\\nFrom now on only the directory adds and removes its members, and members gain whatever roles '+group+' is granted.'))return;
        try{done(await postJson('/studio/api/scim/mappings',{op:'map',connection:id(),refType:el('scim-map-type').value,ref,group,
          confirm:'CONFIRM MAP '+id()+'/'+ref+' TO '+group}));await load()}catch(e){fail(e)}
      };
      el('scim-unmap').onclick=async()=>{
        const group=el('scim-map-group').value.trim();
        if(!confirm('Remove the mapping of '+group+' and every member the directory added?\\n\\nThose members lose the roles granted to '+group+' now.'))return;
        try{done(await postJson('/studio/api/scim/mappings',{op:'unmap',connection:id(),group,confirm:'CONFIRM UNMAP '+group}));await load()}catch(e){fail(e)}
      };
      function review(){
        const r=view&&view.reviews.find(x=>x.id===el('scim-review-id').value.trim());
        if(!r)throw Error('Load the connection and enter the ID of one of its reviews');
        return r;
      }
      el('scim-review-approve').onclick=async()=>{
        try{
          const r=review();
          const consequence=r.action==='link'
            ?'Link directory user '+r.userName+' to Nathan administrator '+r.email+'? The directory can then request this account\\'s deprovisioning (each request is reviewed again).'
            :'Deprovision administrator '+r.email+'? This blocks the account, ends every Nathan session, revokes every token and sends back-channel logout.';
          if(!confirm(consequence))return;
          done(await postJson('/studio/api/scim/users',{op:'approve',connection:id(),review:r.id,confirm:'CONFIRM APPROVE '+r.action.toUpperCase()+' '+r.email}));await load();
        }catch(e){fail(e)}
      };
      el('scim-review-dismiss').onclick=async()=>{
        try{
          const r=review();
          if(!confirm('Dismiss: '+r.email+' stays as it is. '+(r.action==='link'?'This directory user is not linked automatically again.':'The directory\\'s deactivation is ignored until it sends a new one.')))return;
          done(await postJson('/studio/api/scim/users',{op:'dismiss',connection:id(),review:r.id,confirm:'CONFIRM DISMISS '+r.action.toUpperCase()+' '+r.email}));await load();
        }catch(e){fail(e)}
      };
      function linked(){
        const u=view&&view.users.find(x=>x.scimId===el('scim-user-id').value.trim()&&x.userId);
        if(!u)throw Error('Load the connection and enter the SCIM id of a linked directory user');
        return u;
      }
      el('scim-keep-active').onclick=async()=>{
        try{
          const u=linked();
          if(!confirm('Unblock '+u.email+' although the directory deprovisioned it?\\n\\nSessions and tokens revoked earlier are not restored. Replays and resyncs keep your decision; a new deactivation or deletion from the directory blocks the account again.'))return;
          done(await postJson('/studio/api/scim/users',{op:'keep-active',connection:id(),scimId:u.scimId,confirm:'CONFIRM KEEP ACTIVE '+u.email}));await load();
        }catch(e){fail(e)}
      };
      el('scim-unlink').onclick=async()=>{
        try{
          const u=linked();
          if(!confirm('Unlink '+u.email+' from directory user '+u.userName+'?\\n\\nIts directory-maintained group memberships (and the roles they carry) are removed, the directory no longer controls the account, and it is not linked again automatically. A block the directory caused stays.'))return;
          done(await postJson('/studio/api/scim/users',{op:'unlink',connection:id(),scimId:u.scimId,confirm:'CONFIRM UNLINK '+u.email}));await load();
        }catch(e){fail(e)}
      };
      el('scim-outbox-load').onclick=async()=>{
        try{outbox=await j('/studio/api/scim/outbox?id='+encodeURIComponent(id()));el('scim-outbox-view').textContent=JSON.stringify(outbox,null,2)}
        catch(e){el('scim-outbox-view').textContent=e.message}
      };
      el('scim-outbox-skip').onclick=async()=>{
        const h=outbox&&outbox.head&&outbox.head[0];
        if(!h){fail(Error('Show the outbox head first'));return}
        const what=h.kind+' '+((h.resource&&(h.resource.userName||h.resource.displayName))||h.resourceId);
        if(!confirm('Skip the change to '+what+' (failed '+h.attempts+' times: '+(h.lastError||'unknown error')+')?\\n\\nNathan will NOT apply it. If it deactivates or deletes a user, that user is NOT blocked: block them yourself in Users. It is applied again when the resource changes in the directory or on a resync.'))return;
        try{done(await postJson('/studio/api/scim/outbox',{op:'skip',connection:id(),kind:h.kind,id:h.resourceId,seq:h.seq,confirm:'CONFIRM SKIP '+h.kind.toUpperCase()+' '+h.resourceId}));el('scim-outbox-load').onclick()}catch(e){fail(e)}
      };
    })();
`;
