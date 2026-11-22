/**
 * NATH-15 Identity Studio section: token audiences (Gatekeeper and APIs), which clients may use
 * them, each client's principal kind, and machine/agent clients. Every write goes to
 * POST /studio/api/tokens (admin + step-up + same-origin + audit on the server).
 * Output is rendered with textContent only.
 */
export const TOKENS_STUDIO_HTML = `<h2>Access tokens for Gatekeeper and APIs</h2>
  <p>Register each API that accepts Nathan access tokens (for example Gatekeeper) as an audience. Tokens for it are JWTs (<code>typ: at+jwt</code>) valid for at most 900 seconds, with <code>principal_kind</code> (user, machine or agent) and, when the audience is bound to an application, a <code>roles</code> hint. Authoritative roles stay in the directory API. See <code>docs/gatekeeper.md</code>.</p>
  <button class="secondary" id="tok-load">Show audiences and clients</button><pre id="tok-overview"></pre>
  <h3>Audiences</h3>
  <label>Audience (exact https URL)<input id="tok-aud" placeholder="https://gatekeeper.example.com/api" autocomplete="off"></label>
  <label>Application for the roles hint (optional)<input id="tok-aud-app" placeholder="billing" autocomplete="off"></label>
  <button id="tok-aud-save">Register audience</button><button class="secondary" id="tok-aud-remove">Remove audience</button>
  <label>Client ID<input id="tok-link-client" autocomplete="off"></label>
  <button id="tok-link">Allow client to request this audience</button><button class="secondary" id="tok-unlink">Disallow</button>
  <h3>Principal kind</h3>
  <p>Mark agents and MCP clients as <strong>agent</strong>. Unmarked clients are classified by grant: a signed-in user is <code>user</code>, client credentials are <code>machine</code>. A client is never a user by attribute.</p>
  <label>Client ID<input id="tok-kind-client" autocomplete="off"></label>
  <label>Kind<select id="tok-kind"><option value="agent">Agent or MCP client</option><option value="auto">Classify by grant (default)</option></select></label>
  <button id="tok-kind-save">Set principal kind</button>
  <h3>Machine and agent clients</h3>
  <p>Creates a confidential client-credentials client for one audience with scope <code>nathan:api</code>. Its secret is shown once.</p>
  <label>Client name<input id="tok-m-name" placeholder="Billing jobs"></label>
  <label>Kind<select id="tok-m-kind"><option value="machine">Machine (service)</option><option value="agent">Agent</option></select></label>
  <button id="tok-m-create">Create client for the audience above</button>
  <p id="tok-status" role="status"></p><pre id="tok-result"></pre>`;

export const TOKENS_STUDIO_SCRIPT = `
    (function(){
      const el=id=>document.getElementById(id);
      const aud=()=>el('tok-aud').value.trim();
      const show=v=>{el('tok-result').textContent=JSON.stringify(v,null,2);el('tok-status').textContent='Saved'};
      const fail=e=>{el('tok-status').textContent=e.message};
      async function load(){try{el('tok-overview').textContent=JSON.stringify(await j('/studio/api/tokens'),null,2)}catch(e){el('tok-overview').textContent=e.message}}
      async function op(body,question){
        if(question&&!confirm(question))return;
        try{show(await postJson('/studio/api/tokens',body));await load()}catch(e){fail(e)}
      }
      el('tok-load').onclick=load;
      el('tok-aud-save').onclick=()=>op({op:'audience.register',identifier:aud(),app:el('tok-aud-app').value.trim()||null});
      el('tok-aud-remove').onclick=()=>op({op:'audience.remove',identifier:aud(),confirm:'CONFIRM REMOVE AUDIENCE '+aud()},
        'Stop issuing tokens for '+aud()+'? Issued tokens expire within 900 seconds.');
      el('tok-link').onclick=()=>op({op:'audience.link',identifier:aud(),clientId:el('tok-link-client').value.trim()});
      el('tok-unlink').onclick=()=>op({op:'audience.unlink',identifier:aud(),clientId:el('tok-link-client').value.trim()});
      el('tok-kind-save').onclick=()=>{const kind=el('tok-kind').value,id=el('tok-kind-client').value.trim();
        op({op:'client.kind',clientId:id,kind,confirm:kind==='auto'?'CONFIRM CLASSIFY BY GRANT '+id:'CONFIRM MARK AGENT '+id},
          kind==='auto'?'Classify '+id+' by grant again? Its user-delegated tokens will say user.'
            :'Mark '+id+' as an agent? It may then refresh without a live session and use nathan:api. Its existing user grants are revoked.')};
      el('tok-m-create').onclick=()=>{const name=el('tok-m-name').value.trim();
        op({op:'machine.create',name,kind:el('tok-m-kind').value,audience:aud(),confirm:'CONFIRM MACHINE CLIENT '+name},
          'Create client '+name+' for '+aud()+'? Its secret is shown once.')};
    })();
`;
