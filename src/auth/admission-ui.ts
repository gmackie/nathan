/**
 * NATH-16 Identity Studio section: account admission (invitation-only or self-service) and
 * invitations. Every write goes to POST /studio/api/admission (admin + step-up + same-origin +
 * exact confirmation + audit on the server). Output is rendered with textContent only.
 */
export const ADMISSION_STUDIO_HTML = `<h2>Account admission and invitations</h2>
  <p>Decides who may <strong>create</strong> a Nathan account, by any sign-in method: password, social providers, SAML and SCIM just-in-time provisioning. <strong>Invitation-only</strong> (the default) creates an account only for an email address with an open invitation; <strong>self-service</strong> lets anyone who can sign in create one. Admission grants no application access and no administrator rights. The installer's first administrator is always admitted.</p>
  <button class="secondary" id="adm-load">Show admission mode and invitations</button><pre id="adm-overview"></pre>
  <label>Admission mode<select id="adm-mode"><option value="invitation-only">Invitation-only (recommended)</option><option value="self-service">Self-service</option></select></label>
  <button id="adm-mode-save">Change admission mode</button>
  <h3>Invite someone</h3>
  <p>The invitation is bound to this exact email address, works once and expires. The person signs in with any enabled method using that address; a provider that does not verify the address cannot use it.</p>
  <label>Email address<input id="adm-email" type="email" placeholder="new.person@example.com" autocomplete="off"></label>
  <label>Valid for (days, 1 to 30)<input id="adm-days" type="number" min="1" max="30" value="7"></label>
  <button id="adm-invite">Create invitation</button>
  <label>Invitation ID to revoke<input id="adm-revoke-id" autocomplete="off"></label>
  <button class="secondary" id="adm-revoke">Revoke invitation</button>
  <p id="adm-status" role="status"></p><pre id="adm-result"></pre>`;

export const ADMISSION_STUDIO_SCRIPT = `
    (function(){
      const el=id=>document.getElementById(id);
      async function load(){try{el('adm-overview').textContent=JSON.stringify(await j('/studio/api/admission'),null,2)}catch(e){el('adm-overview').textContent=e.message}}
      async function op(body,question){
        if(question&&!confirm(question))return;
        try{el('adm-result').textContent=JSON.stringify(await postJson('/studio/api/admission',body),null,2);el('adm-status').textContent='Saved';await load()}
        catch(e){el('adm-status').textContent=e.message}
      }
      el('adm-load').onclick=load;
      el('adm-mode-save').onclick=()=>{const mode=el('adm-mode').value;
        op({op:'mode',mode,confirm:'CONFIRM ADMISSION '+mode},mode==='self-service'
          ?'Let anyone who can sign in through an enabled method create an account?'
          :'Require an invitation for every new account? Existing accounts keep working.')};
      el('adm-invite').onclick=()=>op({op:'invite',email:el('adm-email').value.trim(),days:Number(el('adm-days').value)});
      el('adm-revoke').onclick=()=>{const id=el('adm-revoke-id').value.trim();
        op({op:'revoke',id,confirm:'CONFIRM REVOKE INVITATION '+id},'Revoke invitation '+id+'?')};
    })();
`;
