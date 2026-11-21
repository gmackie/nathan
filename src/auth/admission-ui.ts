/**
 * NATH-16 Identity Studio section: account admission (invitation-only or self-service) and
 * invitations. Every write goes to POST /studio/api/admission (admin + step-up + same-origin +
 * exact confirmation + audit on the server). Output is rendered with textContent only.
 */
export const ADMISSION_STUDIO_HTML = `<h2 id="admission">Account admission and invitations</h2>
  <p id="adm-upgrade" role="status" hidden><span id="adm-upgrade-text"></span> <a href="#adm-mode">Choose the admission mode</a> <button class="secondary" id="adm-upgrade-dismiss">Dismiss</button></p>
  <p>Decides who may <strong>create</strong> a Nathan account, by any sign-in method: password, social providers, enterprise SSO (SAML and OIDC) and SCIM just-in-time provisioning. <strong>Invitation-only</strong> (the default) creates an account only for an email address with an open invitation, and only when the sign-in method proved that address: a provider-verified email, or an address inside the verified domain of the SAML, OIDC or SCIM connection. A password sign-up uses the invitation only once its address is verified, and cannot sign in before that. <strong>Self-service</strong> lets anyone who can sign in create one. Admission grants no application access and no administrator rights. The installer's first administrator is always admitted.</p>
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
  <h3>Reissue an invitation</h3>
  <p>If someone created an unverified account for an address (for example a password sign-up they cannot verify), the real person cannot get that address. Reissuing removes that unverified account (only if it has no current session, no passkey and no social or SSO login, is not an administrator and is not managed by a directory) and invites the address again. Audited. A real invitee who signs in with a social provider that verifies the address replaces such an account automatically.</p>
  <label>Email address to reissue<input id="adm-reissue-email" type="email" autocomplete="off"></label>
  <button class="secondary" id="adm-reissue">Remove unverified account and reissue invitation</button>
  <p id="adm-status" role="status"></p><pre id="adm-result"></pre>`;

export const ADMISSION_STUDIO_SCRIPT = `
    (function(){
      const el=id=>document.getElementById(id);
      function notice(view){const due=Boolean(view&&view.upgradeNotice);el('adm-upgrade').hidden=!due;if(due)el('adm-upgrade-text').textContent=view.upgradeNotice}
      async function load(){try{const view=await j('/studio/api/admission');notice(view);el('adm-overview').textContent=JSON.stringify(view,null,2)}catch(e){el('adm-overview').textContent=e.message}}
      async function op(body,question){
        if(question&&!confirm(question))return;
        try{el('adm-result').textContent=JSON.stringify(await postJson('/studio/api/admission',body),null,2);el('adm-status').textContent='Saved';await load()}
        catch(e){el('adm-status').textContent=e.message}
      }
      el('adm-load').onclick=load;
      // NATH-16: the one-time upgrade notice; quietly absent when the viewer cannot read admission.
      j('/studio/api/admission').then(notice).catch(()=>{});
      el('adm-upgrade-dismiss').onclick=()=>op({op:'dismiss-upgrade-notice'});
      el('adm-reissue').onclick=()=>{const email=el('adm-reissue-email').value.trim().toLowerCase();
        op({op:'reissue',email,confirm:'CONFIRM REISSUE INVITATION '+email},'Remove the unverified account for '+email+' (if any) and invite it again?')};
      el('adm-mode-save').onclick=()=>{const mode=el('adm-mode').value;
        op({op:'mode',mode,confirm:'CONFIRM ADMISSION '+mode},mode==='self-service'
          ?'Let anyone who can sign in through an enabled method create an account?'
          :'Require an invitation for every new account? Existing accounts keep working.')};
      el('adm-invite').onclick=()=>op({op:'invite',email:el('adm-email').value.trim(),days:Number(el('adm-days').value)});
      el('adm-revoke').onclick=()=>{const id=el('adm-revoke-id').value.trim();
        op({op:'revoke',id,confirm:'CONFIRM REVOKE INVITATION '+id},'Revoke invitation '+id+'?')};
    })();
`;
