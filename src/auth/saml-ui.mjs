/**
 * Identity Studio section for inbound enterprise SAML (NATH-10). Rendered
 * inside studioPage(); the script runs in the same nonce'd block and uses its
 * j()/postJson() helpers. Output is written with textContent only.
 * Keep this free of backticks and "${" because it is embedded in a template.
 */
export const samlStudioSection = `
  <h2>Enterprise SAML</h2>
  <p>Connect Okta, Microsoft Entra ID or Google Workspace as a SAML identity provider. Nathan is the SAML service provider. New connections start <strong>disabled</strong> and can only be enabled after the email domain passes the DNS TXT challenge. Assertions must be signed with SHA-256 or stronger; IdP-initiated sign-in is not accepted.</p>
  <label>Connection ID<input id="saml-id" placeholder="acme-okta" autocomplete="off"></label>
  <h3>Values for your IdP administrator</h3>
  <p>Enter the connection ID first. These values are fixed per connection.</p>
  <p>Audience / SP entity ID:</p><pre id="saml-sp-entity"></pre><button class="secondary" data-copy="saml-sp-entity">Copy entity ID</button>
  <p>ACS (Reply / single sign-on) URL:</p><pre id="saml-sp-acs"></pre><button class="secondary" data-copy="saml-sp-acs">Copy ACS URL</button>
  <p>SP metadata URL (available after creation):</p><pre id="saml-sp-metadata"></pre><button class="secondary" data-copy="saml-sp-metadata">Copy metadata URL</button>
  <h3>Create connection</h3>
  <label>Corporate email domain<input id="saml-domain" placeholder="acme.example" autocomplete="off"></label>
  <label>Identity provider<select id="saml-preset"><option value="okta">Okta</option><option value="entra">Microsoft Entra ID</option><option value="google">Google Workspace</option><option value="generic">Other SAML 2.0 IdP</option></select></label>
  <label>Account provisioning<select id="saml-provisioning"><option value="invitation-only">Invitation only: existing Nathan users in the domain</option><option value="just-in-time">Just-in-time: create accounts for the verified domain</option></select></label>
  <label>IdP metadata URL (HTTPS)<input id="saml-metadata-url" placeholder="https://idp.example.com/app/metadata" autocomplete="off"></label>
  <label>or paste IdP metadata XML<textarea id="saml-metadata-xml" rows="6" spellcheck="false"></textarea></label>
  <button class="secondary" id="saml-preview">Check metadata</button>
  <button id="saml-create">Create disabled connection</button>
  <pre id="saml-create-result"></pre>
  <h3>Verify domain and enable</h3>
  <button class="secondary" id="saml-token">Request new TXT challenge</button>
  <button class="secondary" id="saml-verify">Verify DNS ownership</button>
  <button id="saml-enable">Enable connection</button>
  <button class="secondary" id="saml-disable">Disable connection</button>
  <button class="secondary" id="saml-set-provisioning">Apply provisioning mode</button>
  <h3>Certificate rotation</h3>
  <p>Add the IdP's next signing certificate before the current one expires, switch the IdP to it, then retire the old certificate by its SHA-256 fingerprint.</p>
  <label>Next signing certificate (PEM)<textarea id="saml-next-cert" rows="5" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
  <button class="secondary" id="saml-add-cert">Trust next certificate</button>
  <label>Certificate fingerprint to retire (SHA-256)<input id="saml-retire-fp" placeholder="AB:CD:..." autocomplete="off"></label>
  <button class="secondary" id="saml-retire-cert">Retire certificate</button>
  <p id="saml-status" role="status"></p>
  <button class="secondary" id="saml-list">Refresh SAML connections</button><pre id="saml-results"></pre>
`;

export const samlStudioScript = String.raw`
    (function(){
      const el=id=>document.getElementById(id);
      const status=el('saml-status');
      const sid=()=>el('saml-id').value.trim();
      function showSp(){
        const id=encodeURIComponent(sid());
        const md=id?location.origin+'/api/auth/sso/saml2/sp/metadata?providerId='+id:'';
        el('saml-sp-entity').textContent=md;
        el('saml-sp-acs').textContent=id?location.origin+'/api/auth/sso/saml2/sp/acs/'+id:'';
        el('saml-sp-metadata').textContent=md;
      }
      el('saml-id').oninput=showSp;showSp();
      document.querySelectorAll('[data-copy^="saml-"]').forEach(b=>b.onclick=()=>
        navigator.clipboard.writeText(el(b.dataset.copy).textContent).then(()=>{status.textContent='Copied.'}));
      const metadata=()=>({metadataUrl:el('saml-metadata-url').value.trim()||undefined,
        metadataXml:el('saml-metadata-xml').value.trim()||undefined});
      const show=(id,value)=>{el(id).textContent=JSON.stringify(value,null,2)};
      async function act(fn){try{status.textContent='Working...';await fn();if(status.textContent==='Working...')status.textContent='Done.'}catch(e){status.textContent=e.message}}
      el('saml-preview').onclick=()=>act(async()=>show('saml-create-result',
        await postJson('/studio/api/saml/preview',{providerId:sid(),...metadata()})));
      el('saml-create').onclick=()=>act(async()=>{
        if(!confirm('Create SAML connection '+sid()+' for '+el('saml-domain').value+'? It starts disabled.'))return;
        show('saml-create-result',await postJson('/studio/api/saml/connections',{providerId:sid(),
          domain:el('saml-domain').value.trim(),attributePreset:el('saml-preset').value,
          provisioning:el('saml-provisioning').value,...metadata()}));
      });
      el('saml-token').onclick=()=>act(async()=>show('saml-create-result',
        await postJson('/studio/api/sso/token',{providerId:sid()})));
      el('saml-verify').onclick=()=>act(async()=>show('saml-create-result',
        await postJson('/studio/api/sso/verify',{providerId:sid()})));
      async function setEnabled(enabled){
        const phrase=(enabled?'CONFIRM ENABLE SAML ':'CONFIRM DISABLE SAML ')+sid();
        if(prompt('Type "'+phrase+'" to continue')!==phrase)throw Error('Confirmation did not match');
        show('saml-results',await postJson('/studio/api/saml/status',{providerId:sid(),enabled,confirm:phrase}));
      }
      el('saml-enable').onclick=()=>act(()=>setEnabled(true));
      el('saml-disable').onclick=()=>act(()=>setEnabled(false));
      el('saml-set-provisioning').onclick=()=>act(async()=>{
        const mode=el('saml-provisioning').value,phrase='CONFIRM PROVISIONING '+mode+' '+sid();
        if(prompt('Type "'+phrase+'" to continue')!==phrase)throw Error('Confirmation did not match');
        show('saml-results',await postJson('/studio/api/saml/provisioning',{providerId:sid(),provisioning:mode,confirm:phrase}));
      });
      el('saml-add-cert').onclick=()=>act(async()=>show('saml-results',
        await postJson('/studio/api/saml/certificates',{providerId:sid(),certificate:el('saml-next-cert').value})));
      el('saml-retire-cert').onclick=()=>act(async()=>{
        const phrase='CONFIRM RETIRE CERTIFICATE '+sid();
        if(prompt('Type "'+phrase+'" to stop trusting this certificate')!==phrase)throw Error('Confirmation did not match');
        show('saml-results',await postJson('/studio/api/saml/certificates/retire',{providerId:sid(),
          sha256:el('saml-retire-fp').value.trim(),confirm:phrase}));
      });
      el('saml-list').onclick=()=>act(async()=>{
        const d=await j('/studio/api/saml');
        const warnings=d.connections.flatMap(c=>c.warnings.map(w=>c.providerId+': '+w));
        status.textContent=warnings.length?warnings.join(' | '):'No warnings.';
        show('saml-results',d);
      });
    })();
`;
