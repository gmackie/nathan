/**
 * NATH-12 Identity Studio section for Nathan as a SAML IdP. The end-user pages (auto-POST,
 * IdP-initiated confirmation, SSO confirmation, refusals) moved to ./saml-idp-pages.tsx (NATH-38).
 * The Studio script writes with textContent only.
 * Keep the Studio strings free of backticks and "${" because ui.ts embeds them in a template.
 */
// --------------------------------------------------------------------------- Identity Studio

export const samlIdpStudioSection = `
  <h2>SAML applications</h2>
  <p>Nathan as a SAML 2.0 identity provider for AWS IAM Identity Center, Salesforce, Grafana and other SAML service providers (SPs). Every SP is bound to one Nathan application, and only people that application's roles and access allow can sign in (deny by default). New SPs start <strong>disabled</strong>. Every change needs the exact confirmation text and is audited. See <code>docs/saml-idp.md</code>.</p>
  <button class="secondary" id="sidp-load">Show IdP values, keys and SPs</button><pre id="sidp-overview"></pre>
  <h3>Signing keys</h3>
  <p>The first key you generate becomes active. Later keys are published in metadata as <em>next</em>; activate one only after every SP has loaded the new metadata (at least 24 hours). The old key stays published as <em>previous</em> until you retire it. Private keys never leave the Worker.</p>
  <label>Key size<select id="sidp-bits"><option value="2048">RSA 2048 (widest SP support)</option><option value="3072">RSA 3072</option><option value="4096">RSA 4096</option></select></label>
  <button id="sidp-key-generate">Generate signing key</button>
  <label>Key SHA-256 fingerprint<input id="sidp-key-sha" placeholder="AB:CD:…" autocomplete="off"></label>
  <button class="secondary" id="sidp-key-activate">Activate next key</button><button class="secondary" id="sidp-key-retire">Retire key</button>
  <h3>Register a service provider</h3>
  <label>SP metadata URL (HTTPS)<input id="sidp-md-url" placeholder="https://sp.example.com/saml/metadata" autocomplete="off"></label>
  <label>or paste SP metadata XML<textarea id="sidp-md-xml" rows="5" spellcheck="false"></textarea></label>
  <button class="secondary" id="sidp-preview">Read metadata into the form</button>
  <label>SP ID<input id="sidp-id" placeholder="grafana" autocomplete="off"></label>
  <label>Display name<input id="sidp-name" placeholder="Grafana"></label>
  <label>Bound Nathan application<input id="sidp-app" placeholder="grafana" autocomplete="off"></label>
  <label>SP entity ID (Audience)<input id="sidp-entity" autocomplete="off"></label>
  <label>ACS URLs (exact https, one per line, first is the default; optionally "index URL" to keep the SP metadata's AssertionConsumerServiceIndex, otherwise numbered 0, 1, ...)<textarea id="sidp-acs" rows="3" spellcheck="false"></textarea></label>
  <label>NameID<select id="sidp-nameid"><option value="persistent">Persistent pairwise opaque ID (recommended)</option><option value="email">Verified email address</option></select></label>
  <label>Attributes (one per line: AttributeName=source; sources email, name, roles, groups, permissions, persistent_id)<textarea id="sidp-attrs" rows="4" spellcheck="false" placeholder="email=email&#10;displayName=name&#10;role=roles"></textarea></label>
  <label><input type="checkbox" id="sidp-signed"> Require signed AuthnRequests</label>
  <label>SP signing certificates (PEM, required for signed AuthnRequests)<textarea id="sidp-certs" rows="4" spellcheck="false"></textarea></label>
  <label><input type="checkbox" id="sidp-sign-response"> Also sign the Response (the Assertion is always signed)</label>
  <label><input type="checkbox" id="sidp-passkey"> Require a passkey sign-in (verified evidence only)</label>
  <label><input type="checkbox" id="sidp-idp-init"> Allow IdP-initiated sign-in (off by default; unsolicited responses are easier to misuse)</label>
  <label>Default RelayState for IdP-initiated sign-in (optional)<input id="sidp-relay" autocomplete="off"></label>
  <button id="sidp-create">Create disabled SP</button><button class="secondary" id="sidp-update">Update SP</button>
  <button class="secondary" id="sidp-enable">Enable SP</button><button class="secondary" id="sidp-disable">Disable SP</button>
  <p id="sidp-status" role="status"></p><pre id="sidp-result"></pre>`;

export const samlIdpStudioScript = `
    (function(){
      const el=id=>document.getElementById(id);
      const show=v=>{el('sidp-result').textContent=JSON.stringify(v,null,2);el('sidp-status').textContent='Done'};
      const fail=e=>{el('sidp-status').textContent=e.message};
      const lines=id=>el(id).value.split('\\n').map(s=>s.trim()).filter(Boolean);
      async function load(){try{el('sidp-overview').textContent=JSON.stringify(await j('/studio/api/saml-idp'),null,2)}catch(e){el('sidp-overview').textContent=e.message}}
      async function op(body,confirmText){
        const typed=prompt('Type exactly: '+confirmText);
        if(typed===null)return;
        try{show(await postJson('/studio/api/saml-idp',Object.assign({},body,{confirm:typed})));await load()}catch(e){fail(e)}
      }
      function sp(){
        const certs=el('sidp-certs').value.split(/-----END CERTIFICATE-----/).map(s=>s.trim()).filter(Boolean).map(s=>s+'\\n-----END CERTIFICATE-----');
        const acs=lines('sidp-acs').map(l=>{const m=/^(\\d{1,5})\\s+(\\S+)$/.exec(l);return m?{index:Number(m[1]),url:m[2]}:{index:null,url:l}});
        const indexed=acs.some(a=>a.index!==null);
        return {id:el('sidp-id').value.trim(),name:el('sidp-name').value.trim(),appId:el('sidp-app').value.trim(),entityId:el('sidp-entity').value.trim(),
          acsUrls:acs.map(a=>a.url),acsIndexes:indexed?acs.map(a=>a.index):undefined,nameIdFormat:el('sidp-nameid').value,
          attributes:lines('sidp-attrs').map(l=>{const i=l.lastIndexOf('=');return {name:l.slice(0,i).trim(),source:l.slice(i+1).trim()}}),
          wantRequestsSigned:el('sidp-signed').checked,certificates:certs,signResponse:el('sidp-sign-response').checked,
          requirePasskey:el('sidp-passkey').checked,allowIdpInitiated:el('sidp-idp-init').checked,defaultRelayState:el('sidp-relay').value||null};
      }
      el('sidp-load').onclick=load;
      el('sidp-preview').onclick=async()=>{
        try{
          const v=await postJson('/studio/api/saml-idp',{op:'sp.preview',metadataUrl:el('sidp-md-url').value.trim()||undefined,metadataXml:el('sidp-md-xml').value.trim()||undefined});
          el('sidp-entity').value=v.entityId;el('sidp-acs').value=v.acsUrls.map((u,i)=>v.acsIndexes[i]+' '+u).join('\\n');el('sidp-nameid').value=v.nameIdFormat;
          el('sidp-signed').checked=v.wantRequestsSigned;
          el('sidp-certs').value=v.certificates.map(c=>'-----BEGIN CERTIFICATE-----\\n'+c+'\\n-----END CERTIFICATE-----').join('\\n');
          show(v);
        }catch(e){fail(e)}
      };
      el('sidp-create').onclick=()=>{const s=sp();op(Object.assign({op:'sp.create'},s),'CONFIRM CREATE SAML SP '+s.id)};
      el('sidp-update').onclick=()=>{const s=sp();op(Object.assign({op:'sp.update'},s),'CONFIRM UPDATE SAML SP '+s.id)};
      el('sidp-enable').onclick=()=>{const id=el('sidp-id').value.trim();op({op:'sp.status',id,enabled:true},'CONFIRM ENABLE SAML SP '+id)};
      el('sidp-disable').onclick=()=>{const id=el('sidp-id').value.trim();op({op:'sp.status',id,enabled:false},'CONFIRM DISABLE SAML SP '+id)};
      el('sidp-key-generate').onclick=()=>op({op:'key.generate',bits:Number(el('sidp-bits').value)},'CONFIRM GENERATE SAML IDP KEY');
      el('sidp-key-activate').onclick=()=>op({op:'key.activate',sha256:el('sidp-key-sha').value.trim()},'CONFIRM ACTIVATE SAML IDP KEY');
      el('sidp-key-retire').onclick=()=>op({op:'key.retire',sha256:el('sidp-key-sha').value.trim()},'CONFIRM RETIRE SAML IDP KEY');
    })();`;
