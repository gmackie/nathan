/**
 * NATH-12 pages for Nathan as a SAML IdP: the auto-POST page that delivers a signed Response to an
 * SP's ACS URL, the IdP-initiated confirmation page, error pages, and the Identity Studio section.
 * Every value is HTML-escaped; the Studio script writes with textContent only.
 * Keep the Studio strings free of backticks and "${" because ui.ts embeds them in a template.
 */
const html = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const nonce = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
const STYLE = "body{font:16px system-ui;background:#10121a;color:#f2f3fa;margin:0;min-height:100vh;display:grid;place-items:center}" +
  "main{width:min(480px,94vw);padding:32px;background:#1b1e2a;border:1px solid #35394b;border-radius:16px}p{color:#b6bfce;line-height:1.5}" +
  "button,a.button{background:#ef9028;color:#171717;border:0;border-radius:8px;padding:13px 16px;cursor:pointer;font:inherit;text-decoration:none;display:inline-block}";

function page(title, body, { formAction = "'none'", script = "", status = 200, n = nonce() } = {}) {
  return new Response("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<meta name=\"referrer\" content=\"same-origin\"><title>" + html(title) + " · Nathan</title><style nonce=\"" + n + "\">" + STYLE + "</style></head><body><main>" +
    body + "</main>" + (script ? "<script nonce=\"" + n + "\">" + script + "</script>" : "") + "</body></html>", {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Pragma": "no-cache",
      "Content-Security-Policy": "default-src 'none'; style-src 'nonce-" + n + "'; script-src 'nonce-" + n + "'; form-action " + formAction +
        "; base-uri 'none'; frame-ancestors 'none'",
      "Referrer-Policy": "same-origin",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Strict-Transport-Security": "max-age=31536000"
    }
  });
}

/**
 * Delivers a signed SAML Response with the HTTP-POST binding. The form posts only to the exact,
 * registered ACS URL; CSP form-action allows only that URL's origin, and the Referrer-Policy keeps
 * Nathan's URLs from the SP.
 * @param {{ acsUrl: string, samlResponse: string, relayState: string|null, spName: string }} input
 */
export function autoPostPage({ acsUrl, samlResponse, relayState, spName }) {
  const origin = new URL(acsUrl).origin;
  return page("Signing in", "<h1>Signing you in to " + html(spName) + "</h1>" +
    "<form method=\"post\" action=\"" + html(acsUrl) + "\" id=\"saml-post\">" +
    "<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + html(samlResponse) + "\">" +
    (relayState !== null ? "<input type=\"hidden\" name=\"RelayState\" value=\"" + html(relayState) + "\">" : "") +
    "<noscript><p>JavaScript is off. Continue to send your sign-in to " + html(spName) + ".</p></noscript>" +
    "<button type=\"submit\">Continue</button></form>",
  { formAction: origin, script: "document.getElementById('saml-post').submit();" });
}

/** A refusal shown by Nathan. Nothing is sent to the service provider. */
export function idpErrorPage(title, message, { status = 403, signIn = false } = {}) {
  return page(title, "<h1>" + html(title) + "</h1><p>" + html(message) + "</p>" +
    (signIn ? "<p><a class=\"button\" href=\"/sign-in\">Sign in to Nathan</a></p>" : ""), { status });
}

/** IdP-initiated sign-in needs an explicit same-origin POST, so a cross-site link cannot log anyone in. */
export function idpInitiatedPage({ spId, spName, email }) {
  return page("Continue to " + spName, "<h1>Continue to " + html(spName) + "</h1><p>Signed in to Nathan as " + html(email) + ".</p>" +
    "<form method=\"post\" action=\"/saml/idp/start/" + html(spId) + "\"><button type=\"submit\">Sign in to " + html(spName) + "</button></form>",
  { formAction: "'self'" });
}

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
  <label>ACS URLs (exact https, one per line, first is the default)<textarea id="sidp-acs" rows="3" spellcheck="false"></textarea></label>
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
        return {id:el('sidp-id').value.trim(),name:el('sidp-name').value.trim(),appId:el('sidp-app').value.trim(),entityId:el('sidp-entity').value.trim(),
          acsUrls:lines('sidp-acs'),nameIdFormat:el('sidp-nameid').value,
          attributes:lines('sidp-attrs').map(l=>{const i=l.lastIndexOf('=');return {name:l.slice(0,i).trim(),source:l.slice(i+1).trim()}}),
          wantRequestsSigned:el('sidp-signed').checked,certificates:certs,signResponse:el('sidp-sign-response').checked,
          requirePasskey:el('sidp-passkey').checked,allowIdpInitiated:el('sidp-idp-init').checked,defaultRelayState:el('sidp-relay').value||null};
      }
      el('sidp-load').onclick=load;
      el('sidp-preview').onclick=async()=>{
        try{
          const v=await postJson('/studio/api/saml-idp',{op:'sp.preview',metadataUrl:el('sidp-md-url').value.trim()||undefined,metadataXml:el('sidp-md-xml').value.trim()||undefined});
          el('sidp-entity').value=v.entityId;el('sidp-acs').value=v.acsUrls.join('\\n');el('sidp-nameid').value=v.nameIdFormat;
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
