const htmlEscape = (s: string) => s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

function page(title: string, body: string, script = ""): Response {
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEscape(title)} · Nathan</title><style nonce="${nonce}">
  :root{color-scheme:dark}*{box-sizing:border-box}body{font:16px system-ui;background:#10121a;color:#f2f3fa;margin:0;min-height:100vh;display:grid;place-items:center}
  main{width:min(480px,94vw);padding:32px;background:#1b1e2a;border:1px solid #35394b;border-radius:16px}
  h1{font-size:26px;margin:4px 0 12px}p{color:#b6bfce;line-height:1.5}button,input,select,textarea{font:inherit}
  button{background:#ef9028;color:#171717;border:0;border-radius:8px;padding:13px 16px;cursor:pointer;margin:6px 4px 6px 0}
  button.secondary{background:#363d52;color:#fff}input,select,textarea{background:#10121a;color:#fff;border:1px solid #434b60;border-radius:6px;padding:12px;width:100%;margin:5px 0 12px}input[type=checkbox]{width:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere}
  body:has(#studio-root){display:block}body:has(#studio-root) main{width:min(1040px,96vw);margin:22px auto}#studio-root section{border:1px solid #35394b;padding:20px;border-radius:12px;margin:12px 0}#studio-root section>h2{margin-top:0}#studio-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:15px 0}#studio-tabs button{padding:9px 12px}#studio-tabs button[aria-selected=true]{background:#f49a26}#studio-root input,#studio-root select{max-width:650px}small{color:#a8b3c7}a{color:#f5aa62}</style></head><body><main><small>NATHAN 🌭</small><h1>${htmlEscape(title)}</h1>${body}</main><script nonce="${nonce}">${script}</script></body></html>`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; connect-src 'self'; img-src 'none'; style-src 'nonce-" + nonce + "'; script-src 'nonce-" + nonce + "'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Strict-Transport-Security": "max-age=31536000"
    }
  });
}

export function signInPage(providers: string[], passwordEnabled: boolean, enterpriseSso=false): Response {
  const buttons=providers.map(p=>'<button data-provider="'+htmlEscape(p)+'">Continue with '+htmlEscape(p)+'</button>').join("");
  const password=passwordEnabled?'<h2>Email/password</h2><label>Email<input id="email" type="email" autocomplete="username"></label>'+
    '<label>Password<input id="password" type="password" autocomplete="current-password"></label>'+
    '<button id="password-submit">Sign in</button>'+
    '<div id="two-factor" hidden><label>Authenticator code<input id="totp-code" autocomplete="one-time-code" inputmode="numeric"></label>'+
    '<button id="two-factor-submit">Verify second factor</button></div>':"";
  const sso=enterpriseSso?'<h2>Work or school account</h2>'+
    '<label>Corporate email address<input id="sso-email" type="email" autocomplete="email" placeholder="you@company.com"></label>'+
    '<button id="sso-submit">Continue with enterprise SSO</button>':"";
  const passkey='<h2>Passkey</h2><button id="passkey-login">Sign in with passkey</button>';
  return page("Sign in",'<p>Use your configured identity provider, passkey, or approved enterprise account.</p>'+
    buttons+passkey+sso+password+'<p id="status" role="alert"></p>',String.raw`
    const status=document.getElementById('status');
    const unwrap=x=>x.data||x;
    async function request(path,payload){
      const res=await fetch('/api/auth'+path,{method:'POST',headers:{'Content-Type':'application/json'},
        credentials:'same-origin',body:JSON.stringify(payload)});
      const body=await res.json().catch(()=>({}));if(!res.ok)throw Error(body.message||body.error||'Authentication failed');
      return unwrap(body);
    }
    document.querySelectorAll('[data-provider]').forEach(b=>b.onclick=async()=>{
      try{const d=await request('/sign-in/social',{provider:b.dataset.provider,callbackURL:'/'});
        if(!d.url)throw Error('No OAuth redirect URL');location.assign(d.url);
      }catch(e){status.textContent=e.message}
    });
    const pwd=document.getElementById('password-submit');
    if(pwd)pwd.onclick=async()=>{
      try{
        const d=await request('/sign-in/email',{email:document.getElementById('email').value,
          password:document.getElementById('password').value});
        if(d.twoFactorRedirect){
          document.getElementById('two-factor').hidden=false;
          status.textContent='Enter the code from your authenticator to finish signing in.';
        }else location.assign('/');
      }catch(e){status.textContent=e.message}
    };
    const totp=document.getElementById('two-factor-submit');
    if(totp)totp.onclick=async()=>{
      try{
        await request('/two-factor/verify-totp',{code:document.getElementById('totp-code').value,trustDevice:false});
        location.assign('/');
      }catch(e){status.textContent=e.message}
    };
    const sso=document.getElementById('sso-submit');
    if(sso)sso.onclick=async()=>{
      try{
        const d=await request('/sign-in/sso',{email:document.getElementById('sso-email').value,callbackURL:'/'});
        if(!d.url)throw Error('SSO provider unavailable');
        location.assign(d.url);
      }catch(e){status.textContent=e.message}
    };
    const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    const encode=b=>{
      let s='';for(const x of new Uint8Array(b))s+=String.fromCharCode(x);
      return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    };
    document.getElementById('passkey-login').onclick=async()=>{
      try{
        if(!window.PublicKeyCredential)throw Error('Passkeys are unavailable in this browser');
        const optRes=await fetch('/api/auth/passkey/generate-authenticate-options',{credentials:'same-origin'});
        const options=await optRes.json();if(!optRes.ok)throw Error('Passkey challenge unavailable');
        const publicKey=unwrap(options).publicKey||unwrap(options);
        publicKey.challenge=decode(publicKey.challenge);
        if(publicKey.allowCredentials)publicKey.allowCredentials=publicKey.allowCredentials.map(c=>({...c,id:decode(c.id)}));
        const cred=await navigator.credentials.get({publicKey});
        if(!cred)throw Error('Passkey authentication cancelled');
        const response={id:cred.id,rawId:encode(cred.rawId),type:'public-key',
          response:{clientDataJSON:encode(cred.response.clientDataJSON),
            authenticatorData:encode(cred.response.authenticatorData),
            signature:encode(cred.response.signature),
            userHandle:cred.response.userHandle?encode(cred.response.userHandle):undefined},
          clientExtensionResults:cred.getClientExtensionResults()};
        await request('/passkey/verify-authentication',{response});
        location.assign('/');
      }catch(e){status.textContent=e.message}
    };
  `);
}
export function consentPage(verified: boolean, clientName: string, scope: string): Response {
  if(!verified) return new Response("Invalid or expired consent request", {status:400});
  return page("Authorize application", `<p><strong>${htmlEscape(clientName)}</strong> requests access.</p><p>Requested scopes: ${htmlEscape(scope)}</p><button id="allow">Allow</button><button class="secondary" id="deny">Deny</button><p id="status" role="alert"></p>`, `
    async function consent(accept){
      try{
        const r=await fetch('/api/auth/oauth2/consent',{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify({accept,oauth_query:new URLSearchParams(location.search).toString()})});
        const d=await r.json();if(!r.ok)throw Error('Consent failed');if(d.url)location.assign(d.url);else location.assign('/');
      }catch(e){document.getElementById('status').textContent=e.message}
    }
    document.getElementById('allow').onclick=()=>consent(true);
    document.getElementById('deny').onclick=()=>consent(false);
  `);
}
export function studioPage(userEmail: string): Response {
  return page("Identity Studio", `<nav><a href="/security">My security settings</a> · <a href="/sign-in">Switch identity</a></nav><div id="studio-tabs" role="tablist"></div><div id="studio-root"><p>Signed in as <strong>${htmlEscape(userEmail)}</strong>.</p><h2>Register OIDC client</h2><p>Workers, external HTTPS apps, and gateway clients can use the same issuer.</p>
  <label>Client name<input id="name" placeholder="My application"></label>
  <label>Exact HTTPS redirect URI<input id="redirect" placeholder="https://app.example.com/oauth/callback"></label><label>Client type<select id="kind"><option value="external">External web app</option><option value="worker">Cloudflare Worker</option><option value="gateway">Nathan gateway</option><option value="mcp">MCP administrator</option></select></label><label><input type="checkbox" id="public-client"> Public OIDC client (PKCE, no secret)</label>
  <button id="create">Register client</button><p id="status" role="alert"></p><pre id="result"></pre>
  <p><small>Client secrets are shown once. Store them in a secure manager.</small></p><h2>Registered applications</h2><button class="secondary" id="refresh">Refresh registered clients</button><pre id="clients" aria-live="polite"></pre><h3>Disable or resume OIDC client</h3><label>Client ID<input id="manage-client" placeholder="OIDC client_id"></label><button class="secondary" id="disable-client">Disable</button><button class="secondary" id="enable-client">Re-enable</button><p id="manage-status" role="status"></p><h2>Social OAuth providers</h2>
  <p>Add or rotate Google and GitHub credentials without redeploying. Secrets are encrypted inside the customer-owned D1 database and are never returned by the admin API. Keep another tested login method before disabling your last provider.</p>
  <button class="secondary" id="social-list">Refresh OAuth providers</button><pre id="social-list-result"></pre>
  <label>Provider<select id="social-provider"><option value="google">Google</option><option value="github">GitHub</option></select></label>
  <p id="social-guide"></p><a id="social-console" target="_blank" rel="noopener noreferrer" href="https://console.cloud.google.com/auth/clients">Open provider console</a>
  <p>Authorized redirect URI:</p><pre id="social-callback"></pre><button class="secondary" id="social-copy">Copy callback URL</button>
  <label>Client ID<input id="social-client-id" placeholder="Paste OAuth client ID" autocomplete="off"></label>
  <label>Client secret<input id="social-secret" type="password" placeholder="Paste OAuth client secret" autocomplete="new-password"></label>
  <button id="social-save">Save / rotate encrypted credentials</button>
  <button class="secondary" id="social-enable">Enable provider</button>
  <button class="secondary" id="social-disable">Disable provider</button>
  <p id="social-result" role="status"></p>
  <h2>Identity providers and security posture</h2><button class="secondary" id="status-btn">View active capabilities</button><pre id="capabilities"></pre><h2>Available plugins</h2><p>Catalog entries are read-only until their packages and database migrations are reviewed and deployed.</p><select id="plugin-tier"><option value="all">All tiers</option><option value="verified">Verified candidates</option><option value="community">Community</option><option value="custom">Private/custom</option></select><button class="secondary" id="plugins-btn">List integrations</button><pre id="plugins"></pre><h2>Security audit events</h2><button class="secondary" id="audit-btn">Refresh security audit</button><pre id="audit"></pre>
  <h2>Users</h2><p>Read-only directory of recent accounts. Passwords, credentials and session values are never returned.</p>
  <button class="secondary" id="users-list">Refresh users</button><pre id="users-results"></pre>
  <h2>Domain-wide SSO</h2>
  <p>One issuer at <strong>login.&lt;domain&gt;</strong> serves the root and every approved subdomain. Each client gets an exact callback URL and its own session. No wildcard redirects or shared parent-domain login cookies.</p>
  <button class="secondary" id="realm-overview">Show verified realm</button><pre id="realm-details"></pre>
  <label>Root or subdomain hostname<input id="realm-host" placeholder="example.com or app.example.com" autocomplete="off"></label>
  <label>Application type<select id="realm-kind">
    <option value="web">Root or web application</option>
    <option value="worker">Cloudflare Worker with OIDC integration</option>
    <option value="gateway">Nathan gateway for a private Worker</option>
    <option value="external">External application</option></select></label>
  <label>Exact application callback path<input id="realm-callback" placeholder="/auth/callback" value="/auth/callback"></label>
  <label><input type="checkbox" id="realm-public"> Public OIDC client (PKCE, no secret)</label>
  <p>New clients start <strong>disabled</strong>. Configure the application first, then explicitly enable its client in Registered applications.</p>
  <button id="realm-register">Register this hostname</button>
  <pre id="realm-registration"></pre>
  <button class="secondary" id="realm-clients-refresh">List registered domain clients</button><pre id="realm-clients"></pre>
  <h3>Bulk onboard root and subdomains</h3>
  <p>Paste up to 20 reviewed hostnames from <code>nathan domains discover</code> or the Cloudflare installer. Every client is created disabled and requires explicit activation. Use the same client type and callback path for this batch.</p>
  <label>Approved hostnames (one per line)<textarea id="realm-bulk-hosts" rows="6" placeholder="example.com&#10;www.example.com&#10;app.example.com" spellcheck="false"></textarea></label>
  <button id="realm-bulk-register">Register reviewed hostnames</button><pre id="realm-bulk-result"></pre>
  <h2>Protected applications</h2><p>Service-binding policies start disabled. Save a policy, then explicitly enable it.</p>
  <label>Application ID<input id="app-id" placeholder="operations"></label>
  <label>Hostname<input id="app-host" placeholder="operations.example.com"></label>
  <label>Required roles (comma-separated)<input id="app-roles" placeholder="admin,owner"></label>
  <button id="app-save">Save policy</button><pre id="app-create-result"></pre>
  <button class="secondary" id="app-list">List policies</button><pre id="app-results"></pre>
  <label>Application ID<input id="app-toggle-id"></label>
  <button class="secondary" id="app-enable">Enable</button>
  <button class="secondary" id="app-disable">Disable</button><p id="app-status" role="status"></p>
  <h2>SCIM directory connections</h2>
  <p>Nathan can receive SCIM 2.0 directory Users/Groups into a transactional, per-connection Durable Object. This initial <strong>directory-only</strong> mode does not automatically create Better Auth login accounts, revoke sessions or grant roles. Configure and review any lifecycle projection before relying on SCIM for access control.</p>
  <label>Connection ID<input id="scim-id" placeholder="acme-workforce"></label>
  <label>Directory email domain<input id="scim-domain" placeholder="acme.example"></label>
  <label>Organization ID (optional)<input id="scim-org" placeholder="org_..."></label>
  <button id="scim-create">Create directory connection</button>
  <p class="hint">The bearer token appears exactly once after creation or rotation. Copy it to a secrets manager and to your directory provider.</p>
  <pre id="scim-credential-result"></pre>
  <button class="secondary" id="scim-refresh">Refresh connections</button>
  <pre id="scim-connections"></pre>
  <label>Connection ID to manage<input id="scim-manage-id" placeholder="acme-workforce"></label>
  <button class="secondary" id="scim-enable">Enable connection</button>
  <button class="secondary" id="scim-disable">Disable connection</button>
  <button class="secondary" id="scim-rotate">Rotate bearer token</button>
  <p id="scim-status" role="status"></p>
  <h2>Enterprise SSO</h2><p>Register an upstream corporate OIDC provider. Nathan remains the downstream OIDC issuer.</p>
  <label>Provider ID<input id="sso-id" placeholder="acme-entra"></label>
  <label>Corporate email domain<input id="sso-domain" placeholder="acme.example"></label>
  <label>Issuer URL<input id="sso-issuer" placeholder="https://login.example.com"></label>
  <label>Client ID<input id="sso-client"></label>
  <label>Client secret<input id="sso-secret" type="password" autocomplete="off"></label>
  <button id="sso-register">Register provider</button>
  <p>Each corporate IdP must prove domain ownership using the Better Auth DNS TXT challenge before users can authenticate with it or link accounts.</p>
  <button class="secondary" id="sso-token">Request new TXT challenge</button>
  <button class="secondary" id="sso-verify">Verify DNS ownership</button>
  <p id="sso-status" role="status"></p><pre id="sso-verification"></pre>
  <button class="secondary" id="sso-list">List enterprise providers</button><pre id="sso-results"></pre>
  <h2>MCP administration</h2><p>OAuth-protected stateless MCP endpoint. Register an MCP OIDC client for resource-bound access.</p>
  <pre id="mcp-help"></pre></div>`, `
    document.getElementById('refresh').onclick=async()=>{
      const r=await fetch('/studio/api/clients',{credentials:'same-origin'});const d=await r.json();
      document.getElementById('clients').textContent=r.ok?JSON.stringify(d,null,2):'Unable to load clients';
    };

    const socialInfo={
      google:{url:'https://console.cloud.google.com/auth/clients',guide:'Create a Google Cloud Web OAuth client, configure the consent screen, and add the exact callback URL.'},
      github:{url:'https://github.com/settings/developers',guide:'In GitHub Developer Settings create an OAuth App and paste the exact authorization callback URL.'}
    };
    function updateSocialGuide(){
      const id=document.getElementById('social-provider').value;
      document.getElementById('social-console').href=socialInfo[id].url;
      document.getElementById('social-guide').textContent=socialInfo[id].guide;
      document.getElementById('social-callback').textContent=location.origin+'/api/auth/callback/'+id;
    }
    document.getElementById('social-provider').onchange=updateSocialGuide;
    updateSocialGuide();
    document.getElementById('social-copy').onclick=()=>navigator.clipboard.writeText(
      document.getElementById('social-callback').textContent);
    document.getElementById('social-list').onclick=async()=>{
      const out=document.getElementById('social-list-result');
      try{out.textContent=JSON.stringify((await j('/studio/api/providers')).providers,null,2)}
      catch(e){out.textContent=e.message}
    };
    document.getElementById('social-save').onclick=async()=>{
      const out=document.getElementById('social-result');
      if(!confirm('Store these OAuth credentials in your encrypted Nathan configuration?'))return;
      try{
        const value=await postJson('/studio/api/providers',{
          id:document.getElementById('social-provider').value,
          clientId:document.getElementById('social-client-id').value,
          clientSecret:document.getElementById('social-secret').value
        });
        document.getElementById('social-secret').value='';
        out.textContent=JSON.stringify(value);
        document.getElementById('social-list').click();
      }catch(e){out.textContent=e.message}
    };
    async function setSocial(enabled){
      const id=document.getElementById('social-provider').value;
      const conf='CONFIRM '+(enabled?'ENABLE ':'DISABLE ')+id;
      if(!confirm('Change OAuth provider '+id+' to '+(enabled?'enabled':'disabled')+'?'))return;
      try{
        const value=await postJson('/studio/api/providers/status',{id,enabled,confirm:conf});
        document.getElementById('social-result').textContent=JSON.stringify(value);
        document.getElementById('social-list').click();
      }catch(e){document.getElementById('social-result').textContent=e.message}
    }
    document.getElementById('social-enable').onclick=()=>setSocial(true);
    document.getElementById('social-disable').onclick=()=>setSocial(false);

    document.getElementById('status-btn').onclick=async()=>{
      const r=await fetch('/studio/api/status',{credentials:'same-origin'});const d=await r.json();
      document.getElementById('capabilities').textContent=r.ok?JSON.stringify(d,null,2):'Unavailable';
    };
    async function setClientDisabled(disabled){
      const el=document.getElementById('manage-status');el.textContent='Updating...';
      try {
        const r=await fetch('/studio/api/clients/status',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({clientId:document.getElementById('manage-client').value,disabled})});
        const d=await r.json(); if(!r.ok)throw Error(d.error||'Update failed');
        el.textContent=disabled?'Client disabled':'Client re-enabled';
        document.getElementById('refresh').click();
      }catch(e){el.textContent=e.message}
    }
    document.getElementById('disable-client').onclick=()=>setClientDisabled(true);
    document.getElementById('enable-client').onclick=()=>setClientDisabled(false);
    document.getElementById('plugins-btn').onclick=async()=>{
      const r=await fetch('/studio/api/plugins',{credentials:'same-origin'});
      const d=await r.json();if(!r.ok)return;
      const tier=document.getElementById('plugin-tier').value;
      document.getElementById('plugins').textContent=d.plugins.filter(p=>tier==='all'||p.tier===tier).map(p=>p.name+' ['+p.tier+'] — '+(p.installed?'Enabled':'Needs review/build')).join(String.fromCharCode(10));
    };
    document.getElementById('audit-btn').onclick=async()=>{
      const r=await fetch('/studio/api/audit',{credentials:'same-origin'});const d=await r.json();
      document.getElementById('audit').textContent=r.ok?JSON.stringify(d.events,null,2):'Audit unavailable';
    };

    async function j(path,opts){
      const r=await fetch(path,{credentials:'same-origin',...opts});
      const data=await r.json();if(!r.ok)throw Error(data.error||'Request failed');return data;
    }
    async function postJson(path,value){
      return j(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});
    }
    document.getElementById('users-list').onclick=async()=>{
      const out=document.getElementById('users-results');
      try{out.textContent=JSON.stringify(await j('/studio/api/users'),null,2)}catch(e){out.textContent=e.message}
    };

    document.getElementById('realm-overview').onclick=async()=>{
      const output=document.getElementById('realm-details');
      try{
        const response=await j('/studio/api/realm');
        output.textContent=JSON.stringify(response,null,2);
        if(response.realm?.apex)document.getElementById('realm-host').value=response.realm.apex;
      }catch(e){output.textContent=e.message}
    };
    document.getElementById('realm-kind').onchange=()=>{
      document.getElementById('realm-callback').value=
        document.getElementById('realm-kind').value==='gateway'?'/__nathan/callback':'/auth/callback';
    };
    document.getElementById('realm-register').onclick=async()=>{
      const output=document.getElementById('realm-registration');
      if(!confirm('Register this exact hostname as a new, initially disabled OIDC client?'))return;
      try{
        const value=await postJson('/studio/api/realm/clients',{
          hostname:document.getElementById('realm-host').value.trim().toLowerCase(),
          kind:document.getElementById('realm-kind').value,
          callbackPath:document.getElementById('realm-callback').value,
          publicClient:document.getElementById('realm-public').checked
        });
        output.textContent=JSON.stringify(value,null,2);
        document.getElementById('realm-clients-refresh').click();
      }catch(e){output.textContent=e.message}
    };

    document.getElementById('realm-bulk-register').onclick=async()=>{
      const output=document.getElementById('realm-bulk-result');
      const hostnames=document.getElementById('realm-bulk-hosts').value;
      if(!confirm('Register the reviewed hostnames as disabled clients? Save the one-time secrets securely.'))return;
      try{
        const data=await postJson('/studio/api/realm/clients/batch',{
          hostnames,kind:document.getElementById('realm-kind').value,
          callbackPath:document.getElementById('realm-callback').value,
          publicClient:document.getElementById('realm-public').checked,
          confirm:'REGISTER DOMAIN CLIENTS'
        });
        output.textContent=JSON.stringify(data,null,2);
        document.getElementById('realm-clients-refresh').click();
      }catch(e){output.textContent=e.message}
    };

    document.getElementById('realm-clients-refresh').onclick=async()=>{
      const output=document.getElementById('realm-clients');
      try{output.textContent=JSON.stringify(await j('/studio/api/realm/clients'),null,2)}
      catch(e){output.textContent=e.message}
    };

    document.getElementById('app-save').onclick=async()=>{
      const out=document.getElementById('app-create-result');
      try{out.textContent=JSON.stringify(await postJson('/studio/api/apps',{
        id:document.getElementById('app-id').value,hostname:document.getElementById('app-host').value,
        roles:document.getElementById('app-roles').value.split(',').map(x=>x.trim()).filter(Boolean)
      }),null,2)}catch(e){out.textContent=e.message}
    };
    document.getElementById('app-list').onclick=async()=>{
      const out=document.getElementById('app-results');
      try{out.textContent=JSON.stringify(await j('/studio/api/apps'),null,2)}catch(e){out.textContent=e.message}
    };
    async function toggleApp(enabled){
      const id=document.getElementById('app-toggle-id').value,out=document.getElementById('app-status');
      if(!confirm('Change access policy for '+id+'?'))return;
      try{out.textContent=JSON.stringify(await postJson('/studio/api/apps/status',{
        id,enabled,confirm:'CONFIRM '+(enabled?'ENABLE ':'DISABLE ')+id
      }))}catch(e){out.textContent=e.message}
    }
    document.getElementById('app-enable').onclick=()=>toggleApp(true);
    document.getElementById('app-disable').onclick=()=>toggleApp(false);

    document.getElementById('scim-create').onclick=async()=>{
      const out=document.getElementById('scim-credential-result');
      if(!confirm('Create a disabled SCIM connection and issue a one-time bearer credential?'))return;
      try{
        const result=await postJson('/studio/api/scim/connections',{
          id:document.getElementById('scim-id').value,
          domain:document.getElementById('scim-domain').value,
          ...(document.getElementById('scim-org').value?
            {organizationId:document.getElementById('scim-org').value}: {})
        });
        out.textContent=JSON.stringify(result,null,2);
        document.getElementById('scim-manage-id').value=result.id;
        document.getElementById('scim-refresh').click();
      }catch(e){out.textContent=e.message}
    };
    document.getElementById('scim-refresh').onclick=async()=>{
      const out=document.getElementById('scim-connections');
      try{out.textContent=JSON.stringify((await j('/studio/api/scim/connections')).connections,null,2)}
      catch(e){out.textContent=e.message}
    };
    async function manageScim(action){
      const id=document.getElementById('scim-manage-id').value,
        out=document.getElementById('scim-status'),
        result=document.getElementById('scim-credential-result');
      if(!id)return;
      const token=action==='rotate'?'CONFIRM ROTATE '+id:
        'CONFIRM '+(action==='enable'?'ENABLE ':'DISABLE ')+id;
      if(!confirm('Apply '+action+' to SCIM directory connection '+id+'?'))return;
      try{
        const value=await postJson(action==='rotate'?'/studio/api/scim/rotate':'/studio/api/scim/status',
          {id,...(action==='rotate'?{}:{enabled:action==='enable'}),confirm:token});
        out.textContent='SCIM connection '+action+' succeeded';
        if(value.bearerToken)result.textContent=JSON.stringify(value,null,2);
        document.getElementById('scim-refresh').click();
      }catch(e){out.textContent=e.message}
    }
    document.getElementById('scim-enable').onclick=()=>manageScim('enable');
    document.getElementById('scim-disable').onclick=()=>manageScim('disable');
    document.getElementById('scim-rotate').onclick=()=>manageScim('rotate');

    document.getElementById('sso-register').onclick=async()=>{
      const out=document.getElementById('sso-status');
      try{const value=await postJson('/studio/api/sso/oidc',{
        providerId:document.getElementById('sso-id').value,
        domain:document.getElementById('sso-domain').value,
        issuer:document.getElementById('sso-issuer').value,
        clientId:document.getElementById('sso-client').value,
        clientSecret:document.getElementById('sso-secret').value
      });document.getElementById('sso-secret').value='';out.textContent=JSON.stringify(value)}
      catch(e){out.textContent=e.message}
    };

    document.getElementById('sso-token').onclick=async()=>{
      const out=document.getElementById('sso-verification');
      try{
        const value=await postJson('/studio/api/sso/token',{
          providerId:document.getElementById('sso-id').value
        });
        out.textContent=JSON.stringify(value,null,2);
      }catch(e){out.textContent=e.message}
    };
    document.getElementById('sso-verify').onclick=async()=>{
      const out=document.getElementById('sso-verification');
      try{
        const value=await postJson('/studio/api/sso/verify',{
          providerId:document.getElementById('sso-id').value
        });
        out.textContent=JSON.stringify(value,null,2);
        document.getElementById('sso-list').click();
      }catch(e){out.textContent=e.message}
    };

    document.getElementById('sso-list').onclick=async()=>{
      const out=document.getElementById('sso-results');
      try{out.textContent=JSON.stringify(await j('/studio/api/sso'),null,2)}catch(e){out.textContent=e.message}
    };
    document.getElementById('mcp-help').textContent=
      'Endpoint: '+location.origin+'/mcp\nResource metadata: '+location.origin+'/.well-known/oauth-protected-resource\n' +
      'Scopes: nathan:read / nathan:admin\nProtocol: 2026-07-28';
    const root=document.getElementById('studio-root');
    const headings=Array.from(root.children).filter(el=>el.tagName==='H2');
    const tabs=document.getElementById('studio-tabs');
    headings.forEach((h,i)=>{
      const pane=document.createElement('section'),next=headings[i+1];let el=h;
      while(el&&el!==next){const following=el.nextElementSibling;pane.appendChild(el);el=following}
      root.appendChild(pane);
      const tab=document.createElement('button');tab.textContent=h.textContent;tab.type='button';
      tab.setAttribute('role','tab');
      tab.onclick=()=>{
        root.querySelectorAll('section[data-pane]').forEach(p=>p.hidden=p!==pane);
        tabs.querySelectorAll('button').forEach(t=>t.setAttribute('aria-selected',String(t===tab)));
      };
      pane.dataset.pane=String(i);tabs.appendChild(tab);
    });
    if(tabs.firstElementChild)tabs.firstElementChild.click();

    document.getElementById('create').onclick=async()=>{
      const status=document.getElementById('status');status.textContent='Creating...';
      try{
        const r=await fetch('/studio/api/clients',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify({name:document.getElementById('name').value,redirectUri:document.getElementById('redirect').value,kind:document.getElementById('kind').value,publicClient:document.getElementById('public-client').checked})});
        const d=await r.json();if(!r.ok)throw Error(d.error||'Failed');status.textContent='Client created';
        document.getElementById('result').textContent=JSON.stringify(d,null,2);
      }catch(e){status.textContent=e.message}
    }
  `);
}
