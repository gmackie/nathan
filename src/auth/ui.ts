const htmlEscape = (s: string) => s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

function page(title: string, body: string, script = ""): Response {
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEscape(title)} · Nathan</title><style nonce="${nonce}">
  :root{color-scheme:dark}*{box-sizing:border-box}body{font:16px system-ui;background:#10121a;color:#f2f3fa;margin:0;min-height:100vh;display:grid;place-items:center}
  main{width:min(480px,94vw);padding:32px;background:#1b1e2a;border:1px solid #35394b;border-radius:16px}
  h1{font-size:26px;margin:4px 0 12px}p{color:#b6bfce;line-height:1.5}button,input,select{font:inherit}
  button{background:#ef9028;color:#171717;border:0;border-radius:8px;padding:13px 16px;cursor:pointer;margin:6px 4px 6px 0}
  button.secondary{background:#363d52;color:#fff}input,select{background:#10121a;color:#fff;border:1px solid #434b60;border-radius:6px;padding:12px;width:100%;margin:5px 0 12px}input[type=checkbox]{width:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere}
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

export function signInPage(providers: string[], passwordEnabled: boolean): Response {
  const buttons = providers.map(p => `<button data-provider="${htmlEscape(p)}">Continue with ${htmlEscape(p)}</button>`).join("");
  const password = passwordEnabled ? '<label>Email<input id="email" type="email" autocomplete="username"></label><label>Password<input id="password" type="password" autocomplete="current-password"></label><button id="password-submit">Sign in</button>' : "";
  return page("Sign in", '<p>Sign in securely with your configured identity provider.</p>' + buttons + password + '<p id="status" role="alert"></p>', `
    const status=document.getElementById('status');
    document.querySelectorAll('[data-provider]').forEach(b=>b.onclick=async()=>{
      try{
        const r=await fetch('/api/auth/sign-in/social',{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify({provider:b.dataset.provider,callbackURL:'/'})});
        const d=await r.json(); if(!r.ok||!d.url)throw Error('Login could not be started'); location.assign(d.url);
      }catch(e){status.textContent=e.message}
    });
    const btn=document.getElementById('password-submit');
    if(btn)btn.onclick=async()=>{
      const r=await fetch('/api/auth/sign-in/email',{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value})});
      if(!r.ok){status.textContent='Sign-in failed';return;} location.assign('/');
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
  <p><small>Client secrets are shown once. Store them in a secure manager.</small></p><h2>Registered applications</h2><button class="secondary" id="refresh">Refresh registered clients</button><pre id="clients" aria-live="polite"></pre><h3>Disable or resume OIDC client</h3><label>Client ID<input id="manage-client" placeholder="OIDC client_id"></label><button class="secondary" id="disable-client">Disable</button><button class="secondary" id="enable-client">Re-enable</button><p id="manage-status" role="status"></p><h2>Identity providers and security posture</h2><button class="secondary" id="status-btn">View active capabilities</button><pre id="capabilities"></pre><h2>Available plugins</h2><p>Catalog entries are read-only until their packages and database migrations are reviewed and deployed.</p><select id="plugin-tier"><option value="all">All tiers</option><option value="verified">Verified candidates</option><option value="community">Community</option><option value="custom">Private/custom</option></select><button class="secondary" id="plugins-btn">List integrations</button><pre id="plugins"></pre><h2>Security audit events</h2><button class="secondary" id="audit-btn">Refresh security audit</button><pre id="audit"></pre>
  <h2>Protected applications</h2><p>Service-binding policies start disabled. Save a policy, then explicitly enable it.</p>
  <label>Application ID<input id="app-id" placeholder="operations"></label>
  <label>Hostname<input id="app-host" placeholder="operations.example.com"></label>
  <label>Required roles (comma-separated)<input id="app-roles" placeholder="admin,owner"></label>
  <button id="app-save">Save policy</button><pre id="app-create-result"></pre>
  <button class="secondary" id="app-list">List policies</button><pre id="app-results"></pre>
  <label>Application ID<input id="app-toggle-id"></label>
  <button class="secondary" id="app-enable">Enable</button>
  <button class="secondary" id="app-disable">Disable</button><p id="app-status" role="status"></p>
  <h2>Enterprise SSO</h2><p>Register an upstream corporate OIDC provider. Nathan remains the downstream OIDC issuer.</p>
  <label>Provider ID<input id="sso-id" placeholder="acme-entra"></label>
  <label>Corporate email domain<input id="sso-domain" placeholder="acme.example"></label>
  <label>Issuer URL<input id="sso-issuer" placeholder="https://login.example.com"></label>
  <label>Client ID<input id="sso-client"></label>
  <label>Client secret<input id="sso-secret" type="password" autocomplete="off"></label>
  <button id="sso-register">Register provider</button><p id="sso-status" role="status"></p>
  <button class="secondary" id="sso-list">List enterprise providers</button><pre id="sso-results"></pre>
  <h2>MCP administration</h2><p>OAuth-protected stateless MCP endpoint. Register an MCP OIDC client for resource-bound access.</p>
  <pre id="mcp-help"></pre></div>`, `
    document.getElementById('refresh').onclick=async()=>{
      const r=await fetch('/studio/api/clients',{credentials:'same-origin'});const d=await r.json();
      document.getElementById('clients').textContent=r.ok?JSON.stringify(d,null,2):'Unable to load clients';
    };
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
