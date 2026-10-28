const htmlEscape = (s: string) => s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

function page(title: string, body: string, script = ""): Response {
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEscape(title)} · Nathan</title><style nonce="${nonce}">
  :root{color-scheme:dark}*{box-sizing:border-box}body{font:16px system-ui;background:#10121a;color:#f2f3fa;margin:0;min-height:100vh;display:grid;place-items:center}
  main{width:min(480px,94vw);padding:32px;background:#1b1e2a;border:1px solid #35394b;border-radius:16px}
  h1{font-size:26px;margin:4px 0 12px}p{color:#b6bfce;line-height:1.5}button,input,select{font:inherit}
  button{background:#ef9028;color:#171717;border:0;border-radius:8px;padding:13px 16px;cursor:pointer;margin:6px 4px 6px 0}
  button.secondary{background:#363d52;color:#fff}input,select{background:#10121a;color:#fff;border:1px solid #434b60;border-radius:6px;padding:12px;width:100%;margin:5px 0 12px}input[type=checkbox]{width:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere}
  small{color:#a8b3c7}a{color:#f5aa62}</style></head><body><main><small>NATHAN 🌭</small><h1>${htmlEscape(title)}</h1>${body}</main><script nonce="${nonce}">${script}</script></body></html>`;
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
  return page("Identity Studio", `<p>Signed in as <strong>${htmlEscape(userEmail)}</strong>.</p><h2>Register OIDC client</h2><p>Workers, external HTTPS apps, and gateway clients can use the same issuer.</p>
  <label>Client name<input id="name" placeholder="My application"></label>
  <label>Exact HTTPS redirect URI<input id="redirect" placeholder="https://app.example.com/oauth/callback"></label><label>Client type<select id="kind"><option value="external">External web app</option><option value="worker">Cloudflare Worker</option><option value="gateway">Nathan gateway</option></select></label><label><input type="checkbox" id="public-client"> Public OIDC client (PKCE, no secret)</label>
  <button id="create">Register client</button><p id="status" role="alert"></p><pre id="result"></pre>
  <p><small>Client secrets are shown once. Store them in a secure manager.</small></p><h2>Registered applications</h2><button class="secondary" id="refresh">Refresh registered clients</button><pre id="clients" aria-live="polite"></pre><h2>Identity providers and security posture</h2><button class="secondary" id="status-btn">View active capabilities</button><pre id="capabilities"></pre><h2>Available plugins</h2><p>Catalog entries are read-only until their packages and database migrations are reviewed and deployed.</p><select id="plugin-tier"><option value="all">All tiers</option><option value="verified">Verified candidates</option><option value="community">Community</option><option value="custom">Private/custom</option></select><button class="secondary" id="plugins-btn">List integrations</button><pre id="plugins"></pre><h2>Security audit events</h2><button class="secondary" id="audit-btn">Refresh security audit</button><pre id="audit"></pre>`, `
    document.getElementById('refresh').onclick=async()=>{
      const r=await fetch('/studio/api/clients',{credentials:'same-origin'});const d=await r.json();
      document.getElementById('clients').textContent=r.ok?JSON.stringify(d,null,2):'Unable to load clients';
    };
    document.getElementById('status-btn').onclick=async()=>{
      const r=await fetch('/studio/api/status',{credentials:'same-origin'});const d=await r.json();
      document.getElementById('capabilities').textContent=r.ok?JSON.stringify(d,null,2):'Unavailable';
    };
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
