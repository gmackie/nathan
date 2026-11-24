import { displayName } from "../shared/providers.mjs";
import { signedOAuthQuery } from "./oauth-query.mjs";
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
      "Referrer-Policy": "same-origin",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Strict-Transport-Security": "max-age=31536000"
    }
  });
}

export function signInPage(providers: string[], passwordEnabled: boolean, enterpriseSso=false): Response {
  const buttons=providers.map(p=>'<button data-provider="'+htmlEscape(p)+'">Continue with '+htmlEscape(displayName(p))+'</button>').join("");
  const password=passwordEnabled?'<h2>Email/password</h2><label>Email<input id="email" type="email" autocomplete="username"></label>'+
    '<label>Password<input id="password" type="password" autocomplete="current-password"></label>'+
    '<button id="password-submit">Sign in</button>'+
    '<div id="two-factor" hidden><label>Authenticator code<input id="totp-code" autocomplete="one-time-code" inputmode="numeric"></label>'+
    '<button id="two-factor-submit">Verify second factor</button></div>':"";
  const sso=enterpriseSso?'<h2>Work or school account</h2>'+
    '<label>Corporate email address<input id="sso-email" type="email" autocomplete="email" placeholder="you@company.com"></label>'+
    '<button id="sso-submit">Sign in with SSO</button>':"";
  const passkey='<h2>Passkey</h2><button id="passkey-login">Sign in with passkey</button>';
  return page("Sign in",'<p>Use your configured identity provider, passkey, or approved enterprise account.</p>'+
    buttons+passkey+sso+password+'<p id="status" role="alert"></p>',String.raw`
    const status=document.getElementById('status');
    // An app's /oauth2/authorize sent the browser here with a signed query; every sign-in request
    // carries it so Better Auth resumes that authorization (back to the app) instead of landing on "/".
    const oauthQuery=(${signedOAuthQuery.toString()})(location.search);
    const withOAuth=b=>oauthQuery?{...b,oauth_query:oauthQuery}:b;
    // After a sign-in, follow the resumed authorization when Better Auth returns one.
    const land=d=>location.assign(d&&typeof d.url==='string'&&d.url?d.url:'/');
    const unwrap=x=>x.data||x;
    async function request(path,payload){
      const res=await fetch('/api/auth'+path,{method:'POST',headers:{'Content-Type':'application/json'},
        credentials:'same-origin',body:JSON.stringify(payload)});
      const body=await res.json().catch(()=>({}));if(!res.ok)throw Error(body.message||body.error||'Authentication failed');
      return unwrap(body);
    }
    // NATH-16/19: a refused sign-in returns here with ?error=<code>; explain known codes with fixed text.
    const signInErrors={ACCOUNT_NOT_ADMITTED:'This installation creates new accounts by invitation only, and this email address has no open invitation. Ask an administrator to invite it, then sign in again.',
      ACCOUNT_DEPROVISIONED:'Your organization\'s directory has deactivated this account. Contact your administrator.',
      BANNED_USER:'This account is blocked. Contact your administrator.'};
    const signInError=new URLSearchParams(location.search).get('error');
    if(signInError&&/^[A-Za-z_]{1,64}$/.test(signInError))status.textContent=Object.hasOwn(signInErrors,signInError)?signInErrors[signInError]:('Sign-in failed ('+signInError+').');
    document.querySelectorAll('[data-provider]').forEach(b=>b.onclick=async()=>{
      try{const d=await request('/sign-in/social',withOAuth({provider:b.dataset.provider,callbackURL:'/',errorCallbackURL:'/sign-in'}));
        if(!d.url)throw Error('No OAuth redirect URL');location.assign(d.url);
      }catch(e){status.textContent=e.message}
    });
    const pwd=document.getElementById('password-submit');
    if(pwd)pwd.onclick=async()=>{
      try{
        const d=await request('/sign-in/email',withOAuth({email:document.getElementById('email').value,
          password:document.getElementById('password').value}));
        if(d.twoFactorRedirect){
          document.getElementById('two-factor').hidden=false;
          status.textContent='Enter the code from your authenticator to finish signing in.';
        }else land(d);
      }catch(e){status.textContent=e.message}
    };
    const totp=document.getElementById('two-factor-submit');
    if(totp)totp.onclick=async()=>{
      try{
        land(await request('/two-factor/verify-totp',withOAuth({code:document.getElementById('totp-code').value,trustDevice:false})));
      }catch(e){status.textContent=e.message}
    };
    const sso=document.getElementById('sso-submit');
    if(sso)sso.onclick=async()=>{
      try{
        // Nathan routes the email domain to its enabled SAML or verified OIDC connection.
        const res=await fetch('/sign-in/sso/start',{method:'POST',headers:{'Content-Type':'application/json'},
          credentials:'same-origin',body:JSON.stringify(withOAuth({email:document.getElementById('sso-email').value}))});
        const d=unwrap(await res.json().catch(()=>({})));if(!res.ok)throw Error(d.error||d.message||'SSO provider unavailable');
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
        land(await request('/passkey/verify-authentication',withOAuth({response})));
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
