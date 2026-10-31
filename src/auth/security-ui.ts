const escapeHtml=(s:string)=>s.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;");
export function securityPage(userEmail:string):Response {
  const nonce=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const body=String.raw`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Account security · Nathan</title>
  <style nonce="__NONCE__">:root{color-scheme:dark;font-family:system-ui,sans-serif}body{margin:40px auto;padding:20px;max-width:760px;background:#10131b;color:#f8fafc}
  section{background:#1e2430;padding:22px;border:1px solid #384052;border-radius:12px;margin:20px 0}p{color:#aeb8c9}
  button,input{font:inherit;padding:10px;border-radius:7px}button{background:#f2a44a;border:0;cursor:pointer;color:#10131b;margin-right:8px}
  input{display:block;width:min(500px,100%);background:#10131b;color:#f8fafc;border:1px solid #596579;margin:12px 0}a{color:#f2a44a}
  pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#a8ecd1}</style></head>
  <body><nav><a href="/studio">Identity Studio</a> · <a href="/sign-in">Sign in</a></nav><h1>Account security</h1>
  <p>Signed in as <strong>__EMAIL__</strong>.</p>
  <section id="admin-setup"><h2>Initial administrator onboarding</h2>
  <p>Only the verified, Cloudflare-authorized initial administrator can complete this step. Enroll your authenticators below, save recovery codes, and return here to confirm setup.</p>
  <button id="admin-status">Check setup requirements</button><button id="admin-finish">Complete initial setup</button>
  <button id="admin-stepup">Reauthenticate with passkey for administration</button>
  <p>For business-profile installations, signing in through a social/enterprise provider is not enough to administer Nathan. After enrolling a passkey, use a fresh passkey authentication ceremony to unlock sensitive operations for 15 minutes.</p>
  <pre id="admin-setup-status" role="status"></pre>
  <p><a href="/studio">Continue to Identity Studio once complete</a></p>
  </section>
  <section><h2>Authenticator application (TOTP)</h2><p>Enroll and confirm an authenticator app, then store backup codes offline.
  Nathan only asserts MFA assurance after an actual verified authentication ceremony; enabling TOTP alone does not force MFA on social logins.</p>
  <label>Password (if this account uses password login)<input type="password" id="password" autocomplete="current-password"></label>
  <button id="totp-start">Start TOTP enrollment</button><pre id="totp-setup"></pre>
  <label>Six-digit code<input id="totp-code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}"></label>
  <button id="totp-verify">Verify TOTP</button><p id="totp-status" role="status"></p>
  </section>
  <section><h2>Passkeys</h2><p>Use a platform authenticator or hardware security key. Passkeys may be used as a login method.</p>
  <button id="passkey-add">Add passkey</button><button id="passkey-list">List my passkeys</button><pre id="passkeys"></pre>
  </section>
  <script nonce="__NONCE__">
  async function api(path,method='GET',body){
    const res=await fetch('/api/auth'+path,{method,credentials:'same-origin',
      headers:body?{'Content-Type':'application/json'}:undefined,body:body?JSON.stringify(body):undefined});
    const json=await res.json();if(!res.ok)throw Error(json.message||json.error||'Request failed');return json;
  }
  function unwrap(response){return response.data||response}
  function decode(value){
    const str=atob(value.replace(/-/g,'+').replace(/_/g,'/'));
    return Uint8Array.from(str,c=>c.charCodeAt(0));
  }
  function encode(value){
    let s='';for(const b of new Uint8Array(value))s+=String.fromCharCode(b);
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }

  async function bootstrapStatus(){
    const resp=await fetch('/security/api/bootstrap',{credentials:'same-origin'});
    if(!resp.ok)throw Error('Cannot load administrator setup requirements');
    const status=await resp.json();
    document.getElementById('admin-setup-status').textContent=JSON.stringify(status,null,2);
    document.getElementById('admin-setup').hidden=!status.isInitialAdmin;
    return status;
  }
  document.getElementById('admin-status').onclick=async()=>{
    try{await bootstrapStatus()}catch(e){document.getElementById('admin-setup-status').textContent=e.message}
  };
  document.getElementById('admin-finish').onclick=async()=>{
    if(!confirm('I securely saved my recovery codes and tested my passkey/TOTP enrollment. Complete admin setup?'))return;
    try{
      const response=await fetch('/security/api/bootstrap/complete',{method:'POST',credentials:'same-origin',
        headers:{Origin:location.origin}});
      const body=await response.json();if(!response.ok)throw Error(body.error||'Enrollment is incomplete');
      document.getElementById('admin-setup-status').textContent=JSON.stringify(body,null,2);
    }catch(e){document.getElementById('admin-setup-status').textContent=e.message}
  };
  void bootstrapStatus().catch(()=>{document.getElementById('admin-setup').hidden=true});

  const totpStatus=document.getElementById('totp-status');
  document.getElementById('totp-start').onclick=async()=>{
    try {
      const pwd=document.getElementById('password').value;
      const result=unwrap(await api('/two-factor/enable','POST',pwd?{password:pwd,method:'totp'}:{method:'totp'}));
      const message='Add this TOTP URI in your authenticator: \n'+String(result.totpURI||'Not provided')+
        '\n\nRecovery codes (copy them to a secure offline manager):\n'+JSON.stringify(result.backupCodes||[]);
      document.getElementById('totp-setup').textContent=message;
      totpStatus.textContent='Enter the 6-digit code to verify enrollment.';
    } catch(e){totpStatus.textContent=e.message}
  };
  document.getElementById('totp-verify').onclick=async()=>{
    try{
      await api('/two-factor/verify-totp','POST',{code:document.getElementById('totp-code').value,trustDevice:false});
      totpStatus.textContent='TOTP enrollment verified.';
    }catch(e){totpStatus.textContent=e.message}
  };
  document.getElementById('passkey-add').onclick=async()=>{
    const output=document.getElementById('passkeys');
    try{
      if(!window.PublicKeyCredential)throw Error('WebAuthn is not available in this browser');
      const options=unwrap(await api('/passkey/generate-register-options'));
      const publicKey=options.publicKey||options;
      publicKey.challenge=decode(publicKey.challenge);
      publicKey.user.id=decode(publicKey.user.id);
      if(publicKey.excludeCredentials)publicKey.excludeCredentials=publicKey.excludeCredentials.map(c=>({...c,id:decode(c.id)}));
      const credential=await navigator.credentials.create({publicKey});
      if(!credential)throw Error('Passkey creation was cancelled');
      const response={id:credential.id,rawId:encode(credential.rawId),type:'public-key',
        response:{clientDataJSON:encode(credential.response.clientDataJSON),
          attestationObject:encode(credential.response.attestationObject),
          transports:credential.response.getTransports?credential.response.getTransports():[]},
        clientExtensionResults:credential.getClientExtensionResults()};
      await api('/passkey/verify-registration','POST',{response,name:'My passkey'});
      output.textContent='Passkey successfully enrolled.';
    }catch(e){output.textContent=e.message}
  };

  document.getElementById('admin-stepup').onclick=async()=>{
    const out=document.getElementById('admin-setup-status');
    try{
      if(!window.PublicKeyCredential)throw Error('WebAuthn is not available in this browser');
      const options=unwrap(await api('/passkey/generate-authenticate-options'));
      const publicKey=options.publicKey||options;
      publicKey.challenge=decode(publicKey.challenge);
      if(publicKey.allowCredentials)publicKey.allowCredentials=
        publicKey.allowCredentials.map(c=>({...c,id:decode(c.id)}));
      const credential=await navigator.credentials.get({publicKey});
      if(!credential)throw Error('Passkey sign-in was cancelled');
      const response={id:credential.id,rawId:encode(credential.rawId),type:'public-key',
        response:{
          clientDataJSON:encode(credential.response.clientDataJSON),
          authenticatorData:encode(credential.response.authenticatorData),
          signature:encode(credential.response.signature),
          userHandle:credential.response.userHandle?encode(credential.response.userHandle):undefined
        },clientExtensionResults:credential.getClientExtensionResults()};
      await api('/passkey/verify-authentication','POST',{response});
      out.textContent='Fresh passkey authentication completed. Redirecting to Identity Studio.';
      location.assign('/studio');
    }catch(e){out.textContent=e.message}
  };

  document.getElementById('passkey-list').onclick=async()=>{
    try{
      const response=await api('/passkey/list-user-passkeys');
      const keys=unwrap(response);
      document.getElementById('passkeys').textContent=JSON.stringify(keys,null,2);
    }catch(e){document.getElementById('passkeys').textContent=e.message}
  };
  </script></body></html>`.replaceAll("__NONCE__",nonce).replace("__EMAIL__",escapeHtml(userEmail));
  return new Response(body,{
    headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store",
      "Content-Security-Policy":"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
      "Referrer-Policy":"no-referrer","X-Frame-Options":"DENY","X-Content-Type-Options":"nosniff","Strict-Transport-Security":"max-age=31536000"}
  });
}
