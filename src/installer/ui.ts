export function installerPage(nonce:string):string{
  return \`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Nathan • Deploy to Cloudflare</title><style nonce="\${nonce}">
  :root{font-family:system-ui,sans-serif;color-scheme:dark}body{background:#11131b;color:#eef2fa;max-width:850px;margin:5vh auto;padding:0 22px}header{display:flex;align-items:center;justify-content:space-between}
  main{background:#1b202e;border:1px solid #384153;border-radius:14px;padding:24px}h1{font-size:32px}h2{margin-top:28px}p,small{color:#bac3d4;line-height:1.5}
  button{background:#f49c34;color:#0d1420;border:0;border-radius:8px;padding:12px 18px;font-weight:600;cursor:pointer}button.secondary{background:#384153;color:#fff}
  input,select{font:inherit;background:#10131c;color:#fff;border:1px solid #4a5468;border-radius:6px;padding:10px;width:100%;margin:8px 0 15px}label{display:block}
  pre{background:#11131c;border-radius:8px;overflow-wrap:anywhere;white-space:pre-wrap;padding:15px}a{color:#f5ad5c}
  #apply{background:#465062;color:#9ca9bc;cursor:not-allowed}
  </style></head><body><header><h1>Nathan 🌭</h1><small>Cloudflare-native IdP & access</small></header><main>
  <h2>Deploy your own identity provider</h2><p>Your Cloudflare account owns the Worker, database, and DNS. This is an experimental installer preview. Deployment is disabled until the release package and migration checks are verified.</p>
  <p><a href="/api/login">Connect Cloudflare account</a> · <button class="secondary" id="disconnect">Disconnect</button></p>
  <p id="session" role="status">Loading session...</p>
  <label>Cloudflare account<select id="accounts"><option value="">Sign in to select an account</option></select></label>
  <label>DNS zone<select id="zones"><option value="">Select an account first</option></select></label>
  <label>Identity hostname<input id="hostname" placeholder="auth.example.com" autocomplete="off"></label>
  <label>Worker name<input id="worker" value="nathan-auth"></label>
  <label>Security profile<select id="profile"><option value="business">Business (recommended)</option><option value="standard">Standard</option><option value="high">High assurance (requires verified AAL)</option></select></label>
  <button id="plan">Preview deployment plan</button><button id="apply" disabled title="Installer write path not yet verified">Deploy to Cloudflare (coming soon)</button>
  <pre id="result" aria-live="polite"></pre>
  <h2>Next steps</h2>
  <p>Until hosted publishing is verified, use the <a href="https://github.com/gmackie/nathan/blob/main/docs/deploy.md">Nathan CLI deployment guide</a> and the secure provider setup wizard.</p>
  </main><script nonce="\${nonce}">
    const $=id=>document.getElementById(id);
    async function json(path,options){
      const response=await fetch(path,{credentials:'same-origin',...options});
      const body=await response.json();if(!response.ok)throw Error(body.error||'Request failed');
      return body;
    }
    const fill=(element,items,key,label)=>{
      element.textContent='';
      const empty=document.createElement('option');empty.value='';empty.textContent='Select...';element.appendChild(empty);
      items.forEach(item=>{const opt=document.createElement('option');opt.value=item[key];opt.textContent=item[label];element.appendChild(opt)});
    };
    async function load(){
      try{
        const state=await json('/api/session');$('session').textContent='Connected as '+state.user.email;
        const accounts=await json('/api/accounts');fill($('accounts'),accounts.accounts,'id','name');
      }catch(error){$('session').textContent='Not connected. Select Connect Cloudflare account.'}
    }
    $('accounts').onchange=async()=>{
      try{
        const a=$('accounts').value;if(!a)return;
        const data=await json('/api/zones?account='+encodeURIComponent(a));
        fill($('zones'),data.zones,'id','name');
        $('zones').onchange=()=>{
          const opt=$('zones').selectedOptions[0];
          if(opt&&opt.value)$('hostname').value='auth.'+opt.textContent;
        };
      }catch(error){$('result').textContent=error.message}
    };
    $('plan').onclick=async()=>{
      $('result').textContent='Checking Cloudflare account and DNS...';
      try{
        const data=await json('/api/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
          accountId:$('accounts').value,hostname:$('hostname').value,name:$('worker').value,
          securityProfile:$('profile').value
        })});
        $('result').textContent=JSON.stringify(data,null,2);
      }catch(error){$('result').textContent=error.message}
    };
    $('disconnect').onclick=async()=>{
      await fetch('/api/logout',{method:'POST',credentials:'same-origin',headers:{Origin:location.origin}});
      location.assign('/');
    };
    void load();
  </script></body></html>\`;
}
