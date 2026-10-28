/** Customer-owned Cloudflare account deployment wizard, CSP nonce and no browser token storage. */
export function installerPage(nonce:string):string {
  return String.raw`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deploy Nathan to Cloudflare</title><style nonce="__NONCE__">
:root{font:15px/1.5 system-ui,sans-serif;color-scheme:dark;background:#0e121b;color:#f3f6fc}
*{box-sizing:border-box}body{max-width:1000px;margin:20px auto;padding:0 18px}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;border-bottom:1px solid #333a4d;padding-bottom:14px}
.logo{font-size:27px;font-weight:800}.subtitle{color:#aab7cd;font-size:13px}
main{display:grid;grid-template-columns:minmax(0,1fr) 270px;gap:24px;margin:24px 0}
article,aside{background:#1c2230;border:1px solid #384154;border-radius:14px;padding:24px}
h1{font-size:23px;margin:0 0 8px}h2{font-size:18px;margin:20px 0 8px}p,small{color:#afbad0}
button,a.button{font:inherit;cursor:pointer;background:#f3a440;color:#15191f;border:0;border-radius:8px;padding:11px 15px;text-decoration:none;display:inline-block;font-weight:600;margin:5px 8px 5px 0}
button.secondary{background:#354058;color:#eef3fd}button:disabled{opacity:.42;cursor:not-allowed}
input,select{display:block;width:100%;font:inherit;padding:10px;border-radius:7px;background:#101827;color:#edf4ff;border:1px solid #5a6882;margin:4px 0 14px}
input[type=checkbox]{width:auto;display:inline-block;margin-right:8px}label{display:block;margin-top:8px;color:#cdd7e8}
pre{padding:15px;border-radius:7px;background:#101827;color:#b4f0d2;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;max-height:360px;overflow:auto}
a{color:#f0b76b}.muted{color:#9eaabe;font-size:13px}.pill{background:#334259;padding:4px 9px;border-radius:20px;font-size:12px}
section{padding-bottom:18px;border-bottom:1px solid #353d4d;margin-bottom:12px}section:last-child{border:0}
ol{padding-left:20px;color:#ccd6e5}li{padding:8px 0}li.active{color:#ffbf63;font-weight:bold}li.done{color:#98deb2}
.details{border:1px solid #384354;background:#101827;border-radius:8px;padding:12px;margin:14px 0}
#install-progress{margin-top:18px}#install-progress li{padding:6px 0}#errors{color:#ffadad;white-space:pre-wrap}
kbd{color:#ffe3ae}code{color:#e5d4b7}footer{margin:25px 0;color:#8493a8}
@media(max-width:780px){main{display:block}aside{margin-top:18px}}
</style></head><body>
<header><div><div class="logo">nathan 🌭</div><div class="subtitle">Cloudflare-native identity and access</div></div><span class="pill">Customer-owned installation</span></header>
<main><article><h1>Deploy your identity provider</h1>
<p>Nathan sets up an OAuth/OIDC issuer, D1 database, secure hostname, social login, and a personal admin console in your own Cloudflare account.</p>
<section><h2>1. Connect Cloudflare</h2>
<a class="button" href="/api/login">Connect Cloudflare</a>
<button class="secondary" id="disconnect">Disconnect</button>
<p id="session" role="status">Checking session…</p>
<label>Account<select id="accounts"><option value="">Sign in to discover accounts</option></select></label>
<label>Active DNS zone<select id="zones"><option value="">Choose an account first</option></select></label>
</section>
<section><h2>2. Choose installation details</h2>
<label>Identity hostname<input id="hostname" placeholder="login.example.com" autocomplete="off" required></label>
<label><input type="checkbox" id="realm-enabled" checked> Use this identity provider for the root domain and all authorized subdomains</label>
<label>SSO domain (root and subdomains)<input id="realm-apex" placeholder="example.com" autocomplete="off"></label>
<p class="muted">One central session at <code>login.example.com</code>, separate OIDC clients for <code>example.com</code> and each subdomain. Nathan never uses wildcard callback URLs or shares login cookies with subdomains.</p>
<button class="secondary" id="discover-hosts">Discover existing subdomains</button><pre id="discovered-hosts" aria-live="polite"></pre>
<label>Worker name<input id="worker" value="nathan-auth" pattern="[a-z0-9-]+" required></label>
<label>Administrator email<input id="admin-email" type="email" placeholder="you@example.com"></label>
<p class="muted">For secure first-time bootstrap, this must match the email on your Cloudflare OAuth identity.</p>
<label>Security profile<select id="profile"><option value="business">Business — recommended</option><option value="standard">Standard — consumer / developer</option></select></label>
</section>
<section><h2>3. Configure first sign-in</h2>
<label>Upstream login provider<select id="provider">
<option value="google">Google OAuth</option><option value="github">GitHub OAuth</option></select></label>
<div class="details"><strong>OAuth console guide</strong><p id="provider-instructions"></p>
<a id="provider-console" href="https://console.cloud.google.com/auth/clients" target="_blank" rel="noopener noreferrer">Open provider console</a>
<p>Authorized redirect URI:</p><pre id="provider-callback"></pre><button class="secondary" id="copy-callback">Copy redirect URI</button></div>
<label>OAuth client ID<input id="client-id" autocomplete="off"></label>
<label>OAuth client secret<input id="client-secret" type="password" autocomplete="off"></label>
<p class="muted">Credentials are sent only to your live installation request over HTTPS, directly stored as Worker secrets, and not persisted in the installer database.</p>
</section>
<section><h2>4. Enterprise, MFA and directory provisioning</h2>
<label><input type="checkbox" id="enterprise"> Enable enterprise SSO plugin</label>
<p class="muted">After deployment, configure your OIDC/SAML connections in Identity Studio. Employee domains must be verified before use.</p>
<label>MFA enforcement<select id="mfa">
<option value="optional">Passkeys + TOTP available (optional)</option>
<option value="admin">Require admin MFA (pending assurance verification)</option>
<option value="all">Require MFA for everyone (pending assurance verification)</option>
</select></label>
<p class="muted">Required MFA choices will be blocked by the backend until OAuth, passkey, and federated assurance paths have passed security testing.</p>
  <h3>SCIM 2.0 directory provisioning</h3>
  <label><input type="checkbox" id="scim-enabled"> Prepare an optional SCIM directory connection</label>
  <label>Connection ID<input id="scim-connection" placeholder="acme-workforce" autocomplete="off"></label>
  <label>Corporate directory email domain<input id="scim-domain" placeholder="acme.example" autocomplete="off"></label>
  <p class="muted">The initial connection is created disabled after administrator verification and MFA enrollment. Its one-time bearer token is displayed only at completion. Users and groups are staged in a transactional Durable Object; account linking and authorization are not automatic.</p>
</section>
<section><h2>5. Review and deploy</h2>
<button class="secondary" id="plan">Preview deployment</button><button id="apply">Start deployment</button>
<div id="errors" role="alert"></div><pre id="result" aria-live="polite"></pre>
<div id="install-progress" hidden><h2>Installation progress</h2><ol id="steps"></ol><h3>One-time directory credential</h3><pre id="scim-once" hidden></pre>
<p id="job-info" role="status"></p>
<button class="secondary" id="resume">Continue / Retry</button>
<a id="sign-in-new" target="_blank" rel="noopener noreferrer" hidden>Sign in to your new Nathan instance</a></div>
</section>
</article><aside><h2>What gets created?</h2><ol>
<li>One Better Auth Worker</li><li>One Cloudflare D1 identity database</li>
<li>Private upload and locked-down preview endpoints</li><li>OAuth provider credentials stored as Worker secrets</li>
<li>Custom domain and HTTPS</li><li>OIDC issuer, JWKS, and client registration</li>
<li>Identity Studio and OAuth-protected MCP admin tools</li>
</ol>
<h2>What happens next?</h2><p>Log in with your upstream provider, verify your account, and complete the initial admin bootstrap. Then onboard Workers and external OIDC clients from Identity Studio.</p>
<p><a href="https://github.com/gmackie/nathan" target="_blank" rel="noopener noreferrer">Source and deployment docs</a></p>
<p class="muted">Experimental build: this wizard uses Cloudflare's real APIs, but needs live integration testing before production use.</p>
</aside></main><footer>Nathan uses a pinned, integrity-checked release bundle. No Cloudflare OAuth tokens are exposed to the browser.</footer>
<script nonce="__NONCE__">
const $=id=>document.getElementById(id);
let currentUser=null;
const providerLinks={
  google:{url:'https://console.cloud.google.com/auth/clients',desc:'Create an OAuth web application, configure its consent screen, and add this exact redirect URI.'},
  github:{url:'https://github.com/settings/developers',desc:'Create an OAuth App under GitHub Developer Settings and enter its exact authorization callback URL.'}
};
async function api(path,options){
  const response=await fetch(path,{credentials:'same-origin',...options});
  const body=await response.json().catch(()=>({error:'Server returned an invalid response'}));
  if(!response.ok)throw Error(body.error||'Request failed');
  return body;
}
function send(path,body){return api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})}
function fill(select,items,key,label){
  select.textContent='';
  const blank=document.createElement('option');blank.value='';blank.textContent='Select…';select.append(blank);
  items.forEach(item=>{const opt=document.createElement('option');opt.value=item[key];opt.textContent=item[label];select.append(opt)});
}
function validPlan(){
  return {accountId:$('accounts').value,hostname:$('hostname').value.trim().toLowerCase(),
    name:$('worker').value.trim().toLowerCase(),adminEmail:$('admin-email').value.trim().toLowerCase(),
    securityProfile:$('profile').value,enterpriseSSO:$('enterprise').checked,
    realmEnabled:$('realm-enabled').checked,realmApex:$('realm-enabled').checked?$('realm-apex').value.trim().toLowerCase():undefined,
    scimEnabled:$('scim-enabled').checked,
    scimConnectionId:$('scim-enabled').checked?$('scim-connection').value.trim().toLowerCase():undefined,
    scimDomain:$('scim-enabled').checked?$('scim-domain').value.trim().toLowerCase():undefined,
    mfaPolicy:$('mfa').value==='optional'?'optional':'required'};
}
function updateRealmApex(){
  const host=$('hostname').value.trim().toLowerCase();
  if(host.startsWith('login.'))$('realm-apex').value=host.slice(6);
}
function updateGuide(){
  const provider=$('provider').value,host=$('hostname').value.trim().toLowerCase();
  const link=providerLinks[provider];
  $('provider-console').href=link.url;$('provider-instructions').textContent=link.desc;
  $('provider-callback').textContent=host?'https://'+host+'/api/auth/callback/'+provider:'Choose an identity hostname first.';
}
$('hostname').oninput=()=>{updateRealmApex();updateGuide()};$('provider').onchange=updateGuide;
$('copy-callback').onclick=()=>navigator.clipboard.writeText($('provider-callback').textContent);
$('accounts').onchange=async()=>{
  const account=$('accounts').value;if(!account)return;
  try{
    const data=await api('/api/zones?account='+encodeURIComponent(account));
    fill($('zones'),data.zones,'id','name');
  }catch(e){$('errors').textContent=e.message}
};
$('zones').onchange=()=>{
  if($('zones').value){$('hostname').value='login.'+$('zones').selectedOptions[0].textContent;updateRealmApex();updateGuide()}
};
async function load(){
  updateRealmApex();updateGuide();
  try{
    const s=await api('/api/session');currentUser=s.user;
    $('session').textContent='Signed in as '+s.user.email;
    $('admin-email').value=s.user.email;
    const a=await api('/api/accounts');fill($('accounts'),a.accounts,'id','name');
    const id=sessionStorage.getItem('nathan-job');
    if(id)await resumeStatus(id);
  }catch(e){$('session').textContent='Not connected. Use Connect Cloudflare to sign in.';}
}
async function resumeStatus(id){
  try{const {job}=await api('/api/install/status?id='+encodeURIComponent(id));renderJob(job)}
  catch{sessionStorage.removeItem('nathan-job')}
}
function renderJob(job){
  $('install-progress').hidden=false;
  if(job.oneTimeScim){
    $('scim-once').hidden=false;
    $('scim-once').textContent=JSON.stringify(job.oneTimeScim,null,2);
  }
  $('steps').textContent='';
  for(const item of job.steps||[]){
    const el=document.createElement('li');
    el.textContent=item.stage+' — '+item.status;el.className=item.status==='done'?'done':item.status==='next'?'active':'';
    $('steps').append(el);
  }
  $('job-info').textContent='Stage: '+job.stage+' · '+job.url;
  if(job.actionRequired?.url){
    $('sign-in-new').hidden=false;$('sign-in-new').href=job.actionRequired.url;
    $('sign-in-new').textContent=job.actionRequired.kind==='security-enrollment'
      ? 'Enroll authenticators and finish admin setup'
      : 'Sign in at '+job.actionRequired.url;
    $('job-info').textContent=job.actionRequired.instruction;
  }else $('sign-in-new').hidden=true;
  if(job.stage==='complete'){
    $('result').textContent='Nathan installed. Open '+job.url+'/studio to configure OAuth, enterprise SSO, SCIM and other applications. If a one-time SCIM token was lost, rotate it inside Identity Studio.';
    $('resume').disabled=true;
  }
}
let advancing=false;
async function advance(id){
  if(advancing)return;advancing=true;$('errors').textContent='';$('resume').disabled=true;
  try{
    for(let n=0;n<12;n++){
      const status=(await api('/api/install/status?id='+encodeURIComponent(id))).job;
      renderJob(status);
      if(status.stage==='complete')break;
      const credentials=status.stage==='upload'?{
        provider:$('provider').value,clientId:$('client-id').value.trim(),clientSecret:$('client-secret').value
      }:{};
      if(status.stage==='upload'&&(!credentials.clientId||!credentials.clientSecret))
        throw Error('Enter the OAuth client ID and secret to proceed with the private Worker upload.');
      const {job}=await send('/api/install/advance',{id,credentials});
      if(status.stage==='upload')$('client-secret').value='';
      renderJob(job);
      if(job.actionRequired){$('result').textContent='Action required: '+job.actionRequired.instruction;break}
      if(job.stage==='complete')break;
    }
  }catch(e){$('errors').textContent=e.message}
  finally{advancing=false;$('resume').disabled=false}
}
$('discover-hosts').onclick=async()=>{
  const out=$('discovered-hosts');out.textContent='Reading proxied DNS and Worker custom domains...';
  try{
    const account=$('accounts').value,apex=$('realm-apex').value.trim().toLowerCase();
    const data=await api('/api/realm/discover?account='+encodeURIComponent(account)+'&apex='+encodeURIComponent(apex));
    out.textContent=data.candidates.map(x=>x.hostname+' → '+x.oidcRedirectUri+' ['+x.sources.join(', ')+']').join('\n')||
      'No proxied HTTP hostnames found. The root can still be added explicitly later.';
    out.textContent+='\n\nReview and register approved hosts in Identity Studio after deployment.';
  }catch(e){out.textContent=e.message}
};
$('plan').onclick=async()=>{
  $('errors').textContent='';$('result').textContent='Checking account and DNS...';
  try{const plan=await send('/api/plan',validPlan());$('result').textContent=JSON.stringify(plan,null,2)}
  catch(e){$('result').textContent='';$('errors').textContent=e.message}
};
$('apply').onclick=async()=>{
  $('errors').textContent='';
  const plan=validPlan();
  if(!confirm('Create a Worker, D1 database and route '+plan.hostname+' in your Cloudflare account?'))return;
  try{
    const {job}=await send('/api/install/start',plan);
    sessionStorage.setItem('nathan-job',job.id);
    renderJob(job);await advance(job.id);
  }catch(e){$('errors').textContent=e.message}
};
$('resume').onclick=async()=>{
  const id=sessionStorage.getItem('nathan-job');
  if(id)await advance(id);
};
$('disconnect').onclick=async()=>{
  await fetch('/api/logout',{method:'POST',credentials:'same-origin',headers:{Origin:location.origin}});
  sessionStorage.removeItem('nathan-job');location.assign('/');
};
void load();
</script></body></html>`.replaceAll("__NONCE__",nonce);
}
