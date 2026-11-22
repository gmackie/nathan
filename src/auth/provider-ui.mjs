/**
 * Identity Studio "Social login providers" page (NATH-9). Everything is rendered client-side
 * from GET /studio/api/providers, which carries the shared registry guide (console deep link,
 * exact callback URL, scopes, steps, field schema) and non-secret status. Secrets are only
 * ever sent to the server, never read back.
 */
export const providerStudioSection = `<h2>Social login providers</h2>
  <p>Configure Google, GitHub, Apple, Discord, Twitch and X without redeploying. None of these services lets Nathan create the OAuth app for you, so each card links straight to the right console page, gives the exact callback URL to paste, and checks your credentials before saving. Secrets are encrypted in your own D1 database and are never shown again.</p>
  <p><small>Each provider has one credential source: a <code>NATHAN_PROVIDER_&lt;ID&gt;</code> Worker secret set by the CLI wins over credentials saved here, which win over legacy Worker secrets. You can disable a provider only while another enabled login method has a successful test sign-in by a Nathan administrator with its current credentials. Changing credentials, by any path, voids that provider's test.</small></p>
  <button class="secondary" id="providers-refresh">Refresh providers</button>
  <p id="providers-status" role="status"></p>
  <div id="providers-root" aria-live="polite"></div>`;

export const providerStudioScript = String.raw`
    (function(){
      const root=document.getElementById('providers-root');
      const status=document.getElementById('providers-status');
      const el=(tag,props,children)=>{
        const n=document.createElement(tag);
        if(props)for(const [k,v] of Object.entries(props)){
          if(k==='text')n.textContent=v;else if(k in n)n[k]=v;else n.setAttribute(k,v);
        }
        for(const c of children||[])if(c)n.append(c);
        return n;
      };
      const when=t=>t?new Date(t*1000).toISOString().replace('T',' ').slice(0,16)+' UTC':'never';
      const sources={'worker-secret':'Worker secret (CLI)','encrypted-d1':'encrypted in D1 (Studio)','legacy-worker-secret':'legacy Worker secrets'};
      function summary(p){
        if(!p.configured)return 'Not configured';
        return (p.enabled?'Enabled':'Disabled')+' · '+(sources[p.source]||p.source)+(p.secretName?' '+p.secretName:'')+
          ' · last successful test: '+when(p.testedAt)+(p.testedAt?(p.testedByAdmin?' (administrator)':' (not an administrator)'):'');
      }
      function normalize(field,value){return field.multiline?value.replace(/\r\n?/g,'\n').trim():value.trim()}
      function card(p){
        const result=el('p',{role:'status'});
        const steps=el('ol',null,p.steps.map(s=>el('li',{text:s})));
        const callback=el('code',{text:p.callbackUrl});
        const copy=el('button',{type:'button',className:'secondary',text:'Copy callback URL'});
        copy.addEventListener('click',()=>navigator.clipboard.writeText(p.callbackUrl).then(()=>{result.textContent='Callback URL copied.'}));
        const consoleLink=el('a',{href:p.consoleUrl,target:'_blank',rel:'noopener noreferrer',text:'Open the '+p.name+' developer console ↗'});
        const inputs={};
        const fields=p.fields.map(f=>{
          const set=p.secretsSet.includes(f.name);
          const input=f.multiline?el('textarea',{rows:6,autocomplete:'off',spellcheck:false}):
            el('input',{type:f.secret?'password':'text',autocomplete:f.secret?'new-password':'off',spellcheck:false});
          input.id='prov-'+p.id+'-'+f.name;
          if(!f.secret&&p.values[f.name])input.value=p.values[f.name];
          input.placeholder=f.secret?(set?'Stored and encrypted. Enter a new value to rotate.':'Paste '+f.label):(f.hint||'');
          inputs[f.name]={field:f,input};
          const label=el('label',{htmlFor:input.id},[document.createTextNode(f.label),input]);
          if(f.file){
            const file=el('input',{type:'file',accept:f.file});
            file.addEventListener('change',async()=>{if(file.files[0])input.value=await file.files[0].text()});
            label.append(el('small',{text:'or choose the '+f.file+' file: '}),file);
          }
          if(f.hint)label.append(el('small',{text:f.hint}));
          return label;
        });
        function collect(){
          const values={},errors=[];
          for(const {field,input} of Object.values(inputs)){
            const v=normalize(field,input.value);
            if(v.length<field.min||v.length>field.max||!new RegExp(field.pattern).test(v))errors.push(field.label+(field.hint?' ('+field.hint+')':''));
            values[field.name]=v;
          }
          if(errors.length)throw Error('Check these fields: '+errors.join('; ')+'. Credentials were not sent.');
          return values;
        }
        const save=el('button',{type:'button',text:p.configured?'Save / rotate credentials':'Save credentials'});
        save.disabled=!p.canSaveInStudio;
        save.addEventListener('click',async()=>{
          try{
            const values=collect();
            if(!confirm('Store these '+p.name+' credentials encrypted in Nathan? This enables '+p.name+' and clears its last test result.'))return;
            const r=await postJson('/studio/api/providers',{id:p.id,fields:values});
            for(const {field,input} of Object.values(inputs))if(field.secret)input.value='';
            result.textContent=r.note;await load();
          }catch(e){result.textContent=e.message}
        });
        async function setEnabled(enabled){
          const conf='CONFIRM '+(enabled?'ENABLE ':'DISABLE ')+p.id;
          if(!confirm('Change '+p.name+' sign-in to '+(enabled?'enabled':'disabled')+'?'))return;
          try{await postJson('/studio/api/providers/status',{id:p.id,enabled,confirm:conf});await load()}
          catch(e){result.textContent=e.message}
        }
        const enable=el('button',{type:'button',className:'secondary',text:'Enable'});
        enable.addEventListener('click',()=>setEnabled(true));
        const disable=el('button',{type:'button',className:'secondary',text:'Disable'});
        disable.addEventListener('click',()=>setEnabled(false));
        const test=el('button',{type:'button',className:'secondary',text:'Test sign-in'});
        test.disabled=!p.enabled;
        test.addEventListener('click',async()=>{
          if(!confirm('Sign in with '+p.name+' now, ideally with a test account? You will be signed in as that account; sign back in as an administrator afterwards.'))return;
          try{
            const t=await postJson('/studio/api/providers/test',{id:p.id});
            const r=await fetch('/api/auth/sign-in/social',{method:'POST',credentials:'same-origin',
              headers:{'Content-Type':'application/json'},body:JSON.stringify({provider:p.id,callbackURL:t.callbackURL})});
            const d=await r.json().catch(()=>({}));
            if(!r.ok||!(d.url||d.data&&d.data.url))throw Error('The provider did not return a sign-in URL');
            location.assign(d.url||d.data.url);
          }catch(e){result.textContent=e.message}
        });
        const guide=el('details',{open:!p.configured},[
          el('summary',{text:'Guided setup for '+p.name}),consoleLink,steps,
          el('p',null,[document.createTextNode('Callback URL ('+(p.responseMode==='form_post'?'Apple posts the response to it':'paste exactly')+'):')]),
          el('pre',null,[callback]),copy,
          el('p',null,[el('small',{text:'Scopes: '+p.scopes.join(' ')})]),
          el('p',null,[el('small',{text:'Email trust: '+p.emailTrust})]),
          p.gotchas.length?el('ul',null,p.gotchas.map(g=>el('li',{text:g}))):null
        ]);
        const notices=[p.error,...(p.notices||[])].filter(Boolean);
        return el('article',{id:'provider-'+p.id},[
          el('h3',{text:p.name}),el('p',null,[el('small',{text:summary(p)})]),
          notices.length?el('ul',{role:'note'},notices.map(n=>el('li',{text:n}))):null,
          guide,...fields,save,enable,disable,test,result
        ]);
      }
      async function load(){
        status.textContent='Loading providers...';
        try{
          const d=await j('/studio/api/providers');
          root.textContent='';d.providers.forEach(p=>root.append(card(p)));
          status.textContent=d.providers.filter(p=>p.enabled).length+' of '+d.providers.length+' providers enabled.';
        }catch(e){status.textContent=e.message}
      }
      document.getElementById('providers-refresh').addEventListener('click',load);
      void load();
    })();
`;

/** @param {string} s */
const escape = (s) => s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

/** Result of a Studio test sign-in. Static HTML, no script. */
/**
 * @param {boolean} ok
 * @param {string | null} provider
 * @param {string} email
 * @param {boolean} [adminVerified] the account that signed in is a current Nathan administrator
 * @returns {Response}
 */
export function providerTestResultPage(ok, provider, email, adminVerified = false) {
  const title = ok ? "Test sign-in succeeded" : "Test sign-in not recorded";
  const body = ok
    ? "<p>Nathan received a successful <strong>" + escape(provider ?? "") + "</strong> sign-in and recorded the test against the provider's current credentials.</p>" +
      (adminVerified
        ? "<p>You signed in as a Nathan administrator, so this provider can now remain as the only login method administrators use.</p>"
        : "<p>The account you used is not a Nathan administrator. The test shows the provider works, but it does not count toward " +
          "keeping administrator access: you can't disable your other login methods until an administrator completes a test sign-in.</p>")
    : "<p>Nathan could not confirm a fresh sign-in through the provider with the credentials the test was started for. The test link may " +
      "have expired or been used, the credentials may have changed since the test started, or the sign-in did not complete. " +
      "Start a new test from Identity Studio.</p>";
  const who = email ? "<p><small>You are currently signed in as " + escape(email) + ". Sign in again as an administrator to continue in Identity Studio.</small></p>" : "";
  const html = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<title>" + title + " · Nathan</title></head><body><main><h1>" + title + "</h1>" + body + who +
    "<p><a href=\"/sign-in\">Sign in</a> · <a href=\"/studio\">Identity Studio</a></p></main></body></html>";
  return new Response(html, {
    status: ok ? 200 : 400,
    headers: {
      "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"
    }
  });
}
