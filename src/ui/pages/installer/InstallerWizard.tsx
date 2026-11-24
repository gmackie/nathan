/**
 * NATH-40: the hosted installer's wizard, a React island (src/ui/islands/installer-wizard.tsx).
 *
 * Same behaviour as the former inline script in src/installer/ui.ts, now in a hashed, SRI-pinned
 * bundle: same-origin fetch() to /api/* only (credentials 'same-origin', JSON bodies, the worker
 * checks Origin), Cloudflare OAuth tokens never reach the browser, the install job id is the only
 * thing kept in sessionStorage, and secret provider fields are cleared once the upload stage has
 * taken them. All server- and provider-supplied text is rendered by React, so it is escaped.
 *
 * The registry and callback-URL function come from src/shared/providers.mjs directly, so the
 * server render and the hydrated island use the same data and no props are serialised.
 */
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { CSPProvider } from "@cloudflare/kumo/primitives/csp-provider";
import { Banner } from "@cloudflare/kumo/components/banner";
import { Button, LinkButton } from "@cloudflare/kumo/components/button";
import { Checkbox } from "@cloudflare/kumo/components/checkbox";
import { Input, InputArea } from "@cloudflare/kumo/components/input";
import { Select } from "@cloudflare/kumo/components/select";
import { callbackUrl, installerRegistry } from "../../../shared/providers.mjs";

interface ProviderField {
  name: string; label: string; secret: boolean; min: number; max: number; pattern: string;
  hint?: string; multiline?: boolean; file?: string; optional?: boolean; checkbox?: boolean;
}
interface Provider {
  id: string; name: string; consoleUrl: string | null; consoleHint: string | null; steps: string[]; gotchas: string[]; emailTrust: string; fields: ProviderField[];
}
interface Option { id: string; name: string }
interface JobStep { stage: string; status: string }
interface Job {
  id: string; stage: string; url: string; steps?: JobStep[];
  oneTimeScim?: unknown;
  actionRequired?: { url?: string; kind?: string; instruction?: string } | null;
}

const PROVIDERS = installerRegistry().providers as Provider[];
const JOB_KEY = "nathan-job";

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  const body = await response.json().catch(() => ({ error: "Server returned an invalid response" })) as { error?: string };
  if (!response.ok) throw Error(body.error || "Request failed");
  return body as T;
}
const send = <T,>(path: string, body: unknown) =>
  api<T>(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const message = (e: unknown) => e instanceof Error ? e.message : String(e);

function storage(): Storage | null {
  try { return window.sessionStorage; } catch { return null; }
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="nathan-section">
      <h2 className="nathan-heading">{title}</h2>
      <div className="nathan-stack">{children}</div>
    </section>
  );
}
const Muted = ({ children }: { children: ReactNode }) => <p className="nathan-muted">{children}</p>;
const optionItems = (items: Option[]) => items.map(i => ({ value: i.id, label: i.name }));

export interface InstallerWizardProps {
  /** Initial identity hostname and provider (tests; the page passes none). */
  initialHostname?: string;
  initialProvider?: string;
}

/** Providers the wizard offers, in order (the shared registry). */
export const installerProviderIds = () => PROVIDERS.map(p => p.id);

export function InstallerWizard({ initialHostname = "", initialProvider }: InstallerWizardProps = {}) {
  const [hydrated, setHydrated] = useState(false);
  const [session, setSession] = useState("Checking session…");
  const [accounts, setAccounts] = useState<Option[]>([]);
  const [account, setAccount] = useState("");
  const [zones, setZones] = useState<Option[]>([]);
  const [zone, setZone] = useState("");
  const [hostname, setHostname] = useState(initialHostname);
  const [realmEnabled, setRealmEnabled] = useState(true);
  const [realmApex, setRealmApex] = useState("");
  const [worker, setWorker] = useState("nathan-auth");
  const [adminEmail, setAdminEmail] = useState("");
  const [profile, setProfile] = useState("business");
  const [providerId, setProviderId] = useState(PROVIDERS.some(p => p.id === initialProvider) ? initialProvider! : PROVIDERS[0].id);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [enterprise, setEnterprise] = useState(false);
  const [mfa, setMfa] = useState("optional");
  const [scimEnabled, setScimEnabled] = useState(false);
  const [scimConnection, setScimConnection] = useState("");
  const [scimDomain, setScimDomain] = useState("");
  const [discovered, setDiscovered] = useState("");
  const [errors, setErrors] = useState("");
  const [result, setResult] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const [advancing, setAdvancing] = useState(false);
  const advancingRef = useRef(false);
  // advance() reads the latest provider and fields without re-binding.
  const latest = useRef({ providerId, fields });
  latest.current = { providerId, fields };

  const provider = PROVIDERS.find(p => p.id === providerId) ?? PROVIDERS[0];
  const host = hostname.trim().toLowerCase();
  const callback = useMemo(() => {
    if (!host) return "Choose an identity hostname first.";
    try { return callbackUrl(host, provider.id); } catch { return "Enter a valid identity hostname."; }
  }, [host, provider.id]);

  function changeHostname(value: string) {
    setHostname(value);
    const h = value.trim().toLowerCase();
    if (h.startsWith("login.")) setRealmApex(h.slice(6));
  }

  function plan() {
    return {
      accountId: account, hostname: host, name: worker.trim().toLowerCase(), adminEmail: adminEmail.trim().toLowerCase(),
      securityProfile: profile, enterpriseSSO: enterprise,
      realmEnabled, realmApex: realmEnabled ? realmApex.trim().toLowerCase() : undefined,
      scimEnabled,
      scimConnectionId: scimEnabled ? scimConnection.trim().toLowerCase() : undefined,
      scimDomain: scimEnabled ? scimDomain.trim().toLowerCase() : undefined,
      mfaPolicy: mfa === "optional" ? "optional" : "required"
    };
  }

  function providerFields(): Record<string, string> {
    const { providerId: id, fields: values } = latest.current;
    const p = PROVIDERS.find(x => x.id === id) ?? PROVIDERS[0];
    const out: Record<string, string> = {}, bad: string[] = [];
    for (const f of p.fields) {
      const raw = values[f.name] ?? "";
      const v = f.multiline ? raw.replace(/\r\n?/g, "\n").trim() : raw.trim();
      if (f.optional && v === "") continue;
      if (v.length < f.min || v.length > f.max || !new RegExp(f.pattern).test(v)) bad.push(f.label + (f.hint ? " (" + f.hint + ")" : ""));
      out[f.name] = v;
    }
    if (bad.length) throw Error("Check the " + p.name + " fields: " + bad.join("; "));
    return out;
  }

  function clearSecrets() {
    const p = PROVIDERS.find(x => x.id === latest.current.providerId) ?? PROVIDERS[0];
    setFields(prev => {
      const next = { ...prev };
      for (const f of p.fields) if (f.secret) next[f.name] = "";
      return next;
    });
  }

  function renderJob(next: Job) {
    setJob(next);
    if (next.stage === "complete")
      setResult("Nathan installed. Open " + next.url + "/studio to configure OAuth, enterprise SSO, SCIM and other applications. If a one-time SCIM token was lost, rotate it inside Identity Studio.");
  }

  async function advance(id: string) {
    if (advancingRef.current) return;
    advancingRef.current = true; setAdvancing(true); setErrors("");
    try {
      for (let n = 0; n < 12; n++) {
        const status = (await api<{ job: Job }>("/api/install/status?id=" + encodeURIComponent(id))).job;
        renderJob(status);
        if (status.stage === "complete") break;
        const credentials = status.stage === "upload" ? { provider: latest.current.providerId, fields: providerFields() } : {};
        const { job: advanced } = await send<{ job: Job }>("/api/install/advance", { id, credentials });
        if (status.stage === "upload") clearSecrets();
        renderJob(advanced);
        if (advanced.actionRequired) { setResult("Action required: " + advanced.actionRequired.instruction); break; }
        if (advanced.stage === "complete") break;
      }
    } catch (e) { setErrors(message(e)); }
    finally { advancingRef.current = false; setAdvancing(false); }
  }

  useEffect(() => {
    setHydrated(true);
    (async () => {
      try {
        const s = await api<{ user: { email: string } }>("/api/session");
        setSession("Signed in as " + s.user.email);
        setAdminEmail(s.user.email);
        const a = await api<{ accounts: Option[] }>("/api/accounts");
        setAccounts(a.accounts);
        const id = storage()?.getItem(JOB_KEY);
        if (id) {
          try { renderJob((await api<{ job: Job }>("/api/install/status?id=" + encodeURIComponent(id))).job); }
          catch { storage()?.removeItem(JOB_KEY); }
        }
      } catch { setSession("Not connected. Use Connect Cloudflare to sign in."); }
    })();
  }, []);

  async function chooseAccount(id: string) {
    setAccount(id); setZone("");
    if (!id) return;
    try { setZones((await api<{ zones: Option[] }>("/api/zones?account=" + encodeURIComponent(id))).zones); }
    catch (e) { setErrors(message(e)); }
  }
  function chooseZone(id: string) {
    setZone(id);
    const name = zones.find(z => z.id === id)?.name;
    if (name) changeHostname("login." + name);
  }

  async function discover() {
    setDiscovered("Reading proxied DNS and Worker custom domains...");
    try {
      const data = await api<{ candidates: Array<{ hostname: string; oidcRedirectUri: string; sources: string[] }> }>(
        "/api/realm/discover?account=" + encodeURIComponent(account) + "&apex=" + encodeURIComponent(realmApex.trim().toLowerCase()));
      setDiscovered((data.candidates.map(x => x.hostname + " → " + x.oidcRedirectUri + " [" + x.sources.join(", ") + "]").join("\n") ||
        "No proxied HTTP hostnames found. The root can still be added explicitly later.") +
        "\n\nReview and register approved hosts in Identity Studio after deployment.");
    } catch (e) { setDiscovered(message(e)); }
  }
  async function preview() {
    setErrors(""); setResult("Checking account and DNS...");
    try { setResult(JSON.stringify(await send("/api/plan", plan()), null, 2)); }
    catch (e) { setResult(""); setErrors(message(e)); }
  }
  async function start() {
    setErrors("");
    const p = plan();
    if (!window.confirm("Create a Worker, D1 database and route " + p.hostname + " in your Cloudflare account?")) return;
    try {
      const { job: started } = await send<{ job: Job }>("/api/install/start", p);
      storage()?.setItem(JOB_KEY, started.id);
      renderJob(started);
      await advance(started.id);
    } catch (e) { setErrors(message(e)); }
  }
  async function resume() {
    const id = storage()?.getItem(JOB_KEY);
    if (id) await advance(id);
  }
  async function disconnect() {
    await fetch("/api/logout", { method: "POST", credentials: "same-origin", headers: { Origin: location.origin } });
    storage()?.removeItem(JOB_KEY);
    location.assign("/");
  }
  async function readFile(name: string, file: File | undefined) {
    if (file) { const text = await file.text(); setFields(prev => ({ ...prev, [name]: text })); }
  }

  const off = !hydrated;
  const action = job?.actionRequired?.url ? job.actionRequired : null;
  return (
    // The server render carries the page nonce; in the browser Base UI may not add <style> elements.
    <CSPProvider disableStyleElements>
      <div className="nathan-stack nathan-wizard" data-hydrated={hydrated ? "true" : "false"}>
        <Section title="1. Connect Cloudflare">
          <div className="nathan-actions">
            <LinkButton href="/api/login" variant="primary">Connect Cloudflare</LinkButton>
            <Button variant="secondary" disabled={off} onClick={disconnect}>Disconnect</Button>
          </div>
          <p className="nathan-text" role="status" id="session">{session}</p>
          <Select label="Account" placeholder={accounts.length ? "Select…" : "Sign in to discover accounts"}
            items={optionItems(accounts)} value={account || null} disabled={off || !accounts.length}
            onValueChange={v => void chooseAccount(typeof v === "string" ? v : "")} />
          <Select label="Active DNS zone" placeholder={zones.length ? "Select…" : "Choose an account first"}
            items={optionItems(zones)} value={zone || null} disabled={off || !zones.length}
            onValueChange={v => chooseZone(typeof v === "string" ? v : "")} />
        </Section>

        <Section title="2. Choose installation details">
          <Input label="Identity hostname" placeholder="login.example.com" autoComplete="off" required
            value={hostname} onChange={e => changeHostname(e.target.value)} />
          <Checkbox label="Use this identity provider for the root domain and all authorized subdomains"
            checked={realmEnabled} onCheckedChange={c => setRealmEnabled(c === true)} />
          <Input label="SSO domain (root and subdomains)" placeholder="example.com" autoComplete="off"
            value={realmApex} onChange={e => setRealmApex(e.target.value)} />
          <Muted>One central session at <code>login.example.com</code>, separate OIDC clients for <code>example.com</code> and each subdomain. Nathan never uses wildcard callback URLs or shares login cookies with subdomains.</Muted>
          <div className="nathan-actions">
            <Button variant="secondary" disabled={off} onClick={discover}>Discover existing subdomains</Button>
          </div>
          {discovered ? <pre className="nathan-pre" aria-live="polite">{discovered}</pre> : null}
          <Input label="Worker name" pattern="[a-z0-9-]+" required value={worker} onChange={e => setWorker(e.target.value)} />
          <Input label="Administrator email" type="email" placeholder="you@example.com" value={adminEmail}
            onChange={e => setAdminEmail(e.target.value)}
            description="For secure first-time bootstrap, this must match the email on your Cloudflare OAuth identity." />
          <Select label="Security profile" value={profile} onValueChange={v => setProfile(String(v))} disabled={off}
            items={[{ value: "business", label: "Business — recommended" }, { value: "standard", label: "Standard — consumer / developer" }]} />
        </Section>

        <Section title="3. Configure first sign-in">
          <Select label="Upstream login provider" value={providerId} disabled={off}
            onValueChange={v => setProviderId(String(v))} items={PROVIDERS.map(p => ({ value: p.id, label: p.name }))} />
          <div className="nathan-panel nathan-stack">
            <strong>Provider console guide</strong>
            <ol className="nathan-list">{provider.steps.map(s => <li key={s}>{s}</li>)}</ol>
            <p className="nathan-text">
              {provider.consoleUrl
                ? <a className="nathan-link" href={provider.consoleUrl} target="_blank" rel="noopener noreferrer">{"Open the " + provider.name + " developer console"}</a>
                : provider.consoleHint}
            </p>
            <p className="nathan-text">Authorized redirect URI:</p>
            <pre className="nathan-pre" data-nathan-callback="">{callback}</pre>
            <div className="nathan-actions">
              <Button variant="secondary" disabled={off} onClick={() => void navigator.clipboard.writeText(callback)}>Copy redirect URI</Button>
            </div>
            <Muted>{"Email trust: " + provider.emailTrust}</Muted>
            <ul className="nathan-list nathan-muted">{provider.gotchas.map(s => <li key={s}>{s}</li>)}</ul>
          </div>
          {provider.fields.map(f => {
            const label = provider.name + " " + f.label;
            const common = { label, placeholder: f.hint || "", autoComplete: "off", spellCheck: false, value: fields[f.name] ?? "" };
            return (
              <div className="nathan-stack" key={provider.id + ":" + f.name}>
                {f.checkbox
                  ? <Checkbox label={label} checked={fields[f.name] === "true"} disabled={off}
                      onCheckedChange={c => setFields(prev => ({ ...prev, [f.name]: c === true ? "true" : "" }))} />
                  : f.multiline
                  ? <InputArea {...common} rows={6} onChange={e => setFields(prev => ({ ...prev, [f.name]: e.target.value }))} />
                  : <Input {...common} type={f.secret ? "password" : "text"} onChange={e => setFields(prev => ({ ...prev, [f.name]: e.target.value }))} />}
                {f.file ? <Input label={label + " file"} type="file" accept={f.file} disabled={off}
                  onChange={e => void readFile(f.name, e.target.files?.[0])} /> : null}
              </div>
            );
          })}
          <Muted>Credentials are sent only to your live installation request over HTTPS and encrypted into your new Nathan D1 database under a key held only by your identity Worker. The installer database never stores them. Add more providers later in Identity Studio.</Muted>
        </Section>

        <Section title="4. Enterprise, MFA and directory provisioning">
          <Checkbox label="Enable enterprise SSO plugin" checked={enterprise} onCheckedChange={c => setEnterprise(c === true)} />
          <Muted>After deployment, configure your OIDC/SAML connections in Identity Studio. Employee domains must be verified before use.</Muted>
          <Select label="MFA enforcement" value={mfa} onValueChange={v => setMfa(String(v))} disabled={off} items={[
            { value: "optional", label: "Passkeys + TOTP available (optional)" },
            { value: "admin", label: "Require admin MFA (pending assurance verification)" },
            { value: "all", label: "Require MFA for everyone (pending assurance verification)" }
          ]} />
          <Muted>Required MFA choices will be blocked by the backend until OAuth, passkey, and federated assurance paths have passed security testing.</Muted>
          <h3 className="nathan-subheading">SCIM 2.0 directory provisioning</h3>
          <Checkbox label="Prepare an optional SCIM directory connection" checked={scimEnabled} onCheckedChange={c => setScimEnabled(c === true)} />
          <Input label="Connection ID" placeholder="acme-workforce" autoComplete="off" value={scimConnection} onChange={e => setScimConnection(e.target.value)} />
          <Input label="Corporate directory email domain" placeholder="acme.example" autoComplete="off" value={scimDomain} onChange={e => setScimDomain(e.target.value)} />
          <Muted>The initial connection is created disabled after administrator verification and MFA enrollment. Its one-time bearer token is displayed only at completion. Users and groups are staged in a transactional Durable Object; account linking and authorization are not automatic.</Muted>
        </Section>

        <Section title="5. Review and deploy">
          <div className="nathan-actions">
            <Button variant="secondary" disabled={off} onClick={preview}>Preview deployment</Button>
            <Button variant="primary" disabled={off || advancing} onClick={start}>Start deployment</Button>
          </div>
          <div role="alert">{errors ? <Banner variant="error" text={errors} /> : null}</div>
          {result ? <pre className="nathan-pre" aria-live="polite">{result}</pre> : null}
          {job ? (
            <div className="nathan-stack" id="install-progress">
              <h3 className="nathan-subheading">Installation progress</h3>
              <ol className="nathan-list">
                {(job.steps || []).map(item => (
                  <li key={item.stage} data-status={item.status}>{item.stage + " — " + item.status}</li>
                ))}
              </ol>
              {job.oneTimeScim ? (
                <>
                  <h3 className="nathan-subheading">One-time directory credential</h3>
                  <pre className="nathan-pre">{JSON.stringify(job.oneTimeScim, null, 2)}</pre>
                </>
              ) : null}
              <p className="nathan-text" role="status">{action ? action.instruction : "Stage: " + job.stage + " · " + job.url}</p>
              <div className="nathan-actions">
                <Button variant="secondary" disabled={advancing || job.stage === "complete"} onClick={resume}>Continue / Retry</Button>
                {action?.url && /^https:\/\//.test(action.url) ? (
                  <LinkButton href={action.url} target="_blank" rel="noopener noreferrer" variant="primary">
                    {action.kind === "security-enrollment" ? "Enroll authenticators and finish admin setup" : "Sign in at " + action.url}
                  </LinkButton>
                ) : null}
              </div>
            </div>
          ) : null}
        </Section>
      </div>
    </CSPProvider>
  );
}
