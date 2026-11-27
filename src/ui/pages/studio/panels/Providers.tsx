/**
 * NATH-39 Studio: social login providers (NATH-9). Everything renders from GET /providers, which
 * carries the shared registry guide (console deep link, exact callback URL, scopes, steps, field
 * schema) and non-secret status. Secrets are only ever sent to the server, never read back, and
 * the secret inputs are cleared after a save.
 */
import { useState } from "react";
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { Collapsible } from "@cloudflare/kumo/components/collapsible";
import { Input, InputArea } from "@cloudflare/kumo/components/input";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import { Code, Loaded, Panel, Prose, RefreshButton, Row, Section, useAction, useConfirm, useLoad, when, ErrorBanner, Notice } from "../kit.tsx";

const SOURCES: Record<string, string> = {
  "worker-secret": "Worker secret (CLI)", "encrypted-d1": "encrypted in D1 (Studio)", "legacy-worker-secret": "legacy Worker secrets"
};

function summary(p: any): string {
  if (!p.configured) return "Not configured";
  return (p.enabled ? "Enabled" : "Disabled") + " · " + (SOURCES[p.source] || p.source) + (p.secretName ? " " + p.secretName : "") +
    " · last successful test: " + (p.testedAt ? when(p.testedAt) : "never") + (p.testedAt ? (p.testedByAdmin ? " (administrator)" : " (not an administrator)") : "");
}

const normalize = (field: any, value: string) => field.multiline ? value.replace(/\r\n?/g, "\n").trim() : value.trim();

export function Providers() {
  const providers = useLoad(() => apiGet("/providers"));
  const enabled = providers.data?.providers?.filter((p: any) => p.enabled).length;
  return (
    <Panel title="Social login providers" description={<>
      <Prose>Configure Google, GitHub, Apple, Discord, Twitch and X without redeploying. None of these services lets Nathan create the OAuth app for
        you, so each card links straight to the right console page, gives the exact callback URL to paste, and checks your credentials before saving.
        Secrets are encrypted in your own D1 database and are never shown again.</Prose>
      <Prose>Each provider has one credential source: a <Code>NATHAN_PROVIDER_&lt;ID&gt;</Code> Worker secret set by the CLI wins over credentials saved
        here, which win over legacy Worker secrets. You can disable a provider only while another enabled login method has a successful test sign-in by
        a Nathan administrator with its current credentials. Changing credentials, by any path, voids that provider's test.</Prose>
    </>}>
      <Row>
        <RefreshButton onClick={() => void providers.reload()} label="Refresh providers" />
        {providers.data ? <span className="nathan-text nathan-studio-muted" role="status">{enabled} of {providers.data.providers.length} providers enabled.</span> : null}
      </Row>
      <Loaded state={providers}>{(d: any) => (
        <div className="nathan-stack">
          {d.providers.map((p: any) => <ProviderCard key={p.id} p={p} reload={() => void providers.reload()} />)}
        </div>
      )}</Loaded>
    </Panel>
  );
}

function ProviderCard({ p, reload }: { p: any; reload: () => void }) {
  const action = useAction();
  const ask = useConfirm();
  const initial = Object.fromEntries(p.fields.map((f: any) => [f.name, !f.secret && p.values?.[f.name] ? String(p.values[f.name]) : ""]));
  const [values, setValues] = useState<Record<string, string>>(initial);
  const [testError, setTestError] = useState<Error | null>(null);
  const set = (name: string, v: string) => setValues(x => ({ ...x, [name]: v }));

  function collect(): Record<string, string> {
    const out: Record<string, string> = {}, errors: string[] = [];
    for (const field of p.fields) {
      const v = normalize(field, values[field.name] ?? "");
      if (v.length < field.min || v.length > field.max || !new RegExp(field.pattern).test(v)) errors.push(field.label + (field.hint ? " (" + field.hint + ")" : ""));
      out[field.name] = v;
    }
    if (errors.length) throw Error("Check these fields: " + errors.join("; ") + ". Credentials were not sent.");
    return out;
  }
  const save = () => {
    let fields: Record<string, string>;
    try { fields = collect(); } catch (e) { return action.run(async () => { throw e; }); }
    return action.run(() => apiPost("/providers", { id: p.id, fields }), {
      confirm: confirmations.providers.save(p.name), message: r => r?.note ?? "Saved",
      after: () => {
        setValues(x => Object.fromEntries(Object.entries(x).map(([k, v]) => [k, p.fields.find((f: any) => f.name === k)?.secret ? "" : v])));
        reload();
      }
    });
  };
  const setEnabled = (on: boolean) => action.run(confirm => apiPost("/providers/status", { id: p.id, enabled: on, confirm }),
    { confirm: confirmations.providers.status(p.id, p.name, on), message: on ? "Enabled" : "Disabled", after: reload });
  const test = async () => {
    setTestError(null);
    if (await ask(confirmations.providers.test(p.name)) === null) return;
    try {
      const t = await apiPost("/providers/test", { id: p.id });
      const r = await fetch("/api/auth/sign-in/social", { method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify({ provider: p.id, callbackURL: t.callbackURL }) });
      const d = await r.json().catch(() => ({})) as any;
      const url = d.url || d.data?.url;
      if (!r.ok || !url) throw Error("The provider did not return a sign-in URL");
      location.assign(url);
    } catch (e) { setTestError(e instanceof Error ? e : Error("Test sign-in failed")); }
  };
  const [copied, setCopied] = useState(false);
  const notices = [p.error, ...(p.notices || [])].filter(Boolean);
  const consoleUrl = typeof p.consoleUrl === "string" && /^https:\/\//.test(p.consoleUrl) ? p.consoleUrl : null;
  return (
    <Section title={p.name}>
      <Row>
        <Badge variant={p.enabled ? "success" : "neutral"}>{p.enabled ? "Enabled" : p.configured ? "Disabled" : "Not configured"}</Badge>
        <span className="nathan-text nathan-studio-muted">{summary(p)}</span>
      </Row>
      {notices.length ? <Notice title="Attention" tone="alert"><ul className="nathan-studio-list">{notices.map((n: string, i: number) => <li key={i}>{n}</li>)}</ul></Notice> : null}
      <Collapsible.Root defaultOpen={!p.configured}>
        <Collapsible.DefaultTrigger>{"Guided setup for " + p.name}</Collapsible.DefaultTrigger>
        <Collapsible.Panel>
          <div className="nathan-stack">
            {consoleUrl ? <p className="nathan-text"><a className="nathan-studio-link" href={consoleUrl} target="_blank" rel="noopener noreferrer">Open the {p.name} developer console ↗</a></p> : null}
            <ol className="nathan-studio-list">{p.steps.map((s: string, i: number) => <li key={i}>{s}</li>)}</ol>
            <Prose>Callback URL ({p.responseMode === "form_post" ? "Apple posts the response to it" : "paste exactly"}):</Prose>
            <pre className="nathan-studio-json"><code>{p.callbackUrl}</code></pre>
            <Row><Button size="sm" variant="secondary" onClick={() => navigator.clipboard.writeText(p.callbackUrl).then(() => setCopied(true))}>
              {copied ? "Callback URL copied" : "Copy callback URL"}</Button></Row>
            <Prose>Scopes: {p.scopes.join(" ")}</Prose>
            <Prose>Email trust: {p.emailTrust}</Prose>
            {p.gotchas.length ? <ul className="nathan-studio-list">{p.gotchas.map((g: string, i: number) => <li key={i}>{g}</li>)}</ul> : null}
          </div>
        </Collapsible.Panel>
      </Collapsible.Root>
      <form className="nathan-stack" noValidate onSubmit={e => { e.preventDefault(); void save(); }}>
        {p.fields.map((field: any) => {
          const stored = p.secretsSet.includes(field.name);
          const placeholder = field.secret ? (stored ? "Stored and encrypted. Enter a new value to rotate." : "Paste " + field.label) : (field.hint || "");
          const id = "prov-" + p.id + "-" + field.name;
          return (
            <div key={field.name} className="nathan-stack">
              {field.multiline
                ? <InputArea id={id} label={field.label} rows={6} value={values[field.name] ?? ""} placeholder={placeholder} spellCheck={false}
                    autoComplete="off" description={field.hint} onValueChange={v => set(field.name, v)} />
                : <Input id={id} label={field.label} type={field.secret ? "password" : "text"} value={values[field.name] ?? ""} placeholder={placeholder}
                    spellCheck={false} autoComplete={field.secret ? "new-password" : "off"} description={field.hint} onChange={e => set(field.name, e.target.value)} />}
              {field.file ? (
                <label className="nathan-text nathan-studio-muted">or choose the {field.file} file:{" "}
                  <input type="file" accept={field.file} onChange={async e => { const file = e.target.files?.[0]; if (file) set(field.name, await file.text()); }} />
                </label>
              ) : null}
            </div>
          );
        })}
        <Row>
          <Button type="submit" variant="primary" disabled={!p.canSaveInStudio}>{p.configured ? "Save / rotate credentials" : "Save credentials"}</Button>
          <Button type="button" variant="secondary" onClick={() => void setEnabled(true)}>Enable</Button>
          <Button type="button" variant="secondary-destructive" onClick={() => void setEnabled(false)}>Disable</Button>
          <Button type="button" variant="secondary" disabled={!p.enabled} onClick={() => void test()}>Test sign-in</Button>
        </Row>
      </form>
      {testError ? <ErrorBanner error={testError} /> : null}
      {action.view}
    </Section>
  );
}
