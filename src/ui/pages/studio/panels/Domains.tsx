/** NATH-39 Studio: protected applications (service-binding policies) and the domain-wide SSO realm. */
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import {
  AreaField, CheckField, Code, DataTable, Form, JsonView, Loaded, Panel, Prose, RefreshButton, Row, Section, SelectField, Subsection, TextField,
  useAction, useFields, useLoad, when
} from "../kit.tsx";

const REALM_KINDS = {
  web: "Root or web application", worker: "Cloudflare Worker with OIDC integration",
  gateway: "Nathan gateway for a private Worker", external: "External application"
} as const;

export function Domains() {
  return (
    <Panel title="Protected apps and domains">
      <ProtectedApps />
      <Realm />
    </Panel>
  );
}

function ProtectedApps() {
  const apps = useLoad(() => apiGet("/apps"));
  const action = useAction();
  const f = useFields({ id: "", hostname: "" });
  const save = () => action.run(() => apiPost("/apps", { id: f.values.id, hostname: f.values.hostname }),
    { message: "Policy saved", after: () => { void apps.reload(); } });
  const toggle = (id: string, enabled: boolean) => action.run(confirm => apiPost("/apps/status", { id, enabled, confirm }),
    { confirm: confirmations.apps.status(id, enabled), message: enabled ? "Policy enabled" : "Policy disabled", after: () => { void apps.reload(); } });
  return (
    <Section title="Protected applications" description={<Prose>
      Service-binding policies start disabled and deny everyone until a role is granted under Roles and access. Save a policy, then explicitly enable it.</Prose>}>
      <Form onSubmit={save}>
        <TextField label="Application ID" placeholder="operations" {...f.text("id")} />
        <TextField label="Hostname" placeholder="operations.example.com" {...f.text("hostname")} />
        <Row><Button type="submit" variant="primary">Save policy</Button></Row>
      </Form>
      <Loaded state={apps}>{(d: any) => (
        <DataTable label="Protected applications" empty="No application policies yet." rows={d.applications}
          columns={[{ key: "id", label: "ID" }, { key: "hostname", label: "Hostname" }, { key: "accessMode", label: "Access mode" },
            { key: "enabled", label: "State", render: r => <Badge variant={r.enabled ? "success" : "neutral"}>{r.enabled ? "Enabled" : "Disabled"}</Badge> },
            { key: "updated_at", label: "Updated", render: r => when(r.updated_at) },
            { key: "actions", label: "", render: r => r.enabled
              ? <Button size="sm" variant="secondary-destructive" onClick={() => toggle(String(r.id), false)}>Disable</Button>
              : <Button size="sm" variant="secondary" onClick={() => toggle(String(r.id), true)}>Enable</Button> }]} />
      )}</Loaded>
      <Row><RefreshButton onClick={() => void apps.reload()} label="List policies" /></Row>
      {action.view}
    </Section>
  );
}

function Realm() {
  const realm = useLoad(() => apiGet("/realm"));
  const clients = useLoad(() => apiGet("/realm/clients"));
  const one = useAction();
  const batch = useAction();
  const f = useFields({ hostname: "", kind: "web" as keyof typeof REALM_KINDS, callbackPath: "/auth/callback", publicClient: false, hostnames: "" });
  const setKind = (kind: keyof typeof REALM_KINDS) => f.setValues(v => ({ ...v, kind, callbackPath: kind === "gateway" ? "/__nathan/callback" : "/auth/callback" }));
  const common = () => ({ kind: f.values.kind, callbackPath: f.values.callbackPath, publicClient: f.values.publicClient });
  const register = () => one.run(() => apiPost("/realm/clients", { hostname: f.values.hostname.trim().toLowerCase(), ...common() }),
    { confirm: confirmations.realm.register(), message: "Hostname registered (disabled)", after: () => { void clients.reload(); } });
  const registerBatch = () => batch.run(confirm => apiPost("/realm/clients/batch", { hostnames: f.values.hostnames, ...common(), confirm }),
    { confirm: confirmations.realm.batch(), message: "Hostnames registered (disabled)", after: () => { void clients.reload(); } });
  const apex = realm.data?.realm?.apex;
  return (
    <Section title="Domain-wide SSO" description={<Prose>
      One issuer at <strong>login.&lt;domain&gt;</strong> serves the root and every approved subdomain. Each client gets an exact callback URL and its
      own session. No wildcard redirects or shared parent-domain login cookies.</Prose>}>
      <Loaded state={realm}>{(d: any) => <JsonView value={d} label="Verified realm" />}</Loaded>
      <Subsection title="Register one hostname">
        <Form onSubmit={register}>
          <TextField label="Root or subdomain hostname" placeholder={apex ? String(apex) : "example.com or app.example.com"} {...f.text("hostname")} />
          <SelectField label="Application type" value={f.values.kind} onChange={setKind} options={REALM_KINDS} />
          <TextField label="Exact application callback path" placeholder="/auth/callback" {...f.text("callbackPath")} />
          <CheckField label="Public OIDC client (PKCE, no secret)" {...f.check("publicClient")} />
          <Prose>New clients start <strong>disabled</strong>. Configure the application first, then explicitly enable its client in Applications.</Prose>
          <Row><Button type="submit" variant="primary">Register this hostname</Button></Row>
        </Form>
        {one.view}
      </Subsection>
      <Subsection title="Bulk onboard root and subdomains">
        <Prose>Paste up to 20 reviewed hostnames from <Code>nathan domains discover</Code> or the Cloudflare installer. Every client is created
          disabled and requires explicit activation. The batch uses the client type and callback path above.</Prose>
        <Form onSubmit={registerBatch}>
          <AreaField label="Approved hostnames (one per line)" rows={6} placeholder={"example.com\nwww.example.com\napp.example.com"} {...f.text("hostnames")} />
          <Row><Button type="submit" variant="primary">Register reviewed hostnames</Button></Row>
        </Form>
        {batch.view}
      </Subsection>
      <Subsection title="Registered domain clients">
        <Loaded state={clients}>{(d: any) => (
          <DataTable label="Domain clients" empty="No domain clients yet." rows={d.clients} rowKey={r => r.hostname}
            columns={[{ key: "hostname", label: "Hostname" }, { key: "kind", label: "Type" }, { key: "callbackUri", label: "Callback" },
              { key: "status", label: "Status" }, { key: "clientId", label: "Client ID" }]} />
        )}</Loaded>
        <Row><RefreshButton onClick={() => void clients.reload()} label="List registered domain clients" /></Row>
      </Subsection>
    </Section>
  );
}
