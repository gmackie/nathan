/** NATH-39 Studio: OIDC clients (register, list, disable/re-enable). */
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import { CheckField, DataTable, Form, Loaded, Panel, Prose, RefreshButton, Row, Section, SelectField, TextField, useAction, useFields, useLoad } from "../kit.tsx";

const KINDS = { external: "External web app", worker: "Cloudflare Worker", gateway: "Nathan gateway", mcp: "MCP administrator" } as const;

export function Applications() {
  const clients = useLoad(() => apiGet("/clients"));
  const create = useAction();
  const manage = useAction();
  const f = useFields({ name: "", redirectUri: "", kind: "external" as keyof typeof KINDS, publicClient: false, clientId: "" });
  const register = () => create.run(() => apiPost("/clients", {
    name: f.values.name, redirectUri: f.values.redirectUri, kind: f.values.kind, publicClient: f.values.publicClient
  }), { message: "Client created", after: () => { void clients.reload(); } });
  const setDisabled = (clientId: string, disabled: boolean) => manage.run(() => apiPost("/clients/status", { clientId, disabled }),
    { confirm: confirmations.clients.status(clientId, disabled), message: disabled ? "Client disabled" : "Client re-enabled", after: () => { void clients.reload(); } });
  return (
    <Panel title="Applications" description={<Prose>Workers, external HTTPS apps, and gateway clients can use the same issuer. Roles for each application are managed in Roles and access.</Prose>}>
      <Section title="Register OIDC client" description={<Prose>Client secrets are shown once. Store them in a secure manager.</Prose>}>
        <Form onSubmit={register}>
          <TextField label="Client name" placeholder="My application" {...f.text("name")} />
          <TextField label="Exact HTTPS redirect URI" placeholder="https://app.example.com/oauth/callback" {...f.text("redirectUri")} />
          <SelectField label="Client type" value={f.values.kind} onChange={v => f.set("kind", v)} options={KINDS} />
          <CheckField label="Public OIDC client (PKCE, no secret)" {...f.check("publicClient")} />
          <Row><Button type="submit" variant="primary">Register client</Button></Row>
        </Form>
        {create.view}
      </Section>
      <Section title="Registered applications">
        <Loaded state={clients}>{(d: any) => (
          <DataTable label="Registered OIDC clients" empty="No OIDC clients yet." rows={d.clients}
            columns={[{ key: "name", label: "Name" }, { key: "id", label: "Client ID" }, { key: "redirectUris", label: "Redirect URIs" },
              { key: "authMethod", label: "Auth" },
              { key: "disabled", label: "State", render: r => <Badge variant={r.disabled ? "neutral" : "success"}>{r.disabled ? "Disabled" : "Enabled"}</Badge> },
              { key: "actions", label: "", render: r => r.disabled
                ? <Button size="sm" variant="secondary" onClick={() => setDisabled(String(r.id), false)}>Re-enable</Button>
                : <Button size="sm" variant="secondary-destructive" onClick={() => setDisabled(String(r.id), true)}>Disable</Button> }]} />
        )}</Loaded>
        <Row><RefreshButton onClick={() => void clients.reload()} label="Refresh registered clients" /></Row>
        <Form onSubmit={() => setDisabled(f.values.clientId.trim(), true)}>
          <TextField label="Disable or resume OIDC client by ID" placeholder="OIDC client_id" {...f.text("clientId")} />
          <Row>
            <Button type="submit" variant="secondary-destructive">Disable</Button>
            <Button type="button" variant="secondary" onClick={() => setDisabled(f.values.clientId.trim(), false)}>Re-enable</Button>
          </Row>
        </Form>
        {manage.view}
      </Section>
    </Panel>
  );
}
