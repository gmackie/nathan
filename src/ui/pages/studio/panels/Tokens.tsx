/**
 * NATH-39 Studio: token audiences (Gatekeeper and APIs), which clients may use them, each client's
 * principal kind, and machine/agent clients (NATH-15). Writes go to POST /studio/api/v1/tokens.
 */
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import { Code, DataTable, Form, Loaded, Panel, Prose, RefreshButton, Row, Section, SelectField, TextField, useAction, useFields, useLoad } from "../kit.tsx";

const KINDS = { agent: "Agent or MCP client", auto: "Classify by grant (default)" } as const;
const MACHINE = { machine: "Machine (service)", agent: "Agent" } as const;

export function Tokens() {
  const overview = useLoad(() => apiGet("/tokens"));
  const action = useAction();
  const f = useFields({ aud: "", audApp: "", linkClient: "", kindClient: "", kind: "agent" as keyof typeof KINDS, mName: "", mKind: "machine" as keyof typeof MACHINE });
  const aud = () => f.values.aud.trim();
  const op = (body: Record<string, unknown>, confirm?: confirmations.Confirmation) =>
    action.run(phrase => apiPost("/tokens", confirm?.phrase ? { ...body, confirm: phrase } : body), { confirm, after: () => { void overview.reload(); } });
  return (
    <Panel title="Access tokens" description={<Prose>
      Register each API that accepts Nathan access tokens (for example Gatekeeper) as an audience. Tokens for it are JWTs (<Code>typ: at+jwt</Code>)
      valid for at most 900 seconds, with <Code>principal_kind</Code> (user, machine or agent) and, when the audience is bound to an application,
      a <Code>roles</Code> hint. Authoritative roles stay in the directory API. See <Code>docs/gatekeeper.md</Code>.</Prose>}>
      <Section title="Audiences and clients">
        <Loaded state={overview}>{(d: any) => (
          <div className="nathan-stack">
            <DataTable label="Audiences" empty="No audiences registered." rows={d.audiences} rowKey={r => r.identifier}
              columns={[{ key: "identifier", label: "Audience" }, { key: "app", label: "Roles hint app" }, { key: "accessTokenTtl", label: "TTL (s)" },
                { key: "clients", label: "Allowed clients" },
                { key: "disabled", label: "State", render: r => <Badge variant={r.disabled ? "neutral" : "success"}>{r.disabled ? "Disabled" : "Active"}</Badge> },
                { key: "pick", label: "", render: r => <Button size="sm" variant="secondary" onClick={() => f.set("aud", String(r.identifier))}>Select</Button> }]} />
            <DataTable label="Clients" empty="No clients." rows={d.clients}
              columns={[{ key: "name", label: "Name" }, { key: "id", label: "Client ID" }, { key: "grantTypes", label: "Grant types" },
                { key: "principalKind", label: "Principal kind", render: r => r.principalKind ?? "by grant" },
                { key: "disabled", label: "State", render: r => r.disabled ? "Disabled" : "Enabled" }]} />
          </div>
        )}</Loaded>
        <Row><RefreshButton onClick={() => void overview.reload()} label="Show audiences and clients" /></Row>
      </Section>
      <Section title="Audiences">
        <Form onSubmit={() => op({ op: "audience.register", identifier: aud(), app: f.values.audApp.trim() || null })}>
          <TextField label="Audience (exact https URL)" placeholder="https://gatekeeper.example.com/api" {...f.text("aud")} />
          <TextField label="Application for the roles hint (optional)" placeholder="billing" {...f.text("audApp")} />
          <Row>
            <Button type="submit" variant="primary">Register audience</Button>
            <Button type="button" variant="secondary-destructive" onClick={() => op({ op: "audience.remove", identifier: aud() }, confirmations.tokens.audienceRemove(aud()))}>Remove audience</Button>
          </Row>
        </Form>
        <Form onSubmit={() => op({ op: "audience.link", identifier: aud(), clientId: f.values.linkClient.trim() })}>
          <TextField label="Client ID" {...f.text("linkClient")} />
          <Row>
            <Button type="submit" variant="primary">Allow client to request this audience</Button>
            <Button type="button" variant="secondary-destructive" onClick={() => op({ op: "audience.unlink", identifier: aud(), clientId: f.values.linkClient.trim() })}>Disallow</Button>
          </Row>
        </Form>
      </Section>
      <Section title="Principal kind" description={<Prose>
        Mark agents and MCP clients as <strong>agent</strong>. Unmarked clients are classified by grant: a signed-in user is <Code>user</Code>, client
        credentials are <Code>machine</Code>. A client is never a user by attribute.</Prose>}>
        <Form onSubmit={() => {
          const id = f.values.kindClient.trim(), kind = f.values.kind;
          op({ op: "client.kind", clientId: id, kind }, confirmations.tokens.clientKind(id, kind));
        }}>
          <TextField label="Client ID" {...f.text("kindClient")} />
          <SelectField label="Kind" value={f.values.kind} onChange={v => f.set("kind", v)} options={KINDS} />
          <Row><Button type="submit" variant="primary">Set principal kind</Button></Row>
        </Form>
      </Section>
      <Section title="Machine and agent clients" description={<Prose>
        Creates a confidential client-credentials client for the audience above with scope <Code>nathan:api</Code>. Its secret is shown once.</Prose>}>
        <Form onSubmit={() => {
          const name = f.values.mName.trim();
          op({ op: "machine.create", name, kind: f.values.mKind, audience: aud() }, confirmations.tokens.machine(name, aud()));
        }}>
          <TextField label="Client name" placeholder="Billing jobs" {...f.text("mName")} />
          <SelectField label="Kind" value={f.values.mKind} onChange={v => f.set("mKind", v)} options={MACHINE} />
          <Row><Button type="submit" variant="primary">Create client for the audience above</Button></Row>
        </Form>
      </Section>
      {action.view}
    </Panel>
  );
}
