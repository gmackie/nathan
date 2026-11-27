/** NATH-39 Studio: remote MCP servers protected by Nathan and their connections (NATH-14). */
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import { AreaField, Code, DataTable, Form, Loaded, Panel, Prose, RefreshButton, Row, Section, TextField, useAction, useFields, useLoad, when } from "../kit.tsx";

export function Mcp() {
  const overview = useLoad(() => apiGet("/mcp"));
  const action = useAction();
  const f = useFields({ id: "", app: "", name: "", full: "", catalog: "", grant: "" });
  const id = () => f.values.id.trim();
  const op = (body: Record<string, unknown>, confirm?: confirmations.Confirmation) =>
    action.run(phrase => apiPost("/mcp", confirm?.phrase ? { ...body, confirm: phrase } : body), { confirm, after: () => { void overview.reload(); } });
  const register = () => {
    let extra: any = {};
    try { extra = f.values.catalog.trim() ? JSON.parse(f.values.catalog) : {}; }
    catch { return action.run(async () => { throw Error("Catalog JSON is invalid"); }); }
    return op({ op: "resource.register", identifier: id(), app: f.values.app.trim(), name: f.values.name.trim(), full: f.values.full.trim() || null,
      aliases: extra.aliases || {}, scopes: extra.scopes || {} });
  };
  return (
    <Panel title="Remote MCP servers" description={<Prose>
      Protect any Worker as a remote MCP server with Nathan as its authorization server. The server is an application; its permissions are the MCP
      scopes users tick on the consent page, and a client never gets more than the user's current permissions. Mark scopes that must be ticked on
      their own as <strong>sensitive</strong>. See <Code>docs/remote-mcp.md</Code>.</Prose>}>
      <Section title="MCP servers and connections">
        <Loaded state={overview}>{(d: any) => (
          <div className="nathan-stack">
            <DataTable label="MCP servers" empty="No MCP servers registered." rows={d.resources} rowKey={r => r.identifier}
              columns={[{ key: "identifier", label: "Resource" }, { key: "name", label: "Name" }, { key: "app", label: "Application" },
                { key: "scopes", label: "Scopes", render: r => (r.scopes ?? []).map((s: any) => s.scope + (s.sensitive ? " (sensitive)" : "")).join(", ") },
                { key: "enabled", label: "State", render: r => <Badge variant={r.enabled ? "success" : "neutral"}>{r.enabled ? "Enabled" : "Disabled"}</Badge> },
                { key: "pick", label: "", render: r => <Button size="sm" variant="secondary" onClick={() => f.set("id", String(r.identifier))}>Select</Button> }]} />
            <DataTable label="Connections" empty="No active connections." rows={d.grants}
              columns={[{ key: "clientName", label: "Client" }, { key: "email", label: "User" }, { key: "resource", label: "Resource" }, { key: "scope", label: "Scopes" },
                { key: "expiresAt", label: "Expires", render: r => when(r.expiresAt) },
                { key: "actions", label: "", render: r => <Button size="sm" variant="secondary-destructive"
                  onClick={() => op({ op: "grant.revoke", grantId: String(r.id) }, confirmations.mcp.revoke(String(r.id)))}>Revoke</Button> }]} />
          </div>
        )}</Loaded>
        <Row><RefreshButton onClick={() => void overview.reload()} label="Show MCP servers and connections" /></Row>
      </Section>
      <Section title="Register or update an MCP server">
        <Form onSubmit={register}>
          <TextField label="Resource (exact https URL of the MCP endpoint)" placeholder="https://notes.example.com/mcp" {...f.text("id")} />
          <TextField label="Application" placeholder="notes" {...f.text("app")} />
          <TextField label="Name shown on the consent page" placeholder="Notes" {...f.text("name")} />
          <TextField label="Full access marker (optional)" placeholder="notes:full" {...f.text("full")} />
          <AreaField label="Aliases and scope metadata (JSON)" rows={7} {...f.text("catalog")}
            placeholder={'{"aliases":{"notes:basic":["notes:read","notes:write"]},"scopes":{"notes:write":{"label":"Write notes","description":"Create and edit notes.","requires":["notes:read"]},"notes:export":{"label":"Export","description":"Download all notes.","sensitive":true}}}'} />
          <Row>
            <Button type="submit" variant="primary">Register or update MCP server</Button>
            <Button type="button" variant="secondary-destructive" onClick={() => op({ op: "resource.status", identifier: id(), enabled: false }, confirmations.mcp.disable(id()))}>Disable</Button>
            <Button type="button" variant="secondary" onClick={() => op({ op: "resource.status", identifier: id(), enabled: true }, confirmations.mcp.enable(id()))}>Enable</Button>
            <Button type="button" variant="destructive" onClick={() => op({ op: "resource.remove", identifier: id() }, confirmations.mcp.remove(id()))}>Remove</Button>
          </Row>
        </Form>
      </Section>
      <Section title="Revoke a connection">
        <Form onSubmit={() => { const g = f.values.grant.trim(); op({ op: "grant.revoke", grantId: g }, confirmations.mcp.revoke(g)); }}>
          <TextField label="Connection (grant) id" {...f.text("grant")} />
          <Row><Button type="submit" variant="secondary-destructive">Revoke connection</Button></Row>
        </Form>
      </Section>
      {action.view}
    </Panel>
  );
}
