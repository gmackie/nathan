/** NATH-39 Studio: administrators and recovery (bootstrap owner, explicit grants). */
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import { DataTable, Form, Loaded, Panel, Prose, RefreshButton, Row, Section, TextField, useAction, useFields, useLoad, when } from "../kit.tsx";

export function Admins() {
  const admins = useLoad(() => apiGet("/admins"));
  const action = useAction();
  const f = useFields({ email: "", id: "" });
  const grant = () => {
    const email = f.values.email.trim().toLowerCase();
    return action.run(confirm => apiPost("/admins/grant", { email, confirm }),
      { confirm: confirmations.admins.grant(email), message: "Administrator granted", after: () => { void admins.reload(); } });
  };
  const revoke = (id: string) => action.run(confirm => apiPost("/admins/revoke", { id, confirm }),
    { confirm: confirmations.admins.revoke(id), message: "Administrator revoked", after: () => { void admins.reload(); } });
  return (
    <Panel title="Administrators and recovery" description={<Prose>
      The first administrator is bound to the Cloudflare installer's verified email and can never be revoked from this screen. Additional admins
      require an existing email-verified Nathan account, explicit approval, enrolled authenticators, and verification under this installation’s security policy.</Prose>}>
      <Section title="Admin grants">
        <Loaded state={admins}>{(d: any) => (
          <div className="nathan-stack">
            {d.owner ? <Prose>Initial administrator: <strong>{d.owner.email}</strong> ({d.owner.state})</Prose> : <Prose>No initial administrator is recorded.</Prose>}
            <DataTable label="Additional administrators" empty="No additional administrators." rows={d.grants}
              columns={[{ key: "email", label: "Email" }, { key: "id", label: "User ID" },
                { key: "enabled", label: "State", render: r => <Badge variant={r.enabled ? "success" : "neutral"}>{r.enabled ? "Enabled" : "Revoked"}</Badge> },
                { key: "created_at", label: "Granted", render: r => when(r.created_at ?? r.createdAt) },
                { key: "actions", label: "", render: r => r.enabled
                  ? <Button variant="secondary-destructive" size="sm" onClick={() => revoke(String(r.id))}>Revoke</Button> : null }]} />
          </div>
        )}</Loaded>
        <Row><RefreshButton onClick={() => void admins.reload()} /></Row>
      </Section>
      <Section title="Grant administrator">
        <Form onSubmit={grant}>
          <TextField label="Grant admin to verified email" type="email" placeholder="admin@example.com" {...f.text("email")} />
          <Row><Button type="submit" variant="primary">Grant administrator</Button></Row>
        </Form>
      </Section>
      <Section title="Revoke an additional administrator">
        <Form onSubmit={() => revoke(f.values.id.trim())}>
          <TextField label="User ID" placeholder="Better Auth user ID" {...f.text("id")} />
          <Row><Button type="submit" variant="destructive">Revoke administrator and sessions</Button></Row>
        </Form>
      </Section>
      {action.view}
    </Panel>
  );
}
