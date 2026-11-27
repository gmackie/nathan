/** NATH-39 Studio: the read-only user directory, account admission and invitations (NATH-16), and the audit log. */
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import { DataTable, Form, Loaded, Panel, Prose, RefreshButton, Row, Section, SelectField, TextField, useAction, useFields, useLoad, when } from "../kit.tsx";

export function Users() {
  const users = useLoad(() => apiGet("/users"));
  return (
    <Panel title="Users" description={<Prose>Read-only directory of recent accounts. Passwords, credentials and session values are never returned.
      Give people access to applications under Roles and access.</Prose>}>
      <Section title="Recent accounts">
        <Loaded state={users}>{(d: any) => (
          <DataTable label="Users" empty="No accounts yet." rows={d.users}
            columns={[{ key: "email", label: "Email" }, { key: "name", label: "Name" },
              { key: "emailVerified", label: "Verified", render: r => r.emailVerified ? "Yes" : "No" },
              { key: "role", label: "Role" },
              { key: "banned", label: "State", render: r => <Badge variant={r.banned ? "error" : "success"}>{r.banned ? "Blocked" : "Active"}</Badge> },
              { key: "createdAt", label: "Created", render: r => when(r.createdAt) }, { key: "id", label: "User ID" }]} />
        )}</Loaded>
        <Row><RefreshButton onClick={() => void users.reload()} label="Refresh users" /></Row>
      </Section>
    </Panel>
  );
}

const MODES = { "invitation-only": "Invitation-only (recommended)", "self-service": "Self-service" } as const;

export function Admission({ onNoticeChange }: { onNoticeChange?: () => void }) {
  const view = useLoad(() => apiGet("/admission"));
  const action = useAction();
  const f = useFields({ mode: "invitation-only" as keyof typeof MODES, email: "", days: "7", revokeId: "", reissue: "" });
  const op = (body: Record<string, unknown>, confirm?: confirmations.Confirmation) =>
    action.run(phrase => apiPost("/admission", confirm?.phrase ? { ...body, confirm: phrase } : body),
      { confirm, after: () => { void view.reload(); onNoticeChange?.(); } });
  return (
    <Panel title="Account admission and invitations" description={<Prose>
      Decides who may <strong>create</strong> a Nathan account, by any sign-in method: password, social providers, enterprise SSO (SAML and OIDC)
      and SCIM just-in-time provisioning. <strong>Invitation-only</strong> (the default) creates an account only for an email address with an open
      invitation, and only when the sign-in method proved that address: a provider-verified email, or an address inside the verified domain of the
      SAML, OIDC or SCIM connection. A password sign-up uses the invitation only once its address is verified, and cannot sign in before that.
      <strong> Self-service</strong> lets anyone who can sign in create one. Admission grants no application access and no administrator rights.
      The installer's first administrator is always admitted.</Prose>}>
      <Section title="Admission mode">
        <Loaded state={view}>{(d: any) => (
          <div className="nathan-stack">
            {d.upgradeNotice ? (
              <div className="nathan-stack" role="status">
                <Prose>{d.upgradeNotice}</Prose>
                <Row><Button size="sm" variant="secondary" onClick={() => op({ op: "dismiss-upgrade-notice" })}>Dismiss</Button></Row>
              </div>
            ) : null}
            <Prose>Current mode: <strong>{d.mode}</strong>{d.updatedAt ? " (changed " + when(d.updatedAt) + ")" : ""}</Prose>
          </div>
        )}</Loaded>
        <Form onSubmit={() => op({ op: "mode", mode: f.values.mode }, confirmations.admission.mode(f.values.mode))}>
          <SelectField id="adm-mode" label="Admission mode" value={f.values.mode} onChange={v => f.set("mode", v)} options={MODES} />
          <Row><Button type="submit" variant="primary">Change admission mode</Button></Row>
        </Form>
      </Section>
      <Section title="Invite someone" description={<Prose>
        The invitation is bound to this exact email address, works once and expires. The person signs in with any enabled method using that address;
        a provider that does not verify the address cannot use it.</Prose>}>
        <Form onSubmit={() => op({ op: "invite", email: f.values.email.trim(), days: Number(f.values.days) })}>
          <TextField label="Email address" type="email" placeholder="new.person@example.com" {...f.text("email")} />
          <TextField label="Valid for (days, 1 to 30)" type="number" min={1} max={30} {...f.text("days")} />
          <Row><Button type="submit" variant="primary">Create invitation</Button></Row>
        </Form>
        <Loaded state={view}>{(d: any) => (
          <DataTable label="Invitations" empty="No invitations." rows={d.invitations}
            columns={[{ key: "email", label: "Email" }, { key: "state", label: "State" }, { key: "createdBy", label: "Created by" },
              { key: "expiresAt", label: "Expires", render: r => when(r.expiresAt) }, { key: "usedAt", label: "Used", render: r => when(r.usedAt) },
              { key: "actions", label: "", render: r => r.state === "pending"
                ? <Button size="sm" variant="secondary-destructive" onClick={() => op({ op: "revoke", id: String(r.id) }, confirmations.admission.revoke(String(r.id)))}>Revoke</Button> : null }]} />
        )}</Loaded>
        <Form onSubmit={() => { const id = f.values.revokeId.trim(); op({ op: "revoke", id }, confirmations.admission.revoke(id)); }}>
          <TextField label="Invitation ID to revoke" {...f.text("revokeId")} />
          <Row><Button type="submit" variant="secondary-destructive">Revoke invitation</Button></Row>
        </Form>
      </Section>
      <Section title="Reissue an invitation" description={<Prose>
        If someone created an unverified account for an address (for example a password sign-up they cannot verify), the real person cannot get that
        address. Reissuing removes that unverified account (only if it has no current session, no passkey and no social or SSO login, is not an
        administrator and is not managed by a directory) and invites the address again. Audited. A real invitee who signs in with a social provider
        that verifies the address replaces such an account automatically.</Prose>}>
        <Form onSubmit={() => { const email = f.values.reissue.trim().toLowerCase(); op({ op: "reissue", email }, confirmations.admission.reissue(email)); }}>
          <TextField label="Email address to reissue" type="email" {...f.text("reissue")} />
          <Row><Button type="submit" variant="secondary-destructive">Remove unverified account and reissue invitation</Button></Row>
        </Form>
      </Section>
      {action.view}
    </Panel>
  );
}

const outcomeVariant = (o: string) =>
  /^(succeeded|applied)$/.test(o) ? "success" : /^(failed|refused|denied|rejected)$/.test(o) ? "error" : "neutral";

export function Audit() {
  const audit = useLoad(() => apiGet("/audit"));
  return (
    <Panel title="Security audit" description={<Prose>The latest 75 privileged operations, newest first. Every Studio write is recorded with its outcome.</Prose>}>
      <Section title="Recent events">
        <Loaded state={audit}>{(d: any) => (
          <DataTable label="Audit events" empty="No audit events." rows={d.events}
            columns={[{ key: "created_at", label: "When", render: r => when(r.created_at) }, { key: "action", label: "Action" },
              { key: "outcome", label: "Outcome", render: r => <Badge variant={outcomeVariant(String(r.outcome))}>{String(r.outcome)}</Badge> },
              { key: "target", label: "Target" }, { key: "actor", label: "Actor" }]} />
        )}</Loaded>
        <Row><RefreshButton onClick={() => void audit.reload()} label="Refresh security audit" /></Row>
      </Section>
    </Panel>
  );
}
