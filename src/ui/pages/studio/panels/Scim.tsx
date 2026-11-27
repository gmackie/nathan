/**
 * NATH-39 Studio: SCIM directory connections and their lifecycle (NATH-11): linking and
 * just-in-time toggles, group mappings, administrator reviews, keep active / unlink, and the
 * reconciliation outbox. Writes need admin + fresh step-up + same-origin + exact confirmation and
 * are audited on the server. Bearer tokens are shown once.
 */
import { useState } from "react";
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import {
  CheckField, Code, DataTable, ErrorBanner, Form, JsonView, Loaded, Panel, Prose, RefreshButton, Row, Section, SelectField, Subsection, TextField,
  useAction, useFields, useLoad, when
} from "../kit.tsx";

export function Scim() {
  const [manage, setManage] = useState("");
  return (
    <Panel title="SCIM directory connections" description={<Prose>
      Nathan can receive SCIM 2.0 directory Users/Groups into a transactional, per-connection Durable Object. New connections
      are <strong>directory-only</strong>: they create no login accounts, revoke nothing and grant no roles until you turn on linking below (NATH-11).
      Directory records never grant application access by themselves.</Prose>}>
      <Connections onManage={setManage} />
      {manage ? <Lifecycle key={manage} id={manage} /> : <Section title="Directory lifecycle"><Prose>Choose Manage on a connection to see its lifecycle.</Prose></Section>}
    </Panel>
  );
}

function Connections({ onManage }: { onManage: (id: string) => void }) {
  const list = useLoad(() => apiGet("/scim/connections"));
  const action = useAction();
  const f = useFields({ id: "", domain: "", org: "" });
  const after = () => { void list.reload(); };
  const create = () => action.run(() => apiPost("/scim/connections", {
    id: f.values.id, domain: f.values.domain, ...(f.values.org ? { organizationId: f.values.org } : {})
  }), { confirm: confirmations.scim.create(), message: "Connection created (disabled)", secret: true, after: r => { after(); if (r?.id) onManage(String(r.id)); } });
  const manageConnection = (id: string, what: "enable" | "disable" | "rotate") => action.run(
    confirm => apiPost(what === "rotate" ? "/scim/rotate" : "/scim/status", { id, ...(what === "rotate" ? {} : { enabled: what === "enable" }), confirm }),
    { confirm: confirmations.scim.manage(id, what), message: "SCIM connection " + what + " succeeded", secret: what === "rotate", after });
  return (
    <>
      <Section title="Create a connection" description={<Prose>The bearer token appears exactly once after creation or rotation. Copy it to a secrets manager and to your directory provider.</Prose>}>
        <Form onSubmit={create}>
          <TextField label="Connection ID" placeholder="acme-workforce" {...f.text("id")} />
          <TextField label="Directory email domain" placeholder="acme.example" {...f.text("domain")} />
          <TextField label="Organization ID (optional)" placeholder="org_..." {...f.text("org")} />
          <Row><Button type="submit" variant="primary">Create directory connection</Button></Row>
        </Form>
      </Section>
      <Section title="Connections">
        <Loaded state={list}>{(d: any) => (
          <DataTable label="SCIM connections" empty="No SCIM connections." rows={d.connections}
            columns={[{ key: "id", label: "ID" }, { key: "domain", label: "Domain" }, { key: "lifecycle", label: "Lifecycle" },
              { key: "baseUrl", label: "Base URL", render: r => <Code>{r.baseUrl}</Code> },
              { key: "enabled", label: "State", render: r => <Badge variant={r.enabled ? "success" : "neutral"}>{r.enabled ? "Enabled" : "Disabled"}</Badge> },
              { key: "lastSyncAt", label: "Last sync", render: r => when(r.lastSyncAt) },
              { key: "actions", label: "", render: r => (
                <Row>
                  <Button size="sm" variant="secondary" onClick={() => onManage(String(r.id))}>Manage</Button>
                  {r.enabled
                    ? <Button size="sm" variant="secondary-destructive" onClick={() => manageConnection(String(r.id), "disable")}>Disable</Button>
                    : <Button size="sm" variant="secondary" onClick={() => manageConnection(String(r.id), "enable")}>Enable</Button>}
                  <Button size="sm" variant="secondary-destructive" onClick={() => manageConnection(String(r.id), "rotate")}>Rotate token</Button>
                </Row>
              ) }]} />
        )}</Loaded>
        <Row><RefreshButton onClick={after} label="Refresh connections" /></Row>
        {action.view}
      </Section>
    </>
  );
}

const REVIEW_FILTERS = {
  "": "Open first (pending, then approved), oldest first", pending: "Pending only", approved: "Approved, not yet applied",
  applied: "Applied", dismissed: "Dismissed", superseded: "Superseded"
} as const;

function Lifecycle({ id }: { id: string }) {
  const [filter, setFilter] = useState<keyof typeof REVIEW_FILTERS>("");
  const [offset, setOffset] = useState("0");
  const view = useLoad(() => apiGet("/scim/connection", { id, reviewState: filter, reviewOffset: offset || "0" }), [id, filter, offset]);
  const outbox = useLoad(() => apiGet("/scim/outbox", { id }), [id], false);
  const action = useAction();
  const v: any = view.data;
  const f = useFields({ linking: false, jit: false, refType: "externalId" as "externalId" | "id", ref: "", group: "" });
  const [synced, setSynced] = useState(false);
  if (v && !synced) { setSynced(true); f.setValues(x => ({ ...x, linking: Boolean(v.connection.linking), jit: Boolean(v.connection.jit) })); }
  const after = () => { void view.reload(); };
  const page = v?.reviewPage;
  const head = outbox.data?.head?.[0];
  return (
    <Section title={"Directory lifecycle: " + id} description={<>
      <Prose>With linking on, a directory user is linked to an existing Nathan account only when its email is in the connection's <strong>verified</strong> domain
        and the Nathan account's email is verified. Deactivating or deleting a linked user in the directory blocks the account, ends every Nathan session,
        revokes its tokens and sends back-channel logout; Nathan gateways deny it within 60 seconds. Reactivation unblocks the account but does not restore
        sessions. Just-in-time creation (off by default) creates an unverified account for directory users without one.</Prose>
      <Prose><strong>Administrators are never linked or deprovisioned by the directory alone.</strong> A directory change that would link or block a Nathan
        administrator (admin role, admin grant, the bootstrap owner, or an address in NATHAN_ADMIN_EMAILS), or re-link an account that was deleted, waits
        under Administrator reviews below. The last administrator is never deprovisioned by SCIM.</Prose>
    </>}>
      <Loaded state={view}>{(d: any) => (
        <Prose>{d.connection.domain} · domain {d.connection.domainVerified ? "verified" : "not verified"} · last sync {when(d.connection.lastSyncAt)} · last error {when(d.connection.lastErrorAt)}</Prose>
      )}</Loaded>
      <Subsection title="Lifecycle settings">
        <Form onSubmit={() => action.run(confirm => apiPost("/scim/settings", { id, linking: f.values.linking, jit: f.values.jit, confirm }),
          { confirm: confirmations.scim.settings(id, f.values.linking, f.values.jit), after })}>
          <CheckField label="Link directory users to Nathan accounts (verified domain and email only)" {...f.check("linking")} />
          <CheckField label="Create accounts just in time for directory users without one" {...f.check("jit")} />
          <Row><Button type="submit" variant="primary">Save lifecycle settings</Button></Row>
        </Form>
      </Subsection>
      <Subsection title="Group mapping">
        <Prose>A mapped Nathan group's membership is maintained by the directory. Mapping grants nothing by itself: give the group roles in Roles and access. Only empty Identity Studio groups can be mapped.</Prose>
        {v ? <DataTable label="Group mappings" empty="No mappings." rows={v.mappings} rowKey={(r, i) => String(r.group ?? r.groupId ?? i)}
          columns={[{ key: "group", label: "Nathan group", render: r => r.group ?? r.groupId }, { key: "refType", label: "Reference" }, { key: "ref", label: "Value" }]} /> : null}
        <Form onSubmit={() => {
          const ref = f.values.ref.trim(), group = f.values.group.trim();
          action.run(confirm => apiPost("/scim/mappings", { op: "map", connection: id, refType: f.values.refType, ref, group, confirm }), { confirm: confirmations.scim.map(id, ref, group), after });
        }}>
          <SelectField label="SCIM group reference" value={f.values.refType} onChange={x => f.set("refType", x)}
            options={{ externalId: "externalId (Entra object ID, Okta group ID)", id: "Nathan SCIM id" }} />
          <TextField label="Reference value" {...f.text("ref")} />
          <TextField label="Nathan group ID" placeholder="engineering" {...f.text("group")} />
          <Row>
            <Button type="submit" variant="primary">Map group</Button>
            <Button type="button" variant="secondary-destructive" onClick={() => {
              const group = f.values.group.trim();
              action.run(confirm => apiPost("/scim/mappings", { op: "unmap", connection: id, group, confirm }), { confirm: confirmations.scim.unmap(group), after });
            }}>Remove mapping and its memberships</Button>
          </Row>
        </Form>
      </Subsection>
      <Subsection title="Administrator reviews">
        <Prose>Approving applies the directory's change once; dismissing keeps the account as it is until the directory sends a new change. Open reviews are
          listed first, oldest first, 100 at a time, with the count of each state; a connection opens at most 50 reviews an hour, so a flood from the
          directory cannot bury a real one.</Prose>
        <SelectField label="Show reviews" value={filter} onChange={setFilter} options={REVIEW_FILTERS} />
        <TextField label="Starting at item" type="number" min={0} step={100} value={offset} onChange={setOffset} />
        {v && page ? <p className="nathan-text" role="status">Reviews: {Object.entries(v.reviewCounts).map(([k, n]) => n + " " + k).join(", ") || "none"}.
          Showing {page.total ? page.offset + 1 : 0}–{Math.min(page.offset + page.limit, page.total)} of {page.total}.</p> : null}
        {v ? <DataTable label="Administrator reviews" empty="No reviews in this view." rows={v.reviews}
          columns={[{ key: "action", label: "Change" }, { key: "email", label: "Administrator" }, { key: "userName", label: "Directory user" },
            { key: "state", label: "State" }, { key: "createdAt", label: "Opened", render: r => when(r.createdAt) },
            { key: "actions", label: "", render: r => r.state === "pending" ? (
              <Row>
                <Button size="sm" variant={r.action === "link" ? "primary" : "destructive"} onClick={() => action.run(confirm => apiPost("/scim/users",
                  { op: "approve", connection: id, review: r.id, confirm }), { confirm: confirmations.scim.approve(r), after })}>Approve</Button>
                <Button size="sm" variant="secondary" onClick={() => action.run(confirm => apiPost("/scim/users",
                  { op: "dismiss", connection: id, review: r.id, confirm }), { confirm: confirmations.scim.dismiss(r), after })}>Dismiss</Button>
              </Row>) : null }]} /> : null}
      </Subsection>
      <Subsection title="Directory users">
        <Prose>Keep active unblocks a user the directory deprovisioned; Nathan keeps that decision through replays and resyncs until the directory sends a new
          deactivation or deletion. Unlink detaches the directory user from its Nathan account for good.</Prose>
        {v ? <DataTable label="Directory users" empty="No directory users." rows={v.users} rowKey={r => String(r.scimId)}
          columns={[{ key: "userName", label: "Directory user" }, { key: "email", label: "Email" }, { key: "scimId", label: "SCIM id" },
            { key: "active", label: "Directory state", render: r => r.deleted ? "Deleted" : r.active ? "Active" : "Inactive" },
            { key: "userId", label: "Linked", render: r => r.userId ? "Yes" : "No" },
            { key: "actions", label: "", render: r => r.userId ? (
              <Row>
                <Button size="sm" variant="secondary" onClick={() => action.run(confirm => apiPost("/scim/users",
                  { op: "keep-active", connection: id, scimId: r.scimId, confirm }), { confirm: confirmations.scim.keepActive(r), after })}>Keep active</Button>
                <Button size="sm" variant="secondary-destructive" onClick={() => action.run(confirm => apiPost("/scim/users",
                  { op: "unlink", connection: id, scimId: r.scimId, confirm }), { confirm: confirmations.scim.unlink(r), after })}>Unlink</Button>
              </Row>) : null }]} /> : null}
        {v?.errors?.length ? <Subsection title="Recent errors"><JsonView value={v.errors} label="Errors" /></Subsection> : null}
      </Subsection>
      <Subsection title="Reconciliation outbox">
        <Prose>Directory changes are applied to Nathan in order. If one can never be applied, the connection answers 503 to every later change. Review the
          head entry here and skip it only if you will handle that change by hand.</Prose>
        <Row>
          <Button variant="secondary" onClick={() => void outbox.reload()}>Show outbox head</Button>
          <Button variant="secondary-destructive" disabled={!head} onClick={() => action.run(confirm => apiPost("/scim/outbox",
            { op: "skip", connection: id, kind: head.kind, id: head.resourceId, seq: head.seq, confirm }),
            { confirm: confirmations.scim.skip(head), after: () => { void outbox.reload(); } })}>Skip the failing head entry</Button>
        </Row>
        {outbox.error ? <ErrorBanner error={outbox.error} /> : <JsonView value={outbox.data} label="Outbox head" />}
      </Subsection>
      {action.view}
    </Section>
  );
}
