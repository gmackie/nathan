/**
 * NATH-39 Studio: roles and access per application (NATH-13). Every write goes to POST
 * /studio/api/v1/rbac (admin + step-up + same-origin + audit on the server).
 */
import { useState } from "react";
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import {
  AreaField, CheckField, Code, DataTable, Form, Loaded, Panel, Prose, RefreshButton, Row, Section, SelectField, Subsection, TextField,
  useAction, useFields, useLoad, when
} from "../kit.tsx";

const MODES = { approved: "Approved users and groups only (default)", any_signed_in: "Any signed-in user" } as const;
const PRINCIPALS = { user: "User (exact email)", group: "Group (ID)" } as const;

export function Roles() {
  const [app, setApp] = useState("");
  const [loaded, setLoaded] = useState("");
  const overview = useLoad(() => apiGet("/rbac", { app: loaded }), [loaded], loaded !== "");
  const action = useAction();
  const f = useFields({
    mode: "approved" as keyof typeof MODES, permKey: "", permDesc: "", roleKey: "", roleDesc: "", rolePerms: "",
    grantRole: "", grantType: "user" as keyof typeof PRINCIPALS, grantWho: "", revokeId: "", manifest: "", prune: false
  });
  const a = loaded;
  const op = (body: Record<string, unknown>, confirm?: confirmations.Confirmation) =>
    action.run(phrase => apiPost("/rbac", confirm?.phrase ? { ...body, confirm: phrase } : body), { confirm, after: () => { if (a) void overview.reload(); } });
  const load = () => setLoaded(app.trim());
  const d: any = overview.data;
  const mode = () => f.values.mode === "any_signed_in"
    ? op({ op: "access_mode", app: a, accessMode: f.values.mode }, confirmations.rbac.anySignedIn(a))
    : op({ op: "access_mode", app: a, accessMode: f.values.mode });
  const manifest = () => JSON.parse(f.values.manifest || "{}");
  const preview = () => action.run(() => apiPost("/rbac", { op: "sync", app: a, manifest: manifest(), prune: f.values.prune, dryRun: true }), { message: "Preview (nothing changed)" });
  const apply = () => {
    let m: any;
    try { m = manifest(); } catch { return action.run(async () => { throw Error("The manifest is not valid JSON"); }); }
    const c = confirmations.rbac.sync(a, f.values.prune, m.accessMode === "any_signed_in");
    return action.run(() => apiPost("/rbac", { op: "sync", app: a, manifest: m, prune: f.values.prune, confirmPrune: c.confirmPrune, confirm: c.phrase }),
      { confirm: { ...c, phrase: undefined }, after: () => { void overview.reload(); } });
  };
  return (
    <Panel title="Roles and access" description={<Prose>
      Each application declares permission strings (like <Code>invoices:write</Code>), roles bundle permissions, and roles are granted to users or
      groups. Nobody gets in by default. Blocked users and disabled applications are always denied. Nathan gateways apply changes within 60
      seconds. Conditions and approvals belong in Gatekeeper, which reads these roles from Nathan.</Prose>}>
      <Section title="Application">
        <Form onSubmit={load}>
          <TextField label="Application ID" placeholder="billing" value={app} onChange={setApp} />
          <Row><Button type="submit" variant="primary">Load roles and grants</Button></Row>
        </Form>
        {a ? <Loaded state={overview}>{(o: any) => (
          <div className="nathan-stack">
            <Prose><strong>{o.app.id}</strong> · {o.app.hostname} · <Badge variant={o.app.enabled ? "success" : "neutral"}>{o.app.enabled ? "Enabled" : "Disabled"}</Badge> · access mode <Code>{o.app.accessMode}</Code></Prose>
            <DataTable label="Permissions" empty="No permissions declared." rows={o.permissions} rowKey={r => r.key}
              columns={[{ key: "key", label: "Permission" }, { key: "description", label: "Description" }, { key: "source", label: "Source" }]} />
            <DataTable label="Roles" empty="No roles yet." rows={o.roles} rowKey={r => r.key}
              columns={[{ key: "key", label: "Role" }, { key: "description", label: "Description" }, { key: "permissions", label: "Permissions" }, { key: "source", label: "Source" }]} />
            <DataTable label="Grants" empty="No grants: nobody has a role in this application." rows={o.grants}
              columns={[{ key: "role", label: "Role" }, { key: "principalType", label: "To" }, { key: "label", label: "Who", render: r => r.label ?? r.principalId },
                { key: "createdAt", label: "Granted", render: r => when(r.createdAt) },
                { key: "actions", label: "", render: r => <Button size="sm" variant="secondary-destructive"
                  onClick={() => op({ op: "grant.revoke", id: String(r.id) }, confirmations.rbac.revoke())}>Revoke</Button> }]} />
          </div>
        )}</Loaded> : <Prose>Load an application to see and change its roles.</Prose>}
      </Section>
      {a ? (
        <>
          <Section title="Who can sign in">
            <Form onSubmit={mode}>
              <SelectField label="Access mode" value={f.values.mode} onChange={v => f.set("mode", v)} options={MODES} />
              <Row><Button type="submit" variant="primary">Save access mode</Button></Row>
            </Form>
          </Section>
          <Section title="Permissions">
            <Form onSubmit={() => op({ op: "permission.upsert", app: a, key: f.values.permKey.trim(), description: f.values.permDesc })}>
              <TextField label="Permission key" placeholder="invoices:write" {...f.text("permKey")} />
              <TextField label="Description" placeholder="Create and edit invoices" {...f.text("permDesc")} />
              <Row>
                <Button type="submit" variant="primary">Save permission</Button>
                <Button type="button" variant="secondary-destructive"
                  onClick={() => op({ op: "permission.delete", app: a, key: f.values.permKey.trim() }, confirmations.rbac.permissionDelete())}>Delete permission</Button>
              </Row>
            </Form>
          </Section>
          <Section title="Roles">
            <Form onSubmit={() => op({ op: "role.upsert", app: a, key: f.values.roleKey.trim(), description: f.values.roleDesc,
              permissions: f.values.rolePerms.split(",").map(x => x.trim()).filter(Boolean) })}>
              <TextField label="Role key" placeholder="editor" {...f.text("roleKey")} />
              <TextField label="Description" placeholder="Edit invoices" {...f.text("roleDesc")} />
              <TextField label="Permissions (comma-separated)" placeholder="invoices:read,invoices:write" {...f.text("rolePerms")} />
              <Row>
                <Button type="submit" variant="primary">Save role</Button>
                <Button type="button" variant="secondary-destructive" onClick={() => {
                  const key = f.values.roleKey.trim();
                  op({ op: "role.delete", app: a, key }, confirmations.rbac.roleDelete(a, key));
                }}>Delete role and its grants</Button>
              </Row>
            </Form>
          </Section>
          <Section title="Grants">
            <Form onSubmit={() => {
              const type = f.values.grantType, who = f.values.grantWho.trim(), role = f.values.grantRole.trim();
              op({ op: "grant.create", app: a, role, principalType: type, ...(type === "user" ? { email: who } : { group: who }) }, confirmations.rbac.grant(a, role, who));
            }}>
              <TextField label="Role" placeholder="editor" {...f.text("grantRole")} />
              <SelectField label="Grant to" value={f.values.grantType} onChange={v => f.set("grantType", v)} options={PRINCIPALS} />
              <TextField label="User email or group ID" placeholder="person@example.com or finance" {...f.text("grantWho")} />
              <Row><Button type="submit" variant="primary">Grant role</Button></Row>
            </Form>
            <Form onSubmit={() => op({ op: "grant.revoke", id: f.values.revokeId.trim() }, confirmations.rbac.revoke())}>
              <TextField label="Grant ID to revoke" placeholder="from the grants list" {...f.text("revokeId")} />
              <Row><Button type="submit" variant="secondary-destructive">Revoke grant</Button></Row>
            </Form>
          </Section>
          <Section title="Permissions and roles as code" description={<Prose>
            Paste the <Code>rbac</Code> object from <Code>nathan.config.json</Code>, or run <Code>nathan rbac sync &lt;app&gt; --apply</Code>. Grants are never part of code.</Prose>}>
            <AreaField label="Manifest (JSON)" rows={8} placeholder={'{"permissions":{"invoices:read":"Read invoices"},"roles":{"viewer":{"permissions":["invoices:read"]}}}'} {...f.text("manifest")} />
            <CheckField label="Delete code-managed roles and permissions that are no longer declared" {...f.check("prune")} />
            <Row>
              <Button variant="secondary" onClick={() => { try { manifest(); void preview(); } catch { void action.run(async () => { throw Error("The manifest is not valid JSON"); }); } }}>Preview changes</Button>
              <Button variant="primary" onClick={() => void apply()}>Apply</Button>
            </Row>
          </Section>
        </>
      ) : null}
      {action.view}
      <Groups />
      <DirectoryClient />
    </Panel>
  );
}

function Groups() {
  const groups = useLoad(() => apiGet("/rbac/groups"));
  const [selected, setSelected] = useState("");
  const members = useLoad(() => apiGet("/rbac/group", { id: selected }), [selected], selected !== "");
  const action = useAction();
  const f = useFields({ id: "", name: "", email: "" });
  const after = () => { void groups.reload(); if (selected) void members.reload(); };
  const op = (body: Record<string, unknown>, confirm?: confirmations.Confirmation) =>
    action.run(phrase => apiPost("/rbac", confirm?.phrase ? { ...body, confirm: phrase } : body), { confirm, after });
  const id = () => f.values.id.trim();
  return (
    <Section title="Groups">
      <Loaded state={groups}>{(d: any) => (
        <DataTable label="Groups" empty="No groups yet." rows={d.groups}
          columns={[{ key: "id", label: "ID" }, { key: "name", label: "Name" }, { key: "source", label: "Source" }, { key: "members", label: "Members" },
            { key: "actions", label: "", render: r => <Button size="sm" variant="secondary" onClick={() => { setSelected(String(r.id)); f.set("id", String(r.id)); }}>Show members</Button> }]} />
      )}</Loaded>
      <Row><RefreshButton onClick={() => void groups.reload()} label="List groups" /></Row>
      <Form onSubmit={() => op({ op: "group.upsert", id: id(), name: f.values.name })}>
        <TextField label="Group ID" placeholder="finance" {...f.text("id")} />
        <TextField label="Group name" placeholder="Finance team" {...f.text("name")} />
        <Row>
          <Button type="submit" variant="primary">Save group</Button>
          <Button type="button" variant="secondary-destructive" onClick={() => op({ op: "group.delete", id: id() }, confirmations.rbac.groupDelete(id()))}>Delete group</Button>
          <Button type="button" variant="secondary" onClick={() => setSelected(id())}>Show members</Button>
        </Row>
      </Form>
      <Form onSubmit={() => op({ op: "member.add", group: id(), email: f.values.email.trim() })}>
        <TextField label="Member email" type="email" placeholder="person@example.com" {...f.text("email")} />
        <Row>
          <Button type="submit" variant="primary">Add member</Button>
          <Button type="button" variant="secondary-destructive" onClick={() => op({ op: "member.remove", group: id(), email: f.values.email.trim() }, confirmations.rbac.memberRemove())}>Remove member</Button>
        </Row>
      </Form>
      {selected ? (
        <Subsection title={"Members of " + selected}>
          <Loaded state={members}>{(m: any) => (
            <DataTable label="Group members" empty="No members." rows={m.members} rowKey={r => r.userId}
              columns={[{ key: "email", label: "Email" }, { key: "userId", label: "User ID" }, { key: "addedBy", label: "Added by" },
                { key: "createdAt", label: "Added", render: r => when(r.createdAt) }]} />
          )}</Loaded>
        </Subsection>
      ) : null}
      {action.view}
    </Section>
  );
}

function DirectoryClient() {
  const action = useAction();
  const [name, setName] = useState("");
  const create = () => {
    const n = name.trim();
    return action.run(confirm => apiPost("/directory/clients", { name: n, confirm }), { confirm: confirmations.rbac.directoryClient(n), message: "Directory client registered" });
  };
  return (
    <Section title="Gatekeeper directory access" description={<Prose>
      Registers a machine client that may read roles, groups and grants with the OAuth client-credentials grant (scope <Code>nathan:directory.read</Code>). Its secret is shown once.</Prose>}>
      <Form onSubmit={create}>
        <TextField label="Client name" placeholder="Gatekeeper PIP" value={name} onChange={setName} />
        <Row><Button type="submit" variant="primary">Register directory client</Button></Row>
      </Form>
      {action.view}
    </Section>
  );
}
