import { Button } from "@cloudflare/kumo/components/button";
import { Input } from "@cloudflare/kumo/components/input";
import { Link } from "@cloudflare/kumo/components/link";
import { Table } from "@cloudflare/kumo/components/table";
import type { listUsers } from "../../../auth/admin-service";
import { renderPage } from "../../render";

type User = Awaited<ReturnType<typeof listUsers>>[number];
export type OpenInvite = { id: string; email: string; expiresAt: number };
export const directoryPageSize = 25;

export function usersPage(users: User[], invites: OpenInvite[], actor: string, query: string, page: number, classCheck: boolean) {
  const href = (page: number) => "/studio/users?" + new URLSearchParams({q:query,page:String(page)});
  return renderPage(<main className="nathan-stack" style={{maxWidth:960,margin:"24px auto",padding:"0 16px",gap:24}} data-user-directory="" data-classcheck={classCheck ? "true" : undefined}>
    <nav style={{display:"flex",gap:16}}><Link href="/studio">Identity Studio</Link><Link href="/security?setup=admin">Account security</Link></nav>
    <h1 className="nathan-title">User management</h1>
    {classCheck && <p>Use a separate email address for Studio administrators. Allow it in Cloudflare Access before they sign in.
      Manage school roles and assignments in ClassCheck.</p>}
    <form method="get" action="/studio/users" className="nathan-form">
      <Input label="Find by email or name" name="q" type="search" defaultValue={query} maxLength={254} />
      <Button type="submit" variant="secondary">Search</Button>
    </form>
    <section className="nathan-stack" aria-labelledby="accounts">
      <h2 id="accounts">Accounts</h2>
      {users.length ? <div style={{overflowX:"auto"}}><Table aria-label="Accounts">
        <Table.Header><Table.Row>{["Account","Email","Status","Nathan access",""].map((s,i) =>
          <Table.Head key={i} aria-label={s || "Actions"}>{s}</Table.Head>)}</Table.Row></Table.Header>
        <Table.Body>{users.slice(0,directoryPageSize).map(u => <Table.Row key={u.id}>
          <Table.Cell>{u.name || "—"}</Table.Cell><Table.Cell>{u.email}</Table.Cell>
          <Table.Cell>{u.deprovisioned ? "Deprovisioned" : u.blocked ? "Suspended" : u.emailVerified ? "Verified" : "Awaiting verification"}</Table.Cell>
          <Table.Cell>{u.owner ? "Owner" : u.role === "admin" && u.adminGrant ? "Administrator" : "User"}</Table.Cell>
          <Table.Cell>{!u.owner && u.id !== actor && <>
            {Boolean(u.adminGrant) && <Button type="button" size="sm" variant="secondary-destructive" data-operation="revoke-admin" data-id={u.id} data-email={u.email} disabled>Revoke admin</Button>}
            {Boolean(u.emailVerified && !u.blocked && !u.deprovisioned && (!u.adminGrant || u.role !== "admin")) &&
              <Button type="button" size="sm" variant="secondary" data-operation="grant" data-id={u.id} data-email={u.email} disabled>Grant admin</Button>}
          </>}</Table.Cell>
        </Table.Row>)}</Table.Body>
      </Table></div> : <p>{query ? "No accounts match this search." : "No accounts on this page."}</p>}
      <nav aria-label="Account pages" style={{display:"flex",gap:16}}>
        {page>1 && <Link href={href(page-1)}>Previous accounts</Link>}
        {users.length>directoryPageSize && <Link href={href(page+1)}>Next accounts</Link>}
      </nav>
    </section>
    <section className="nathan-stack" aria-labelledby="invite">
      <h2 id="invite">Invitations</h2>
      <form className="nathan-form" method="post" action="/studio/users" data-invite="">
        <Input label="Email address to invite" name="email" type="email" maxLength={254} required />
        <Button type="submit" disabled>Create invitation</Button>
      </form>
      <p>The invitation is valid for seven days. Tell the person to sign in with that address.</p>
      {invites.length ? <ul>{invites.slice(0,50).map(i => <li key={i.id}>
        {i.email} · expires {new Date(i.expiresAt*1000).toISOString().slice(0,10)} UTC{" "}
        <Button type="button" size="sm" variant="secondary" data-operation="revoke-invite" data-id={i.id} data-email={i.email} disabled>Revoke invitation</Button>
      </li>)}</ul> : <p>No matching open invitations.</p>}
      {invites.length>50 && <p>Showing the latest 50 invitations. Search by email to narrow the list.</p>}
    </section>
    <p role="status" aria-live="polite" data-status=""></p>
  </main>,{title:"User management",islands:["user-directory"]});
}
