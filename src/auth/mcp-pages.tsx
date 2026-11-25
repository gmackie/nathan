/**
 * NATH-14 pages for the remote MCP authorization server, in stock Kumo (NATH-38): the granular
 * consent page, the user's MCP connections page and its error page. Moved here from mcp-ui.ts,
 * which keeps only the Identity Studio section.
 *
 * All three run no script at all (renderPage without islands sends script-src 'none'). Plain
 * HTML forms post same-origin; native checkboxes keep the true state visible without script
 * (Kumo's Checkbox draws its tick with script). Every value is React-escaped.
 *
 * WebKit applies form-action to the redirect after the consent POST, so the exact, already
 * validated callback origin (https, or http on a loopback host) is allowed next to 'self'.
 * Referrer-Policy stays same-origin (renderPage): under no-referrer, browsers send `Origin: null`
 * with this page's same-origin form posts, and the handlers (rightly) refuse an opaque origin.
 */
import { Badge } from "@cloudflare/kumo/components/badge";
import { Banner } from "@cloudflare/kumo/components/banner";
import { Button } from "@cloudflare/kumo/components/button";
import { Fragment } from "react";
import { renderPage } from "../ui/render.tsx";
import { AuthLayout } from "../ui/layouts/AuthLayout.tsx";
import { NathanIcon } from "../ui/icons.tsx";
import type { ResolvedAppearance } from "../ui/appearance.ts";

type Entry = { scope: string; label: string; description: string; group: string; requires: string[]; sensitive: boolean; adminOnly: boolean };

const Code = ({ children }: { children: string }) => <code className="nathan-code">{children}</code>;

/** `a, b, c` as code spans. */
function codeList(items: string[], separator = ", ") {
  return items.map((s, i) => <Fragment key={s}>{i ? separator : null}<Code>{s}</Code></Fragment>);
}

/** Checkboxes, grouped, with the Full access box first. `checked` holds scopes and possibly the Full access marker. */
function ScopeBoxes({ entries, offered, checked, full, byScope }:
  { entries: Entry[]; offered: Set<string>; checked: Set<string>; full: string | null; byScope: Map<string, Entry> }) {
  const visible = entries.filter(e => offered.has(e.scope));
  const groups = new Map<string, Entry[]>();
  for (const e of visible) groups.set(e.group, [...(groups.get(e.group) ?? []), e]);
  return (
    <>
      {full && visible.some(e => !e.sensitive) ? (
        <label className="nathan-scope nathan-scope-full">
          <input type="checkbox" name="scope" value={full} defaultChecked={checked.has(full)} />
          <span className="nathan-scope-name">Full access <Code>{full}</Code></span>
          <span className="nathan-scope-description">Every permission below that is not marked sensitive, including permissions this server adds later. When ticked, the individual boxes for those permissions are ignored. Sensitive permissions are never included: tick them on their own.</span>
        </label>
      ) : null}
      {[...groups].map(([group, items]) => (
        <fieldset className="nathan-scopes" key={group}>
          <legend>{group}</legend>
          {items.map(e => {
            const also = e.requires.filter(r => offered.has(r) && !byScope.get(r)?.sensitive);
            return (
              <label className="nathan-scope" key={e.scope}>
                <input type="checkbox" name="scope" value={e.scope} defaultChecked={checked.has(e.scope)} />
                <span className="nathan-scope-name">
                  {e.label} <Code>{e.scope}</Code>
                  {e.sensitive ? <Badge variant="destructive">sensitive</Badge> : null}
                  {e.adminOnly ? <Badge variant="outline">administrators</Badge> : null}
                </span>
                <span className="nathan-scope-description">
                  {e.description || "No description."}
                  {also.length ? <> Also grants {codeList(also)}.</> : null}
                </span>
              </label>
            );
          })}
        </fieldset>
      ))}
    </>
  );
}

export type ConsentView = {
  ticket: string; clientName: string; clientId: string; redirectOrigin: string; resourceName: string; resource: string;
  email: string; entries: Entry[]; byScope: Map<string, Entry>; full: string | null; offered: Set<string>; checked: Set<string>;
  unavailable: string[]; error?: string;
  /** NATH-38: issuer host for the fixed route line and footer. */
  issuer?: string;
};

export interface McpPageOptions {
  appearance?: ResolvedAppearance;
}

export function consentPage(v: ConsentView, status = 200, opts: McpPageOptions = {}): Response {
  return renderPage(
    // Independent review 2026-11-23: the client picks its own name at dynamic registration, so it is
    // never the heading or the trusted route line (it could read "id.example.com" or "Nathan Identity
    // Studio"). The heading is fixed and the route line is the validated callback host.
    <AuthLayout title="Connect an MCP client" issuer={v.issuer} route={new URL(v.redirectOrigin).host}
      appearance={opts.appearance}>
      <p className="nathan-text">
        {"A client calling itself "}<strong>{"\u201c" + v.clientName + "\u201d"}</strong>{" "}
        <span className="nathan-muted">(name chosen by the client, not verified by Nathan; client id <Code>{v.clientId}</Code>)</span>
        {" wants to use the MCP server "}<strong>{v.resourceName}</strong> <Code>{v.resource}</Code>
        {" as "}<strong>{v.email}</strong>{". After you answer, your browser returns to "}<Code>{v.redirectOrigin}</Code>.
      </p>
      {v.error ? <Banner variant="error" role="alert" icon={<NathanIcon name="warning" />} description={v.error} /> : null}
      <p className="nathan-text">Tick exactly what this client may do. It can never do more than you can: if your access to this application shrinks, so does the client's.</p>
      <form className="nathan-form" method="post" action="/mcp-oauth/authorize">
        <input type="hidden" name="ticket" value={v.ticket} />
        <ScopeBoxes entries={v.entries} offered={v.offered} checked={v.checked} full={v.full} byScope={v.byScope} />
        {v.unavailable.length ? <p className="nathan-muted">Requested but not available to you: {codeList(v.unavailable)}.</p> : null}
        <p className="nathan-muted">Permissions that need others bring them along when you allow. You can change or disconnect this later under <a href="/connections">MCP connections</a>.</p>
        <div className="nathan-actions">
          <Button type="submit" name="decision" value="allow" variant="primary" size="lg">Allow selected access</Button>
          <Button type="submit" name="decision" value="deny" variant="secondary" size="lg">Deny</Button>
        </div>
      </form>
    </AuthLayout>,
    { title: "Connect an MCP client", status, formAction: ["'self'", v.redirectOrigin], appearance: opts.appearance }
  );
}

export type ConnectionView = {
  grantId: string; clientName: string; clientId: string; resourceName: string; resource: string; createdAt: number; expiresAt: number;
  entries: Entry[]; byScope: Map<string, Entry>; full: string | null; offered: Set<string>; checked: Set<string>; effective: string[];
};

export function connectionsPage(email: string, csrf: string, connections: ConnectionView[], notice?: { ok: boolean; message: string }, status = 200): Response {
  const day = (s: number) => new Date(s * 1000).toISOString().slice(0, 10);
  return renderPage(
    <AuthLayout title="MCP connections">
      <p className="nathan-text">MCP clients you allowed to act as <strong>{email}</strong>. Changes apply to a client's requests within a minute; disconnecting revokes all of its tokens.</p>
      {notice ? (
        <Banner variant={notice.ok ? "default" : "error"} role="status" icon={<NathanIcon name={notice.ok ? "success" : "warning"} />}
          description={notice.message} />
      ) : null}
      {connections.length ? connections.map(c => (
        <section className="nathan-connection" key={c.grantId}>
          {/* The client chose its own name: quote it and say so, as on the consent page (review 2026-11-23). */}
          <h2 className="nathan-subtitle">{"\u201c" + c.clientName + "\u201d"} <span className="nathan-muted">{"→ " + c.resourceName}</span></h2>
          <p className="nathan-muted">Name chosen by the client, not verified by Nathan.</p>
          <p className="nathan-muted">Client <Code>{c.clientId}</Code>, server <Code>{c.resource}</Code>{". Connected " + day(c.createdAt) + ", expires " + day(c.expiresAt) + "."}</p>
          <p className="nathan-muted">
            {c.effective.length ? <>Usable now: {codeList(c.effective, " ")}.</> : "Usable now: nothing (you no longer hold any of these permissions)."}
          </p>
          <form className="nathan-form" method="post" action="/connections">
            <input type="hidden" name="csrf" value={csrf} />
            <input type="hidden" name="grant" value={c.grantId} />
            <ScopeBoxes entries={c.entries} offered={c.offered} checked={c.checked} full={c.full} byScope={c.byScope} />
            <div className="nathan-actions">
              <Button type="submit" name="action" value="save" variant="primary">Save permissions</Button>
              <Button type="submit" name="action" value="disconnect" variant="secondary">Disconnect</Button>
            </div>
          </form>
        </section>
      )) : <p className="nathan-text">No MCP connections.</p>}
    </AuthLayout>,
    { title: "MCP connections", status }
  );
}

/** A refused MCP authorization step. Nothing was granted; no form, no script. */
export function mcpErrorPage(title: string, message: string, status = 400): Response {
  return renderPage(
    <AuthLayout title={title}>
      <Banner variant="error" role="alert" icon={<NathanIcon name="warning" />} description={message} />
      <p className="nathan-text">Start the connection again from your MCP client. Nothing was granted.</p>
    </AuthLayout>,
    { title, status }
  );
}
