/**
 * NATH-14 pages for the remote MCP authorization server: the script-free consent page, the user's
 * MCP connections page and the Identity Studio section. Every value is HTML-escaped; the consent
 * and connections pages run no script at all.
 */
type Entry = { scope: string; label: string; description: string; group: string; requires: string[]; sensitive: boolean; adminOnly: boolean };

const esc = (s: unknown) => String(s ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");

const STYLE = `:root{color-scheme:dark}*{box-sizing:border-box}body{font:16px system-ui;background:#10121a;color:#f2f3fa;margin:0}
main{width:min(640px,94vw);margin:28px auto;padding:28px;background:#1b1e2a;border:1px solid #35394b;border-radius:16px}
h1{font-size:24px;margin:4px 0 12px}h2{font-size:18px}p,li{color:#b6bfce;line-height:1.5}code{color:#f5c48a;overflow-wrap:anywhere}
fieldset{border:1px solid #35394b;border-radius:10px;margin:12px 0;padding:8px 12px}legend{color:#d9def0;padding:0 6px}
label.scope{display:grid;grid-template-columns:auto 1fr;gap:4px 10px;padding:8px 0;border-top:1px solid #2a2e3d}label.scope:first-of-type{border-top:0}
label.scope span{grid-column:2;color:#b6bfce;font-size:14px}label.full{border:1px solid #6b4a1c;border-radius:10px;padding:10px;margin:10px 0}
.badge{display:inline-block;background:#5c2330;color:#ffd6dd;border-radius:6px;padding:0 6px;font-size:12px;margin-left:6px}
.error{background:#3d1d22;border:1px solid #7a2f3a;border-radius:8px;padding:10px;color:#ffd6dd}.ok{background:#1d3d2a;border:1px solid #2f7a4a;border-radius:8px;padding:10px}
button{font:inherit;background:#ef9028;color:#171717;border:0;border-radius:8px;padding:12px 16px;cursor:pointer;margin:8px 6px 0 0}
button.secondary{background:#363d52;color:#fff}input[type=checkbox]{width:18px;height:18px;margin-top:3px}small{color:#a8b3c7}
section.connection{border:1px solid #35394b;border-radius:12px;padding:14px;margin:14px 0}`;

/** A script-free page. `formTargets` are extra CSP form-action sources (the validated callback origin). */
export function mcpPage(title: string, body: string, status = 200, formTargets: string[] = []): Response {
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Nathan</title><style nonce="${nonce}">${STYLE}</style></head><body><main><small>NATHAN 🌭</small><h1>${esc(title)}</h1>${body}</main></body></html>`;
  // WebKit applies form-action to the redirect after the consent POST, so the exact, already
  // validated callback origin is allowed next to 'self'.
  const formAction = ["'self'", ...formTargets].join(" ");
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; img-src 'none'; style-src 'nonce-" + nonce + "'; script-src 'none'; form-action " + formAction + "; base-uri 'none'; frame-ancestors 'none'",
      // Not no-referrer: under it browsers send `Origin: null` with this page's same-origin form
      // posts, and the consent and connections handlers (rightly) refuse an opaque origin.
      // same-origin still sends no referrer to the client's callback or any other site.
      "Referrer-Policy": "same-origin",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Strict-Transport-Security": "max-age=31536000"
    }
  });
}

export function mcpErrorPage(title: string, message: string, status = 400): Response {
  return mcpPage(title, `<p class="error">${esc(message)}</p><p>Start the connection again from your MCP client. Nothing was granted.</p>`, status);
}

/** Checkboxes, grouped, with the Full access box first. `checked` holds scopes and possibly the Full access marker. */
function scopeBoxes(entries: Entry[], offered: Set<string>, checked: Set<string>, full: string | null, byScope: Map<string, Entry>) {
  const visible = entries.filter(e => offered.has(e.scope));
  let out = "";
  if (full && visible.some(e => !e.sensitive)) {
    out += `<label class="scope full"><input type="checkbox" name="scope" value="${esc(full)}"${checked.has(full) ? " checked" : ""}>` +
      `<strong>Full access <code>${esc(full)}</code></strong><span>Every permission below that is not marked sensitive, including permissions this server adds later. When ticked, the individual boxes for those permissions are ignored. Sensitive permissions are never included: tick them on their own.</span></label>`;
  }
  const groups = new Map<string, Entry[]>();
  for (const e of visible) groups.set(e.group, [...(groups.get(e.group) ?? []), e]);
  for (const [group, items] of groups) {
    out += `<fieldset><legend>${esc(group)}</legend>`;
    for (const e of items) {
      const also = e.requires.filter(r => offered.has(r) && !byScope.get(r)?.sensitive);
      out += `<label class="scope"><input type="checkbox" name="scope" value="${esc(e.scope)}"${checked.has(e.scope) ? " checked" : ""}>` +
        `<strong>${esc(e.label)} <code>${esc(e.scope)}</code>${e.sensitive ? '<span class="badge">sensitive</span>' : ""}${e.adminOnly ? '<span class="badge">administrators</span>' : ""}</strong>` +
        `<span>${esc(e.description || "No description.")}${also.length ? " Also grants " + also.map(r => "<code>" + esc(r) + "</code>").join(", ") + "." : ""}</span></label>`;
    }
    out += `</fieldset>`;
  }
  return out;
}

export type ConsentView = {
  ticket: string; clientName: string; clientId: string; redirectOrigin: string; resourceName: string; resource: string;
  email: string; entries: Entry[]; byScope: Map<string, Entry>; full: string | null; offered: Set<string>; checked: Set<string>;
  unavailable: string[]; error?: string;
};

export function consentPage(v: ConsentView, status = 200): Response {
  const body = `<p><strong>${esc(v.clientName)}</strong> <small>(name chosen by the client; client id <code>${esc(v.clientId)}</code>)</small> wants to use the MCP server <strong>${esc(v.resourceName)}</strong> <code>${esc(v.resource)}</code> as <strong>${esc(v.email)}</strong>. After you answer, your browser returns to <code>${esc(v.redirectOrigin)}</code>.</p>` +
    (v.error ? `<p class="error" role="alert">${esc(v.error)}</p>` : "") +
    `<p>Tick exactly what this client may do. It can never do more than you can: if your access to this application shrinks, so does the client's.</p>` +
    `<form method="post" action="/mcp-oauth/authorize"><input type="hidden" name="ticket" value="${esc(v.ticket)}">` +
    scopeBoxes(v.entries, v.offered, v.checked, v.full, v.byScope) +
    (v.unavailable.length ? `<p><small>Requested but not available to you: ${v.unavailable.map(s => "<code>" + esc(s) + "</code>").join(", ")}.</small></p>` : "") +
    `<p><small>Permissions that need others bring them along when you allow. You can change or disconnect this later under <a href="/connections">MCP connections</a>.</small></p>` +
    `<button name="decision" value="allow">Allow selected access</button><button class="secondary" name="decision" value="deny">Deny</button></form>`;
  return mcpPage("Connect an MCP client", body, status, [v.redirectOrigin]);
}

export type ConnectionView = {
  grantId: string; clientName: string; clientId: string; resourceName: string; resource: string; createdAt: number; expiresAt: number;
  entries: Entry[]; byScope: Map<string, Entry>; full: string | null; offered: Set<string>; checked: Set<string>; effective: string[];
};

export function connectionsPage(email: string, csrf: string, connections: ConnectionView[], notice?: { ok: boolean; message: string }, status = 200): Response {
  const day = (s: number) => new Date(s * 1000).toISOString().slice(0, 10);
  const list = connections.map(c => `<section class="connection"><h2>${esc(c.clientName)} <small>→ ${esc(c.resourceName)}</small></h2>` +
    `<p><small>Client <code>${esc(c.clientId)}</code>, server <code>${esc(c.resource)}</code>. Connected ${day(c.createdAt)}, expires ${day(c.expiresAt)}.</small></p>` +
    `<p><small>Usable now: ${c.effective.length ? c.effective.map(s => "<code>" + esc(s) + "</code>").join(" ") : "nothing (you no longer hold any of these permissions)"}.</small></p>` +
    `<form method="post" action="/connections"><input type="hidden" name="csrf" value="${esc(csrf)}"><input type="hidden" name="grant" value="${esc(c.grantId)}">` +
    scopeBoxes(c.entries, c.offered, c.checked, c.full, c.byScope) +
    `<button name="action" value="save">Save permissions</button><button class="secondary" name="action" value="disconnect">Disconnect</button></form></section>`).join("");
  const body = `<p>MCP clients you allowed to act as <strong>${esc(email)}</strong>. Changes apply to a client's requests within a minute; disconnecting revokes all of its tokens.</p>` +
    (notice ? `<p class="${notice.ok ? "ok" : "error"}" role="status">${esc(notice.message)}</p>` : "") +
    (list || "<p>No MCP connections.</p>");
  return mcpPage("MCP connections", body, status);
}
