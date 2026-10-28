# Admin MCP server

Nathan exposes a stateless, OAuth-protected Model Context Protocol endpoint at \`https://auth.example.com/mcp\`.

**Security:** Never supply Better Auth cookies to MCP. MCP requires a resource-bound JWT access token issued to \`https://auth.example.com/mcp\`, with \`nathan:read\` or \`nathan:admin\` scopes. The resource metadata is discoverable at \`/.well-known/oauth-protected-resource\`. All requests are checked against the current Nathan identity store: email must be verified, user must be in the admin role and in \`NATHAN_ADMIN_EMAILS\`, and account must not be suspended.

## Client registration

From Identity Studio register a **MCP administrator** application with an exact HTTPS redirect URI, such as an agent's OAuth callback. Public clients require PKCE and do not receive a client secret. Ask for the \`resource=https://auth.example.com/mcp\` authorization parameter and the \`nathan:read\` scope.

This initial implementation uses Nathan's own strict stateless JSON-RPC adapter with MCP protocol version **2026-07-28**. It supports \`server/discover\`, \`tools/list\`, and \`tools/call\`. The client must send \`MCP-Protocol-Version\`, \`Mcp-Method\`, \`Mcp-Name\` (when invoking tools), and matching \`params._meta\`. Production client-compatibility tests against the official MCP SDK are still required.

## Read tools

- \`nathan_status\`
- \`nathan_clients_list\`
- \`nathan_apps_list\`
- \`nathan_sso_list\`
- \`nathan_audit_recent\`

## Write tools

By default, the server **does not advertise write tools**. To opt in, deploy the IdP with \`NATHAN_MCP_WRITE_ENABLED=true\`, grant a registered client \`nathan:admin\` on the MCP resource, and authenticate an existing administrator session. Every call must provide the operation's exact confirmation string.

- \`nathan_app_set_enabled\`: \`CONFIRM ENABLE app-id\` or \`CONFIRM DISABLE app-id\`.
- \`nathan_client_set_disabled\`: \`CONFIRM DISABLE client-id\` or \`CONFIRM ENABLE client-id\`.

Every write checks current admin status, current session status, account role, the scope, and an explicit operation-specific confirmation. Successful and unsuccessful write attempts are recorded in \`nathan_security_audit\`.

**Scope limitation:** Changing a client's disabled status may not revoke access tokens previously issued to it; token expiry or separate token revocation is necessary.

## Safety properties

No unauthenticated public tools, no self-service credential recovery, no untrusted plugin execution in the auth Worker, and no secrets in tool output. Requests are per-admin rate-limited in D1, disallow cross-origin requests, enforce a maximum body size, and reject DPoP-bound tokens because proof verification is not implemented here.

If the user's OAuth client cannot send the 2026-07-28 metadata and headers, do not disable the checks; use the Identity Studio web UI until an official SDK compatibility layer is added.
