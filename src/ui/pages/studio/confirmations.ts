/**
 * NATH-39: every Identity Studio confirmation in one pure module (no React, no DOM), so tests can
 * check the exact text.
 *
 * As in the string-built Studio this replaces, the confirmation dialog is the human check, and the
 * exact `confirm` phrase the service requires is built here after the administrator agrees. So each
 * question states the consequence of the change. A `typed` confirmation (SAML connections and the
 * SAML IdP, as before) makes the administrator type the phrase; what they type is what is sent, and
 * the service stays the authority.
 */
export interface Confirmation {
  title: string;
  /** The consequence, shown in the dialog. */
  question: string;
  /** The exact `confirm` value the service expects, if any. */
  phrase?: string;
  /** The administrator must type `phrase` themselves. */
  typed?: boolean;
  /** Irreversible or access-removing: the confirm button is destructive. */
  destructive?: boolean;
  confirmLabel?: string;
}

const NL = "\n\n";

// ---- Administrators and policy ----------------------------------------------------------------

export const admins = {
  grant: (email: string): Confirmation => ({
    title: "Grant administrator", phrase: "CONFIRM GRANT ADMIN " + email, confirmLabel: "Grant administrator",
    question: "Grant administrator rights to verified Nathan account " + email + "?"
  }),
  revoke: (id: string): Confirmation => ({
    title: "Revoke administrator", phrase: "CONFIRM REVOKE ADMIN " + id, destructive: true, confirmLabel: "Revoke",
    question: "Revoke privileges and sessions for user " + id + "? This cannot be undone without a new grant."
  })
};

export const policy = {
  tighten: (setting: "both-authenticators" | "recent-passkey"): Confirmation => ({
    title: "Increase admin security", phrase: "CONFIRM REQUIRE " + setting, confirmLabel: "Require it",
    question: "Increase Nathan admin security to REQUIRE " + setting + "? This cannot be weakened from the UI."
  })
};

// ---- Applications, protected apps, domain realm ------------------------------------------------

export const apps = {
  status: (id: string, enabled: boolean): Confirmation => ({
    title: enabled ? "Enable access policy" : "Disable access policy",
    phrase: "CONFIRM " + (enabled ? "ENABLE " : "DISABLE ") + id, destructive: !enabled,
    question: "Change access policy for " + id + "?"
  })
};

export const clients = {
  status: (clientId: string, disabled: boolean): Confirmation => ({
    title: disabled ? "Disable client" : "Re-enable client", destructive: disabled,
    question: disabled
      ? "Disable OIDC client " + clientId + "? It can no longer sign anyone in until it is re-enabled."
      : "Re-enable OIDC client " + clientId + "?"
  })
};

export const realm = {
  register: (): Confirmation => ({
    title: "Register hostname", confirmLabel: "Register",
    question: "Register this exact hostname as a new, initially disabled OIDC client?"
  }),
  batch: (): Confirmation => ({
    title: "Register hostnames", phrase: "REGISTER DOMAIN CLIENTS", confirmLabel: "Register",
    question: "Register the reviewed hostnames as disabled clients? Save the one-time secrets securely."
  })
};

// ---- Social providers -------------------------------------------------------------------------

export const providers = {
  save: (name: string): Confirmation => ({
    title: "Store credentials", confirmLabel: "Store",
    question: "Store these " + name + " credentials encrypted in Nathan? This enables " + name + " and clears its last test result."
  }),
  status: (id: string, name: string, enabled: boolean): Confirmation => ({
    title: enabled ? "Enable provider" : "Disable provider", phrase: "CONFIRM " + (enabled ? "ENABLE " : "DISABLE ") + id,
    destructive: !enabled, question: "Change " + name + " sign-in to " + (enabled ? "enabled" : "disabled") + "?"
  }),
  test: (name: string): Confirmation => ({
    title: "Test sign-in", confirmLabel: "Sign in now",
    question: "Sign in with " + name + " now, ideally with a test account? You will be signed in as that account; sign back in as an administrator afterwards."
  })
};

// ---- Roles and access (RBAC) ------------------------------------------------------------------

export const rbac = {
  anySignedIn: (app: string): Confirmation => ({
    title: "Admit every signed-in user", phrase: "CONFIRM ANY SIGNED IN " + app,
    question: "Admit EVERY signed-in user to " + app + "? Roles still come only from grants."
  }),
  permissionDelete: (): Confirmation => ({ title: "Delete permission", destructive: true, question: "Remove this permission from every role?" }),
  roleDelete: (app: string, key: string): Confirmation => ({
    title: "Delete role", phrase: "CONFIRM DELETE ROLE " + app + "/" + key, destructive: true,
    question: "Delete role " + key + " and every grant of it?"
  }),
  grant: (app: string, role: string, who: string): Confirmation => ({
    title: "Grant role", confirmLabel: "Grant", question: "Grant " + role + " in " + app + " to " + who + "?"
  }),
  revoke: (): Confirmation => ({ title: "Revoke grant", destructive: true, question: "Revoke this grant?" }),
  groupDelete: (id: string): Confirmation => ({
    title: "Delete group", phrase: "CONFIRM DELETE GROUP " + id, destructive: true,
    question: "Delete group " + id + ", its memberships and grants?"
  }),
  memberRemove: (): Confirmation => ({ title: "Remove member", destructive: true, question: "Remove this member?" }),
  sync: (app: string, prune: boolean, anySignedIn: boolean): Confirmation & { confirmPrune?: string } => ({
    title: "Apply roles as code", destructive: prune, confirmLabel: "Apply",
    question: "Apply these permissions and roles to " + app + (prune ? " and DELETE undeclared code-managed ones" : "") + "?",
    phrase: anySignedIn ? "CONFIRM ANY SIGNED IN " + app : undefined,
    confirmPrune: prune ? "CONFIRM PRUNE " + app : undefined
  }),
  directoryClient: (name: string): Confirmation => ({
    title: "Register directory client", phrase: "CONFIRM DIRECTORY CLIENT " + name, confirmLabel: "Register",
    question: "Register directory client " + name + "? Its secret is shown once."
  })
};

// ---- Tokens and MCP ---------------------------------------------------------------------------

export const tokens = {
  audienceRemove: (aud: string): Confirmation => ({
    title: "Remove audience", phrase: "CONFIRM REMOVE AUDIENCE " + aud, destructive: true,
    question: "Stop issuing tokens for " + aud + "? Issued tokens expire within 900 seconds."
  }),
  clientKind: (id: string, kind: "agent" | "auto"): Confirmation => kind === "auto"
    ? { title: "Classify by grant", phrase: "CONFIRM CLASSIFY BY GRANT " + id,
        question: "Classify " + id + " by grant again? Its user-delegated tokens will say user." }
    : { title: "Mark as agent", phrase: "CONFIRM MARK AGENT " + id, destructive: true,
        question: "Mark " + id + " as an agent? It may then refresh without a live session and use nathan:api. Its existing user grants are revoked." },
  machine: (name: string, audience: string): Confirmation => ({
    title: "Create client", phrase: "CONFIRM MACHINE CLIENT " + name, confirmLabel: "Create",
    question: "Create client " + name + " for " + audience + "? Its secret is shown once."
  })
};

export const mcp = {
  disable: (id: string): Confirmation => ({
    title: "Disable MCP server", phrase: "CONFIRM DISABLE MCP " + id, destructive: true,
    question: "Stop issuing tokens for " + id + "? Issued tokens stop working within a minute."
  }),
  enable: (id: string): Confirmation => ({ title: "Enable MCP server", phrase: "CONFIRM ENABLE MCP " + id, question: "Start issuing tokens for " + id + " again?" }),
  remove: (id: string): Confirmation => ({
    title: "Remove MCP server", phrase: "CONFIRM REMOVE MCP " + id, destructive: true, question: "Remove " + id + " and every connection to it?"
  }),
  revoke: (grant: string): Confirmation => ({
    title: "Revoke connection", phrase: "CONFIRM REVOKE " + grant, destructive: true, question: "Revoke connection " + grant + "?"
  })
};

// ---- Admission --------------------------------------------------------------------------------

export const admission = {
  mode: (mode: "invitation-only" | "self-service"): Confirmation => ({
    title: "Change admission mode", phrase: "CONFIRM ADMISSION " + mode,
    question: mode === "self-service"
      ? "Let anyone who can sign in through an enabled method create an account?"
      : "Require an invitation for every new account? Existing accounts keep working."
  }),
  reissue: (email: string): Confirmation => ({
    title: "Reissue invitation", phrase: "CONFIRM REISSUE INVITATION " + email, destructive: true,
    question: "Remove the unverified account for " + email + " (if any) and invite it again?"
  }),
  revoke: (id: string): Confirmation => ({
    title: "Revoke invitation", phrase: "CONFIRM REVOKE INVITATION " + id, destructive: true, question: "Revoke invitation " + id + "?"
  })
};

// ---- SCIM -------------------------------------------------------------------------------------

export const scim = {
  create: (): Confirmation => ({
    title: "Create SCIM connection", confirmLabel: "Create",
    question: "Create a disabled SCIM connection and issue a one-time bearer credential?"
  }),
  manage: (id: string, action: "enable" | "disable" | "rotate"): Confirmation => ({
    title: action === "rotate" ? "Rotate bearer token" : action === "enable" ? "Enable connection" : "Disable connection",
    phrase: action === "rotate" ? "CONFIRM ROTATE " + id : "CONFIRM " + (action === "enable" ? "ENABLE " : "DISABLE ") + id,
    destructive: action !== "enable",
    question: "Apply " + action + " to SCIM directory connection " + id + "?" +
      (action === "rotate" ? NL + "The current bearer token stops working; update your directory provider with the new one." : "")
  }),
  settings: (id: string, linking: boolean, jit: boolean): Confirmation => ({
    title: "Save lifecycle settings", phrase: "CONFIRM SCIM SETTINGS " + id, destructive: true, confirmLabel: "Save",
    question: "Set linking " + (linking ? "ON" : "OFF") + " and just-in-time creation " + (jit ? "ON" : "OFF") + " for " + id + "?" + NL +
      "Every staged directory user is re-applied now: matching users are linked, and linked users the directory deactivated or deleted are blocked and lose every session and token (administrators wait for review)."
  }),
  map: (id: string, ref: string, group: string): Confirmation => ({
    title: "Map group", phrase: "CONFIRM MAP " + id + "/" + ref + " TO " + group, confirmLabel: "Map",
    question: "Let the directory maintain the members of " + group + " from SCIM group " + ref + "?" + NL +
      "From now on only the directory adds and removes its members, and members gain whatever roles " + group + " is granted."
  }),
  unmap: (group: string): Confirmation => ({
    title: "Remove mapping", phrase: "CONFIRM UNMAP " + group, destructive: true,
    question: "Remove the mapping of " + group + " and every member the directory added?" + NL +
      "Those members lose the roles granted to " + group + " now."
  }),
  approve: (review: { action: string; email: string; userName?: string }): Confirmation => ({
    title: "Approve review", phrase: "CONFIRM APPROVE " + review.action.toUpperCase() + " " + review.email, destructive: review.action !== "link",
    confirmLabel: "Approve",
    question: review.action === "link"
      ? "Link directory user " + review.userName + " to Nathan administrator " + review.email + "? The directory can then request this account's deprovisioning (each request is reviewed again)."
      : "Deprovision administrator " + review.email + "? This blocks the account, ends every Nathan session, revokes every token and sends back-channel logout."
  }),
  dismiss: (review: { action: string; email: string }): Confirmation => ({
    title: "Dismiss review", phrase: "CONFIRM DISMISS " + review.action.toUpperCase() + " " + review.email, confirmLabel: "Dismiss",
    question: "Dismiss: " + review.email + " stays as it is. " + (review.action === "link"
      ? "This directory user is not linked automatically again."
      : "The directory's deactivation is ignored until it sends a new one.")
  }),
  keepActive: (user: { email: string }): Confirmation => ({
    title: "Keep active", phrase: "CONFIRM KEEP ACTIVE " + user.email, confirmLabel: "Unblock",
    question: "Unblock " + user.email + " although the directory deprovisioned it?" + NL +
      "Sessions and tokens revoked earlier are not restored. Replays and resyncs keep your decision; a new deactivation or deletion from the directory blocks the account again."
  }),
  unlink: (user: { email: string; userName?: string }): Confirmation => ({
    title: "Unlink directory user", phrase: "CONFIRM UNLINK " + user.email, destructive: true, confirmLabel: "Unlink",
    question: "Unlink " + user.email + " from directory user " + user.userName + "?" + NL +
      "Its directory-maintained group memberships (and the roles they carry) are removed, the directory no longer controls the account, and it is not linked again automatically. A block the directory caused stays."
  }),
  skip: (head: { kind: string; resourceId: string; attempts?: number; lastError?: string | null; resource?: any }): Confirmation => {
    const what = head.kind + " " + ((head.resource && (head.resource.userName || head.resource.displayName)) || head.resourceId);
    return {
      title: "Skip outbox entry", phrase: "CONFIRM SKIP " + head.kind.toUpperCase() + " " + head.resourceId, destructive: true, confirmLabel: "Skip",
      question: "Skip the change to " + what + " (failed " + head.attempts + " times: " + (head.lastError || "unknown error") + ")?" + NL +
        "Nathan will NOT apply it. If it deactivates or deletes a user, that user is NOT blocked: block them yourself in Users. It is applied again when the resource changes in the directory or on a resync."
    };
  }
};

// ---- Enterprise SSO, SAML, SAML IdP -----------------------------------------------------------

export const saml = {
  create: (id: string, domain: string): Confirmation => ({
    title: "Create SAML connection", confirmLabel: "Create",
    question: "Create SAML connection " + id + " for " + domain + "? It starts disabled."
  }),
  status: (id: string, enabled: boolean): Confirmation => ({
    title: enabled ? "Enable SAML connection" : "Disable SAML connection", typed: true, destructive: !enabled,
    phrase: (enabled ? "CONFIRM ENABLE SAML " : "CONFIRM DISABLE SAML ") + id,
    question: enabled ? "People in the verified domain can sign in through this connection." : "Sign-in through this connection stops immediately."
  }),
  provisioning: (id: string, mode: string): Confirmation => ({
    title: "Apply provisioning mode", typed: true, phrase: "CONFIRM PROVISIONING " + mode + " " + id,
    question: "Change how accounts are provisioned for connection " + id + "."
  }),
  retire: (id: string): Confirmation => ({
    title: "Retire certificate", typed: true, destructive: true, phrase: "CONFIRM RETIRE CERTIFICATE " + id,
    question: "Stop trusting this certificate. Assertions signed with it are refused."
  })
};

export const samlIdp = {
  create: (id: string): Confirmation => ({ title: "Create service provider", typed: true, phrase: "CONFIRM CREATE SAML SP " + id, question: "The SP starts disabled." }),
  update: (id: string): Confirmation => ({ title: "Update service provider", typed: true, phrase: "CONFIRM UPDATE SAML SP " + id, question: "The SP's settings are replaced with this form." }),
  status: (id: string, enabled: boolean): Confirmation => ({
    title: enabled ? "Enable service provider" : "Disable service provider", typed: true, destructive: !enabled,
    phrase: "CONFIRM " + (enabled ? "ENABLE" : "DISABLE") + " SAML SP " + id,
    question: enabled ? "People its application allows can sign in to it." : "Sign-in to this SP stops immediately."
  }),
  generate: (): Confirmation => ({ title: "Generate signing key", typed: true, phrase: "CONFIRM GENERATE SAML IDP KEY", question: "The first key becomes active; later keys are published as next." }),
  activate: (): Confirmation => ({
    title: "Activate next key", typed: true, destructive: true, phrase: "CONFIRM ACTIVATE SAML IDP KEY",
    question: "Activate only after every SP has loaded the new metadata (at least 24 hours)."
  }),
  retire: (): Confirmation => ({ title: "Retire key", typed: true, destructive: true, phrase: "CONFIRM RETIRE SAML IDP KEY", question: "SPs stop trusting signatures made with this key." })
};
