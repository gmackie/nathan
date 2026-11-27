/** NATH-39 Studio: instance status, bootstrap and enrollment, capabilities, admin policy, plugins, MCP admin endpoint. */
import { useEffect, useState } from "react";
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import { Code, DataTable, JsonView, Loaded, Panel, Prose, RefreshButton, Row, Section, SelectField, useAction, useLoad } from "../kit.tsx";

const yes = (v: unknown) => <Badge variant={v ? "success" : "neutral"}>{v ? "On" : "Off"}</Badge>;

export function Overview({ email }: { email: string }) {
  const bootstrap = useLoad(() => apiGet("/bootstrap"));
  const status = useLoad(() => apiGet("/status"));
  return (
    <Panel title="Overview" description={<Prose>Signed in as <strong>{email}</strong>.</Prose>}>
      <Section title="Admin setup">
        <Loaded state={bootstrap}>{(b: any) => (
          <DataTable label="Admin setup" empty="No setup state." rowKey={r => r.k} columns={[{ key: "k", label: "Item" }, { key: "v", label: "State" }]}
            rows={[
              { k: "Bootstrap", v: b.configured ? b.state : "Not initialized" },
              { k: "You are the initial administrator", v: b.isInitialAdmin },
              { k: "Passkeys enrolled", v: b.passkeys },
              { k: "TOTP verified", v: b.totpVerified },
              { k: "Enrollment complete for the current policy", v: b.ready }
            ]} />
        )}</Loaded>
        {bootstrap.data?.warning ? <Prose>{bootstrap.data.warning}</Prose> : null}
      </Section>
      <Section title="Identity providers and capabilities">
        <Loaded state={status}>{(s: any) => (
          <div className="nathan-stack">
            <Prose>Issuer: <Code>{s.issuer}</Code></Prose>
            <DataTable label="Features" empty="" rowKey={r => r.k} columns={[{ key: "k", label: "Feature" }, { key: "v", label: "State", render: r => yes(r.v) }]}
              rows={Object.entries(s.features ?? {}).map(([k, v]) => ({ k, v }))} />
            <DataTable label="Social providers" empty="No social providers." rowKey={r => r.k}
              columns={[{ key: "k", label: "Provider" }, { key: "v", label: "Enabled", render: r => yes(r.v) }]}
              rows={Object.entries(s.providers ?? {}).map(([k, v]) => ({ k, v }))} />
            {s.note ? <Prose>{s.note}</Prose> : null}
          </div>
        )}</Loaded>
      </Section>
      <SecurityPolicy />
      <Plugins />
      <McpEndpoint />
    </Panel>
  );
}

function SecurityPolicy() {
  const policy = useLoad(() => apiGet("/security-policy"));
  const action = useAction();
  const tighten = (setting: "both-authenticators" | "recent-passkey") => action.run(
    confirm => apiPost("/security-policy/tighten", { setting, confirm }),
    { confirm: confirmations.policy.tighten(setting), message: r => r?.note ?? "Policy updated", after: () => { void policy.reload(); } });
  return (
    <Section title="Authentication and MFA policy" description={<Prose>
      Nathan's effective security posture combines the selected installer profile with any stricter policy configured here. Administrators may
      require a recent passkey after the initial owner and every enabled administrator have enrolled one, but weakening a baseline requires a separately reviewed Cloudflare operator change. Federated
      NIST AAL claims remain unsupported until validated.</Prose>}>
      <Loaded state={policy}>{p => <JsonView value={p} label="Effective policy" />}</Loaded>
      <Row>
        <Button variant="primary" onClick={() => tighten("both-authenticators")}>Require passkey + verified TOTP enrollment for administrators</Button>
        <Button variant="primary" onClick={() => tighten("recent-passkey")}>Require a recent passkey login for privileged administration</Button>
      </Row>
      {action.view}
    </Section>
  );
}

const TIERS = { all: "All tiers", verified: "Verified candidates", community: "Community", custom: "Private/custom" } as const;

function Plugins() {
  const catalog = useLoad(() => apiGet("/plugins"));
  const [tier, setTier] = useState<keyof typeof TIERS>("all");
  return (
    <Section title="Available plugins" description={<Prose>Catalog entries are read-only until their packages and database migrations are reviewed and deployed.</Prose>}>
      <SelectField label="Tier" value={tier} onChange={setTier} options={TIERS} />
      <Loaded state={catalog}>{(c: any) => (
        <DataTable label="Plugins" empty="No plugins in this tier." rowKey={r => r.id ?? r.name}
          rows={(c.plugins ?? []).filter((p: any) => tier === "all" || p.tier === tier)}
          columns={[{ key: "name", label: "Plugin" }, { key: "tier", label: "Tier" }, { key: "packageName", label: "Package" },
            { key: "installed", label: "State", render: p => p.installed ? <Badge variant="success">Enabled</Badge> : <Badge variant="neutral">Needs review/build</Badge> }]} />
      )}</Loaded>
      <Row><RefreshButton onClick={() => void catalog.reload()} /></Row>
    </Section>
  );
}

function McpEndpoint() {
  const [origin, setOrigin] = useState("");
  useEffect(() => setOrigin(location.origin), []);
  return (
    <Section title="MCP administration" description={<Prose>OAuth-protected stateless MCP endpoint. Register an MCP OIDC client for resource-bound access.</Prose>}>
      <DataTable label="MCP endpoint" empty="" rowKey={r => r.k} columns={[{ key: "k", label: "" }, { key: "v", label: "Value", render: r => <Code>{r.v}</Code> }]}
        rows={[
          { k: "Endpoint", v: origin + "/mcp" },
          { k: "Resource metadata", v: origin + "/.well-known/oauth-protected-resource" },
          { k: "Scopes", v: "nathan:read / nathan:admin" },
          { k: "Protocol", v: "2026-07-28" }
        ]} />
    </Section>
  );
}
