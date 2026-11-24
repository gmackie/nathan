/**
 * NATH-39 Studio: enterprise SSO. Upstream corporate OIDC providers, inbound SAML connections
 * (NATH-10, Nathan is the SP) and Nathan as a SAML IdP for downstream service providers (NATH-12).
 * SAML changes keep their typed confirmations: the administrator types the exact phrase.
 */
import { useEffect, useState } from "react";
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { apiGet, apiPost } from "../api.ts";
import * as confirmations from "../confirmations.ts";
import {
  AreaField, CheckField, Code, DataTable, Form, JsonView, Loaded, Notice, Panel, Prose, RefreshButton, Row, Section, SelectField, Subsection, TextField,
  useAction, useFields, useLoad, when
} from "../kit.tsx";

// ---- Enterprise OIDC --------------------------------------------------------------------------

export function EnterpriseOidc() {
  const list = useLoad(() => apiGet("/sso"));
  const action = useAction();
  const f = useFields({ providerId: "", domain: "", issuer: "", clientId: "", clientSecret: "" });
  const register = () => {
    const body = { ...f.values };
    // The secret leaves the form as soon as it is sent.
    f.set("clientSecret", "");
    return action.run(() => apiPost("/sso/oidc", body), { message: "Provider registered", after: () => { void list.reload(); } });
  };
  const domain = (path: "/sso/token" | "/sso/verify") => action.run(() => apiPost(path, { providerId: f.values.providerId }),
    { message: path === "/sso/token" ? "New TXT challenge" : "Domain verified", after: () => { void list.reload(); } });
  return (
    <Panel title="Enterprise SSO (OIDC)" description={<Prose>Register an upstream corporate OIDC provider. Nathan remains the downstream OIDC issuer.</Prose>}>
      <Section title="Register provider">
        <Form onSubmit={register}>
          <TextField label="Provider ID" placeholder="acme-entra" {...f.text("providerId")} />
          <TextField label="Corporate email domain" placeholder="acme.example" {...f.text("domain")} />
          <TextField label="Issuer URL" placeholder="https://login.example.com" {...f.text("issuer")} />
          <TextField label="Client ID" {...f.text("clientId")} />
          <TextField label="Client secret" type="password" autoComplete="new-password" {...f.text("clientSecret")} />
          <Row><Button type="submit" variant="primary">Register provider</Button></Row>
        </Form>
      </Section>
      <Section title="Domain ownership" description={<Prose>
        Each corporate IdP must prove domain ownership using the Better Auth DNS TXT challenge before users can authenticate with it or link accounts.</Prose>}>
        <Row>
          <Button variant="secondary" onClick={() => void domain("/sso/token")}>Request new TXT challenge</Button>
          <Button variant="primary" onClick={() => void domain("/sso/verify")}>Verify DNS ownership</Button>
        </Row>
      </Section>
      {action.view}
      <Section title="Enterprise providers">
        <Loaded state={list}>{(d: any) => (
          <DataTable label="Enterprise providers" empty="No enterprise providers." rows={d.providers}
            columns={[{ key: "id", label: "ID" }, { key: "domain", label: "Domain" }, { key: "issuer", label: "Issuer" },
              { key: "kind", label: "Kind", render: r => r.saml ? "SAML" : r.oidc ? "OIDC" : "—" },
              { key: "domainVerified", label: "Domain", render: r => <Badge variant={r.domainVerified ? "success" : "warning"}>{r.domainVerified ? "Verified" : "Unverified"}</Badge> }]} />
        )}</Loaded>
        <Row><RefreshButton onClick={() => void list.reload()} label="List enterprise providers" /></Row>
      </Section>
    </Panel>
  );
}

// ---- Inbound SAML -----------------------------------------------------------------------------

const PRESETS = { okta: "Okta", entra: "Microsoft Entra ID", google: "Google Workspace", generic: "Other SAML 2.0 IdP" } as const;
const PROVISIONING = { "invitation-only": "Invitation only: existing Nathan users in the domain", "just-in-time": "Just-in-time: create accounts for the verified domain" } as const;

function Copyable({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="nathan-stack">
      <Prose>{label}</Prose>
      <pre className="nathan-studio-json"><code>{value || "Enter the connection ID first."}</code></pre>
      {value ? <Row><Button size="sm" variant="secondary" onClick={() => navigator.clipboard.writeText(value).then(() => setCopied(true))}>{copied ? "Copied" : "Copy"}</Button></Row> : null}
    </div>
  );
}

export function SamlConnections() {
  const list = useLoad(() => apiGet("/saml"));
  const action = useAction();
  const [origin, setOrigin] = useState("");
  useEffect(() => setOrigin(location.origin), []);
  const f = useFields({
    id: "", domain: "", preset: "okta" as keyof typeof PRESETS, provisioning: "invitation-only" as keyof typeof PROVISIONING,
    metadataUrl: "", metadataXml: "", nextCert: "", retire: ""
  });
  const sid = f.values.id.trim();
  const enc = encodeURIComponent(sid);
  const metadataUrl = sid && origin ? origin + "/api/auth/sso/saml2/sp/metadata?providerId=" + enc : "";
  const acs = sid && origin ? origin + "/api/auth/sso/saml2/sp/acs/" + enc : "";
  const metadata = () => ({ metadataUrl: f.values.metadataUrl.trim() || undefined, metadataXml: f.values.metadataXml.trim() || undefined });
  const after = () => { void list.reload(); };
  const typed = (path: string, body: Record<string, unknown>, c: confirmations.Confirmation) =>
    action.run(confirm => {
      if (confirm !== c.phrase) throw Error("Confirmation did not match");
      return apiPost(path, { ...body, confirm });
    }, { confirm: c, message: "Done", after });
  return (
    <Panel title="Enterprise SAML" description={<Prose>
      Connect Okta, Microsoft Entra ID or Google Workspace as a SAML identity provider. Nathan is the SAML service provider. New connections start
      <strong> disabled</strong> and can only be enabled after the email domain passes the DNS TXT challenge. Assertions must be signed with SHA-256 or
      stronger; IdP-initiated sign-in is not accepted.</Prose>}>
      <Section title="Connection">
        <TextField label="Connection ID" placeholder="acme-okta" {...f.text("id")} />
        <Subsection title="Values for your IdP administrator">
          <Prose>These values are fixed per connection.</Prose>
          <Copyable label="Audience / SP entity ID:" value={metadataUrl} />
          <Copyable label="ACS (Reply / single sign-on) URL:" value={acs} />
          <Copyable label="SP metadata URL (available after creation):" value={metadataUrl} />
        </Subsection>
      </Section>
      <Section title="Create connection">
        <Form onSubmit={() => action.run(() => apiPost("/saml/connections", {
          providerId: sid, domain: f.values.domain.trim(), attributePreset: f.values.preset, provisioning: f.values.provisioning, ...metadata()
        }), { confirm: confirmations.saml.create(sid, f.values.domain), message: "Connection created (disabled)", after })}>
          <TextField label="Corporate email domain" placeholder="acme.example" {...f.text("domain")} />
          <SelectField label="Identity provider" value={f.values.preset} onChange={v => f.set("preset", v)} options={PRESETS} />
          <SelectField label="Account provisioning" value={f.values.provisioning} onChange={v => f.set("provisioning", v)} options={PROVISIONING} />
          <TextField label="IdP metadata URL (HTTPS)" placeholder="https://idp.example.com/app/metadata" {...f.text("metadataUrl")} />
          <AreaField label="or paste IdP metadata XML" rows={6} {...f.text("metadataXml")} />
          <Row>
            <Button type="button" variant="secondary" onClick={() => action.run(() => apiPost("/saml/preview", { providerId: sid, ...metadata() }), { message: "Metadata checked" })}>Check metadata</Button>
            <Button type="submit" variant="primary">Create disabled connection</Button>
          </Row>
        </Form>
      </Section>
      <Section title="Verify domain and enable">
        <Row>
          <Button variant="secondary" onClick={() => action.run(() => apiPost("/sso/token", { providerId: sid }), { message: "New TXT challenge" })}>Request new TXT challenge</Button>
          <Button variant="secondary" onClick={() => action.run(() => apiPost("/sso/verify", { providerId: sid }), { message: "Domain verified", after })}>Verify DNS ownership</Button>
          <Button variant="primary" onClick={() => typed("/saml/status", { providerId: sid, enabled: true }, confirmations.saml.status(sid, true))}>Enable connection</Button>
          <Button variant="secondary-destructive" onClick={() => typed("/saml/status", { providerId: sid, enabled: false }, confirmations.saml.status(sid, false))}>Disable connection</Button>
          <Button variant="secondary" onClick={() => typed("/saml/provisioning", { providerId: sid, provisioning: f.values.provisioning },
            confirmations.saml.provisioning(sid, f.values.provisioning))}>Apply provisioning mode</Button>
        </Row>
      </Section>
      <Section title="Certificate rotation" description={<Prose>
        Add the IdP's next signing certificate before the current one expires, switch the IdP to it, then retire the old certificate by its SHA-256 fingerprint.</Prose>}>
        <Form onSubmit={() => action.run(() => apiPost("/saml/certificates", { providerId: sid, certificate: f.values.nextCert }), { message: "Certificate trusted", after })}>
          <AreaField label="Next signing certificate (PEM)" rows={5} placeholder="-----BEGIN CERTIFICATE-----" {...f.text("nextCert")} />
          <Row><Button type="submit" variant="secondary">Trust next certificate</Button></Row>
        </Form>
        <Form onSubmit={() => typed("/saml/certificates/retire", { providerId: sid, sha256: f.values.retire.trim() }, confirmations.saml.retire(sid))}>
          <TextField label="Certificate fingerprint to retire (SHA-256)" placeholder="AB:CD:..." {...f.text("retire")} />
          <Row><Button type="submit" variant="secondary-destructive">Retire certificate</Button></Row>
        </Form>
      </Section>
      {action.view}
      <Section title="SAML connections">
        <Loaded state={list}>{(d: any) => {
          const warnings = (d.connections ?? []).flatMap((c: any) => (c.warnings ?? []).map((w: string) => c.providerId + ": " + w));
          return (
            <div className="nathan-stack">
              {!d.enterpriseSso ? <Notice title="Enterprise SSO is off" tone="alert">Set ENTERPRISE_SSO=true on the Worker before people can use these connections.</Notice> : null}
              {warnings.length ? <Notice title="Warnings" tone="alert"><ul className="nathan-studio-list">{warnings.map((w: string, i: number) => <li key={i}>{w}</li>)}</ul></Notice> : null}
              <DataTable label="SAML connections" empty="No SAML connections." rows={d.connections} rowKey={r => r.providerId}
                columns={[{ key: "providerId", label: "ID" }, { key: "domain", label: "Domain" }, { key: "attributePreset", label: "IdP" }, { key: "provisioning", label: "Provisioning" },
                  { key: "domainVerified", label: "Domain", render: r => <Badge variant={r.domainVerified ? "success" : "warning"}>{r.domainVerified ? "Verified" : "Unverified"}</Badge> },
                  { key: "enabled", label: "State", render: r => <Badge variant={r.enabled ? "success" : "neutral"}>{r.enabled ? "Enabled" : "Disabled"}</Badge> },
                  { key: "certificates", label: "Certificates", render: r => (r.certificates ?? []).length },
                  { key: "pick", label: "", render: r => <Button size="sm" variant="secondary" onClick={() => f.set("id", String(r.providerId))}>Select</Button> }]} />
            </div>
          );
        }}</Loaded>
        <Row><RefreshButton onClick={() => void list.reload()} label="Refresh SAML connections" /></Row>
      </Section>
    </Panel>
  );
}

// ---- SAML IdP ---------------------------------------------------------------------------------

const BITS = { "2048": "RSA 2048 (widest SP support)", "3072": "RSA 3072", "4096": "RSA 4096" } as const;
const NAMEID = { persistent: "Persistent pairwise opaque ID (recommended)", email: "Verified email address" } as const;

export function SamlIdp() {
  const overview = useLoad(() => apiGet("/saml-idp"));
  const action = useAction();
  const f = useFields({
    bits: "2048" as keyof typeof BITS, sha: "", mdUrl: "", mdXml: "", id: "", name: "", app: "", entity: "", acs: "",
    nameid: "persistent" as keyof typeof NAMEID, attrs: "", signed: false, certs: "", signResponse: false, passkey: false, idpInit: false, relay: ""
  });
  const v = f.values;
  const lines = (s: string) => s.split("\n").map(x => x.trim()).filter(Boolean);
  const sp = () => {
    const certificates = v.certs.split(/-----END CERTIFICATE-----/).map(s => s.trim()).filter(Boolean).map(s => s + "\n-----END CERTIFICATE-----");
    const acs = lines(v.acs).map(l => { const m = /^(\d{1,5})\s+(\S+)$/.exec(l); return m ? { index: Number(m[1]), url: m[2] } : { index: null, url: l }; });
    const indexed = acs.some(a => a.index !== null);
    return {
      id: v.id.trim(), name: v.name.trim(), appId: v.app.trim(), entityId: v.entity.trim(), acsUrls: acs.map(a => a.url),
      acsIndexes: indexed ? acs.map(a => a.index) : undefined, nameIdFormat: v.nameid,
      attributes: lines(v.attrs).map(l => { const i = l.lastIndexOf("="); return { name: l.slice(0, i).trim(), source: l.slice(i + 1).trim() }; }),
      wantRequestsSigned: v.signed, certificates, signResponse: v.signResponse, requirePasskey: v.passkey, allowIdpInitiated: v.idpInit,
      defaultRelayState: v.relay || null
    };
  };
  // As before, what the administrator types is sent as-is; the service checks it and audits a mismatch.
  const op = (body: Record<string, unknown>, c: confirmations.Confirmation) =>
    action.run(confirm => apiPost("/saml-idp", { ...body, confirm }), { confirm: c, message: "Done", after: () => { void overview.reload(); } });
  const preview = () => action.run(() => apiPost("/saml-idp", { op: "sp.preview", metadataUrl: v.mdUrl.trim() || undefined, metadataXml: v.mdXml.trim() || undefined }), {
    message: "Metadata read into the form",
    after: (r: any) => f.setValues(x => ({
      ...x, entity: r.entityId, acs: r.acsUrls.map((u: string, i: number) => r.acsIndexes[i] + " " + u).join("\n"), nameid: r.nameIdFormat,
      signed: Boolean(r.wantRequestsSigned),
      certs: r.certificates.map((c: string) => "-----BEGIN CERTIFICATE-----\n" + c + "\n-----END CERTIFICATE-----").join("\n")
    }))
  });
  return (
    <Panel title="SAML applications" description={<Prose>
      Nathan as a SAML 2.0 identity provider for AWS IAM Identity Center, Salesforce, Grafana and other SAML service providers (SPs). Every SP is bound
      to one Nathan application, and only people that application's roles and access allow can sign in (deny by default). New SPs start
      <strong> disabled</strong>. Every change needs the exact confirmation text and is audited. See <Code>docs/saml-idp.md</Code>.</Prose>}>
      <Section title="IdP values, keys and service providers">
        <Loaded state={overview}>{(d: any) => (
          <div className="nathan-stack">
            {d.warnings?.length ? <Notice title="Warnings" tone="alert"><ul className="nathan-studio-list">{d.warnings.map((w: string, i: number) => <li key={i}>{w}</li>)}</ul></Notice> : null}
            <JsonView value={d.idp} label="IdP values" />
            <DataTable label="Signing keys" empty="No signing keys yet." rows={d.keys}
              columns={[{ key: "status", label: "Status" }, { key: "bits", label: "Bits" }, { key: "sha256", label: "SHA-256" },
                { key: "notAfter", label: "Expires", render: r => when(r.notAfter) },
                { key: "activatableAt", label: "Activatable from", render: r => when(r.activatableAt) },
                { key: "pick", label: "", render: r => <Button size="sm" variant="secondary" onClick={() => f.set("sha", String(r.sha256))}>Select</Button> }]} />
            <DataTable label="Service providers" empty="No service providers." rows={d.serviceProviders}
              columns={[{ key: "id", label: "ID" }, { key: "name", label: "Name" }, { key: "appId", label: "Application" }, { key: "entityId", label: "Entity ID" },
                { key: "enabled", label: "State", render: r => <Badge variant={r.enabled ? "success" : "neutral"}>{r.enabled ? "Enabled" : "Disabled"}</Badge> }]} />
          </div>
        )}</Loaded>
        <Row><RefreshButton onClick={() => void overview.reload()} label="Show IdP values, keys and SPs" /></Row>
      </Section>
      <Section title="Signing keys" description={<Prose>
        The first key you generate becomes active. Later keys are published in metadata as <em>next</em>; activate one only after every SP has loaded
        the new metadata (at least 24 hours). The old key stays published as <em>previous</em> until you retire it. Private keys never leave the Worker.</Prose>}>
        <SelectField label="Key size" value={v.bits} onChange={x => f.set("bits", x)} options={BITS} />
        <Row><Button variant="primary" onClick={() => op({ op: "key.generate", bits: Number(v.bits) }, confirmations.samlIdp.generate())}>Generate signing key</Button></Row>
        <TextField label="Key SHA-256 fingerprint" placeholder="AB:CD:…" {...f.text("sha")} />
        <Row>
          <Button variant="secondary" onClick={() => op({ op: "key.activate", sha256: v.sha.trim() }, confirmations.samlIdp.activate())}>Activate next key</Button>
          <Button variant="secondary-destructive" onClick={() => op({ op: "key.retire", sha256: v.sha.trim() }, confirmations.samlIdp.retire())}>Retire key</Button>
        </Row>
      </Section>
      <Section title="Register a service provider">
        <TextField label="SP metadata URL (HTTPS)" placeholder="https://sp.example.com/saml/metadata" {...f.text("mdUrl")} />
        <AreaField label="or paste SP metadata XML" rows={5} {...f.text("mdXml")} />
        <Row><Button variant="secondary" onClick={() => void preview()}>Read metadata into the form</Button></Row>
        <Form onSubmit={() => { const s = sp(); op({ op: "sp.create", ...s }, confirmations.samlIdp.create(s.id)); }}>
          <TextField label="SP ID" placeholder="grafana" {...f.text("id")} />
          <TextField label="Display name" placeholder="Grafana" {...f.text("name")} />
          <TextField label="Bound Nathan application" placeholder="grafana" {...f.text("app")} />
          <TextField label="SP entity ID (Audience)" {...f.text("entity")} />
          <AreaField label={'ACS URLs (exact https, one per line, first is the default; optionally "index URL" to keep the SP metadata\'s AssertionConsumerServiceIndex, otherwise numbered 0, 1, ...)'} rows={3} {...f.text("acs")} />
          <SelectField label="NameID" value={v.nameid} onChange={x => f.set("nameid", x)} options={NAMEID} />
          <AreaField label="Attributes (one per line: AttributeName=source; sources email, name, roles, groups, permissions, persistent_id)" rows={4}
            placeholder={"email=email\ndisplayName=name\nrole=roles"} {...f.text("attrs")} />
          <CheckField label="Require signed AuthnRequests" {...f.check("signed")} />
          <AreaField label="SP signing certificates (PEM, required for signed AuthnRequests)" rows={4} {...f.text("certs")} />
          <CheckField label="Also sign the Response (the Assertion is always signed)" {...f.check("signResponse")} />
          <CheckField label="Require a passkey sign-in (verified evidence only)" {...f.check("passkey")} />
          <CheckField label="Allow IdP-initiated sign-in (off by default; unsolicited responses are easier to misuse)" {...f.check("idpInit")} />
          <TextField label="Default RelayState for IdP-initiated sign-in (optional)" {...f.text("relay")} />
          <Row>
            <Button type="submit" variant="primary">Create disabled SP</Button>
            <Button type="button" variant="secondary" onClick={() => { const s = sp(); op({ op: "sp.update", ...s }, confirmations.samlIdp.update(s.id)); }}>Update SP</Button>
            <Button type="button" variant="secondary" onClick={() => { const id = v.id.trim(); op({ op: "sp.status", id, enabled: true }, confirmations.samlIdp.status(id, true)); }}>Enable SP</Button>
            <Button type="button" variant="secondary-destructive" onClick={() => { const id = v.id.trim(); op({ op: "sp.status", id, enabled: false }, confirmations.samlIdp.status(id, false)); }}>Disable SP</Button>
          </Row>
        </Form>
      </Section>
      {action.view}
    </Panel>
  );
}
