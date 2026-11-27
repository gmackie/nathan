/**
 * NATH-39: Identity Studio, a Kumo React SPA in one island (src/ui/islands/studio.tsx).
 *
 * The server renders this component inside renderPage() (src/ui/pages/studio/StudioPage.tsx) with
 * the Overview panel; the island hydrates it and then follows the URL hash (#/users, #/scim, ...).
 * Panels talk only to the typed JSON API at /studio/api/v1 (./api.ts), which enforces admin,
 * step-up, same-origin and audit for every call. The props carry no secrets: only the email of
 * the signed-in administrator.
 */
import { useEffect, useState, type ComponentType, type ReactElement } from "react";
import { Banner } from "@cloudflare/kumo/components/banner";
import { LinkButton } from "@cloudflare/kumo/components/button";
import { Sidebar } from "@cloudflare/kumo/components/sidebar";
import { AppWindow } from "@phosphor-icons/react/dist/ssr/AppWindow";
import { ArrowsClockwise } from "@phosphor-icons/react/dist/ssr/ArrowsClockwise";
import { Buildings } from "@phosphor-icons/react/dist/ssr/Buildings";
import { ClipboardText } from "@phosphor-icons/react/dist/ssr/ClipboardText";
import { Envelope } from "@phosphor-icons/react/dist/ssr/Envelope";
import { Globe } from "@phosphor-icons/react/dist/ssr/Globe";
import { House } from "@phosphor-icons/react/dist/ssr/House";
import { IdentificationCard } from "@phosphor-icons/react/dist/ssr/IdentificationCard";
import { Info } from "@phosphor-icons/react/dist/ssr/Info";
import { Key } from "@phosphor-icons/react/dist/ssr/Key";
import { Plug } from "@phosphor-icons/react/dist/ssr/Plug";
import { ShieldCheck } from "@phosphor-icons/react/dist/ssr/ShieldCheck";
import { ShieldStar } from "@phosphor-icons/react/dist/ssr/ShieldStar";
import { SignIn } from "@phosphor-icons/react/dist/ssr/SignIn";
import { Ticket } from "@phosphor-icons/react/dist/ssr/Ticket";
import { User } from "@phosphor-icons/react/dist/ssr/User";
import { ICON_SIZE, ICON_WEIGHT, iconA11y } from "../../icon-defaults.ts";
import { apiGet } from "./api.ts";
import { ConfirmProvider } from "./kit.tsx";
import { Admins } from "./panels/Admins.tsx";
import { Applications } from "./panels/Applications.tsx";
import { Domains } from "./panels/Domains.tsx";
import { Mcp } from "./panels/Mcp.tsx";
import { Overview } from "./panels/Overview.tsx";
import { Admission, Audit, Users } from "./panels/People.tsx";
import { Providers } from "./panels/Providers.tsx";
import { Roles } from "./panels/Roles.tsx";
import { Scim } from "./panels/Scim.tsx";
import { EnterpriseOidc, SamlConnections, SamlIdp } from "./panels/Sso.tsx";
import { Tokens } from "./panels/Tokens.tsx";

export interface StudioAppProps {
  /** The signed-in administrator (display only). */
  email: string;
  classCheck?: boolean;
}

type IconType = ComponentType<{ className?: string }>;
const ic = (Icon: typeof House): IconType => ({ className }) => <Icon size={ICON_SIZE} weight={ICON_WEIGHT} className={className} {...iconA11y()} />;

interface PanelDef { id: string; label: string; icon: IconType; render: (p: StudioAppProps & { refreshNotice: () => void }) => ReactElement }

export const STUDIO_NAV: { group: string; panels: PanelDef[] }[] = [
  { group: "Instance", panels: [
    { id: "overview", label: "Overview", icon: ic(House), render: p => <Overview email={p.email} /> },
    { id: "admins", label: "Administrators", icon: ic(ShieldStar), render: p => <Admins classCheck={p.classCheck} /> },
    { id: "audit", label: "Audit log", icon: ic(ClipboardText), render: () => <Audit /> }
  ] },
  { group: "Applications", panels: [
    { id: "applications", label: "Applications", icon: ic(AppWindow), render: () => <Applications /> },
    { id: "roles", label: "Roles and access", icon: ic(ShieldCheck), render: () => <Roles /> },
    { id: "domains", label: "Protected apps and domains", icon: ic(Globe), render: () => <Domains /> },
    { id: "tokens", label: "Access tokens", icon: ic(Ticket), render: () => <Tokens /> },
    { id: "mcp", label: "MCP servers", icon: ic(Plug), render: () => <Mcp /> }
  ] },
  { group: "People", panels: [
    { id: "users", label: "Users", icon: ic(User), render: () => <Users /> },
    { id: "admission", label: "Admission and invitations", icon: ic(Envelope), render: p => <Admission onNoticeChange={p.refreshNotice} /> }
  ] },
  { group: "Connections", panels: [
    { id: "providers", label: "Social providers", icon: ic(SignIn), render: () => <Providers /> },
    { id: "sso", label: "Enterprise SSO (OIDC)", icon: ic(Buildings), render: () => <EnterpriseOidc /> },
    { id: "saml", label: "Enterprise SAML", icon: ic(IdentificationCard), render: () => <SamlConnections /> },
    { id: "saml-idp", label: "SAML applications", icon: ic(Key), render: () => <SamlIdp /> },
    { id: "scim", label: "SCIM directories", icon: ic(ArrowsClockwise), render: () => <Scim /> }
  ] }
];

const PANELS = new Map(STUDIO_NAV.flatMap(g => g.panels).map(p => [p.id, p]));
const DEFAULT_PANEL = "overview";

/** "#/scim" → "scim"; anything else (including in-page anchors) keeps the current panel. */
export function panelFromHash(hash: string): string | null {
  const m = /^#\/([a-z-]{1,40})$/.exec(hash);
  return m && PANELS.has(m[1]) ? m[1] : null;
}

export function StudioApp({ email, classCheck }: StudioAppProps) {
  const [panel, setPanel] = useState(DEFAULT_PANEL);
  const [notice, setNotice] = useState<string | null>(null);
  useEffect(() => {
    const follow = () => { const p = panelFromHash(location.hash); if (p) { setPanel(p); window.scrollTo(0, 0); } };
    follow();
    addEventListener("hashchange", follow);
    return () => removeEventListener("hashchange", follow);
  }, []);
  // NATH-16: the one-time admission upgrade notice; quietly absent when it cannot be read.
  const refreshNotice = () => {
    apiGet("/admission").then((v: any) => setNotice(typeof v?.upgradeNotice === "string" ? v.upgradeNotice : null)).catch(() => setNotice(null));
  };
  useEffect(refreshNotice, []);
  const current = PANELS.get(panel) ?? PANELS.get(DEFAULT_PANEL)!;
  return (
    <ConfirmProvider>
      <Sidebar.Provider defaultOpen collapsible="offcanvas" mobileBreakpoint={768}>
        <Sidebar aria-label="Identity Studio">
          <Sidebar.Header>
            <span className="nathan-mark">Nathan · Identity Studio</span>
          </Sidebar.Header>
          <Sidebar.Content>
            {STUDIO_NAV.map(g => (
              <Sidebar.Group key={g.group}>
                <Sidebar.GroupLabel>{g.group}</Sidebar.GroupLabel>
                <Sidebar.Menu>
                  {g.panels.map(p => (
                    <Sidebar.MenuItem key={p.id}>
                      <Sidebar.MenuButton href={"#/" + p.id} icon={p.icon} active={p.id === current.id}
                        aria-current={p.id === current.id ? "page" : undefined}>{p.label}</Sidebar.MenuButton>
                    </Sidebar.MenuItem>
                  ))}
                </Sidebar.Menu>
              </Sidebar.Group>
            ))}
          </Sidebar.Content>
          <Sidebar.Footer>
            <LinkButton href="/studio/users" variant="secondary" size="sm">Manage users</LinkButton>
            <LinkButton href="/security" variant="ghost" size="sm">My security</LinkButton>
            <LinkButton href="/sign-in" variant="ghost" size="sm">Switch identity</LinkButton>
          </Sidebar.Footer>
        </Sidebar>
        <main className="nathan-studio-main" id="studio-main">
          <div className="nathan-studio-topbar">
            <Sidebar.Trigger />
            <span className="nathan-studio-muted">{current.label}</span>
            <span className="nathan-studio-muted nathan-studio-email" data-nathan-admin-email="">{email}</span>
          </div>
          {notice ? (
            <Banner variant="alert" icon={<Info size={ICON_SIZE} weight={ICON_WEIGHT} {...iconA11y()} />} title="Account admission changed"
              description={notice} action={<LinkButton href="#/admission" variant="secondary" size="sm">Choose the admission mode</LinkButton>} />
          ) : null}
          {current.render({ email, classCheck, refreshNotice })}
        </main>
      </Sidebar.Provider>
    </ConfirmProvider>
  );
}
