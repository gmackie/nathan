/**
 * NATH-38: the interactive part of /security, rendered by the Worker and hydrated by the
 * `security` island (src/ui/islands/security.tsx). One island for the whole panel: administrator
 * onboarding, TOTP enrolment and passkeys.
 *
 * - Every button is disabled in the server markup and enabled once React hydrates, so nothing
 *   looks usable without its script.
 * - The "Add to built-in authenticator" link has no href in the server markup. Its href is only
 *   ever authenticatorLink()'s result (src/auth/totp-link.mjs: otpauth://totp only, or null).
 * - The QR is inline SVG drawn from /security/api/totp-qr's module matrix, so img-src stays 'none'.
 * - All server-supplied text (status, passkey names, recovery codes) is rendered as React text.
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Banner } from "@cloudflare/kumo/components/banner";
import { Button, LinkButton } from "@cloudflare/kumo/components/button";
import { Input } from "@cloudflare/kumo/components/input";
import { Label } from "@cloudflare/kumo/components/label";
import { Link } from "@cloudflare/kumo/components/link";
import { LayerCard } from "@cloudflare/kumo/components/layer-card";
import { CheckCircle } from "@phosphor-icons/react/dist/ssr/CheckCircle";
import { Copy } from "@phosphor-icons/react/dist/ssr/Copy";
import { DeviceMobile } from "@phosphor-icons/react/dist/ssr/DeviceMobile";
import { Fingerprint } from "@phosphor-icons/react/dist/ssr/Fingerprint";
import { Info } from "@phosphor-icons/react/dist/ssr/Info";
import { Key } from "@phosphor-icons/react/dist/ssr/Key";
import { ListBullets } from "@phosphor-icons/react/dist/ssr/ListBullets";
import { ShieldCheck } from "@phosphor-icons/react/dist/ssr/ShieldCheck";
import { Usb } from "@phosphor-icons/react/dist/ssr/Usb";
import { XCircle } from "@phosphor-icons/react/dist/ssr/XCircle";
import type { IconProps } from "@phosphor-icons/react";
import type { ComponentType } from "react";
import { authenticatorLink } from "../../../auth/totp-link.mjs";
import { ICON_SIZE, ICON_WEIGHT, iconA11y } from "../../icon-defaults.ts";
import {
  addPasskey, bootstrapStatus, completeBootstrap, enableTotp, listPasskeys, passkeyStepUp, qrPath, totpQr, totpSecret,
  verifyTotp, type BootstrapStatus, type PasskeySummary, type QrMatrix
} from "./security-client.ts";

export type SecurityPanelProps = Record<string, never>;

type Tone = "info" | "success" | "error";
interface Message { tone: Tone; text: string; lines?: string[] }

const icon = (Icon: ComponentType<IconProps>, size = ICON_SIZE) => <Icon size={size} weight={ICON_WEIGHT} {...iconA11y()} />;
const errorText = (e: unknown) => e instanceof Error ? e.message : String(e);

const S = {
  card: { padding: 20, display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 14, minWidth: 0 },
  heading: { display: "flex", alignItems: "center", gap: 10, margin: 0, fontSize: 18, lineHeight: 1.3, fontWeight: 600 },
  subheading: { margin: 0, fontSize: 15, fontWeight: 600 },
  actions: { display: "flex", flexWrap: "wrap", gap: 8 },
  steps: { margin: 0, paddingLeft: 20, display: "grid", gap: 6, lineHeight: 1.5 },
  mono: { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 15, letterSpacing: "0.04em", overflowWrap: "anywhere" },
  codes: { margin: 0, paddingLeft: 28, display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(120px, 1fr))", gap: "4px 16px",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 15 },
  qr: { display: "grid", placeItems: "center", padding: 8 },
  list: { margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 8 },
  muted: { margin: 0, lineHeight: 1.5, opacity: 0.8 },
  /** A long label wraps inside the card at 375px instead of overflowing it. */
  wrapButton: { width: "100%", maxWidth: "100%", flexShrink: 1, height: "auto", minHeight: 36, paddingBlock: 8, whiteSpace: "normal", textAlign: "left" }
} as const;

function Section({ id, title, icon: Icon, children, hidden }: { id?: string; title: string; icon: ComponentType<IconProps>; children: ReactNode; hidden?: boolean }) {
  return (
    <LayerCard render={<section />} id={id} hidden={hidden} style={hidden ? { ...S.card, display: "none" } : S.card} aria-labelledby={id ? id + "-title" : undefined}>
      <h2 id={id ? id + "-title" : undefined} style={S.heading}>{icon(Icon, 22)}{title}</h2>
      {children}
    </LayerCard>
  );
}

/**
 * Kumo Label + Input with fixed ids. Input's own `label` prop takes React useId ids, which differ
 * between the full-page server render and the island-only hydration.
 */
function TextField({ id, label, children }: { id: string; label: string; children: ReactNode }) {
  return (
    <div style={{ display: "grid", gap: 6 }}>
      <Label htmlFor={id}>{label}</Label>
      {children}
    </div>
  );
}

function Status({ id, message }: { id: string; message: Message | null }) {
  // The live region is always present so screen readers announce later updates.
  return (
    <div id={id} role="status" aria-live="polite">
      {message ? (
        <Banner
          variant={message.tone === "error" ? "error" : "default"}
          icon={icon(message.tone === "error" ? XCircle : message.tone === "success" ? CheckCircle : Info)}
          description={message.lines ? (
            <>
              <span>{message.text}</span>
              <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>{message.lines.map(line => <li key={line}>{line}</li>)}</ul>
            </>
          ) : message.text}
        />
      ) : null}
    </div>
  );
}

function QrCode({ matrix }: { matrix: QrMatrix }) {
  const { full, d } = qrPath(matrix);
  return (
    <svg viewBox={"0 0 " + full + " " + full} width="224" height="224" shapeRendering="crispEdges" aria-hidden="true">
      <rect width={full} height={full} fill="#fff" />
      <path d={d} fill="#000" />
    </svg>
  );
}

export function SecurityPanel(_props: SecurityPanelProps) {
  const [hydrated, setHydrated] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const [admin, setAdmin] = useState<BootstrapStatus | null>(null);
  const [adminMessage, setAdminMessage] = useState<Message | null>(null);
  const [stepCode, setStepCode] = useState("");

  // TOTP
  const passwordInput = useRef<HTMLInputElement>(null);
  const [totpUri, setTotpUri] = useState<string | null>(null);
  const [qr, setQr] = useState<QrMatrix | null | "unavailable">(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  const [totpMessage, setTotpMessage] = useState<Message | null>(null);

  // Passkeys
  const [passkeyMessage, setPasskeyMessage] = useState<Message | null>(null);
  const [passkeys, setPasskeys] = useState<PasskeySummary[] | null>(null);

  useEffect(() => {
    setHydrated(true);
    void bootstrapStatus().then(setAdmin).catch(() => {
      if (new URLSearchParams(location.search).get("setup") === "admin")
        setAdminMessage({tone:"error",text:"Could not load your setup requirements. Try again."});
    });
  }, []);

  const run = (name: string, work: () => Promise<void>) => async () => {
    setBusy(name);
    try { await work(); } finally { setBusy(null); }
  };
  const disabled = (name: string) => !hydrated || busy === name;

  const checkStatus = run("admin-status", async () => {
    try { setAdmin(await bootstrapStatus()); setAdminMessage(null); }
    catch (e) { setAdminMessage({ tone: "error", text: errorText(e) }); }
  });

  const finishSetup = run("admin-finish", async () => {
    try {
      await completeBootstrap();
      const status = await bootstrapStatus();
      if (status.sessionReady) location.assign("/studio/users");
      else { setAdmin(status); setAdminMessage({tone:"success",text:"Setup complete. Verify your session to open Studio."}); }
    } catch (e) { setAdminMessage({ tone: "error", text: errorText(e) }); }
  });

  const stepUp = run("admin-stepup", async () => {
    try {
      await passkeyStepUp();
      const status = await bootstrapStatus();
      if (status.sessionReady) location.assign("/studio/users");
      else { setAdmin(status); setAdminMessage({tone:"success",text:"Passkey verified."}); }
    } catch (e) { setAdminMessage({ tone: "error", text: errorText(e) }); }
  });

  const verifyForStudio = run("admin-code", async () => {
    try {
      await verifyTotp(stepCode);
      setStepCode("");
      const status = await bootstrapStatus();
      if (status.sessionReady) location.assign("/studio/users");
      else { setAdmin(status); setAdminMessage({tone:"info",text:"Code verified. Check the remaining setup requirements."}); }
    } catch (e) { setAdminMessage({tone:"error",text:errorText(e)}); }
  });

  const startTotp = run("totp-start", async () => {
    try {
      // Autofill or typing can populate the server-rendered field before hydration.
      const result = await enableTotp(passwordInput.current?.value ?? "");
      const uri = String(result.totpURI || "");
      setTotpUri(uri);
      setQr(null);
      setRecoveryCodes(Array.isArray(result.backupCodes) ? result.backupCodes.map(String) : []);
      setTotpMessage({ tone: "info", text: "Enter the 6-digit code to verify enrollment." });
      setQr((await totpQr(uri)) ?? "unavailable");
    } catch (e) { setTotpMessage({ tone: "error", text: errorText(e) }); }
  });

  const { secret, grouped } = totpSecret(totpUri ?? "");
  // The only href the built-in authenticator link ever gets.
  const openHref = totpUri ? authenticatorLink(totpUri) : null;

  const copy = async (text: string, done: string) => {
    try { await navigator.clipboard.writeText(text); setTotpMessage({ tone: "success", text: done }); }
    catch { setTotpMessage({ tone: "error", text: "Copy failed; select the text and copy it manually." }); }
  };

  const verify = run("totp-verify", async () => {
    try {
      await verifyTotp(code);
      setCode("");
      setTotpMessage({ tone: "success", text: "TOTP enrollment verified." });
      setAdmin(await bootstrapStatus());
    } catch (e) { setTotpMessage({ tone: "error", text: errorText(e) }); }
  });

  const enrol = (name: string, attachment: "" | "cross-platform", label: string) => run(name, async () => {
    try {
      await addPasskey(attachment, label);
      setPasskeyMessage({ tone: "success", text: label + " successfully enrolled." });
      setAdmin(await bootstrapStatus());
    } catch (e) { setPasskeyMessage({ tone: "error", text: errorText(e) }); }
  });

  const list = run("passkey-list", async () => {
    try {
      const keys = await listPasskeys();
      setPasskeys(keys);
      setPasskeyMessage(keys.length ? null : { tone: "info", text: "No passkeys enrolled yet." });
    } catch (e) { setPasskeyMessage({ tone: "error", text: errorText(e) }); }
  });

  return (
    <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 16 }}>
      <Section id="admin-setup" title={admin?.state === "complete" ? "Administrator access" : "Administrator setup"}
        icon={ShieldCheck} hidden={!admin?.isAdministrator && !adminMessage}>
        {admin && !admin.ready && <p style={S.muted}>{admin.requirements?.totp && admin.requirements.passkey
          ? "Enroll a passkey and verify an authenticator app below."
          : admin.requirements?.passkey ? "Enroll a passkey below." : "Choose either an authenticator app or a passkey below."}</p>}
        {admin?.isInitialAdmin && admin.state !== "complete" &&
          <Button id="admin-finish" variant="primary" disabled={!admin.ready || disabled("admin-finish")} onClick={finishSetup}>Complete initial setup</Button>}
        {admin?.sessionReady && <Link href="/studio/users">Open user management</Link>}
        {!admin?.sessionReady && admin?.totpVerified && admin.managementTotp &&
          (admin.requirements?.stepUp === "passkey-or-totp" || !admin.passkeys) &&
          <form className="nathan-stack" onSubmit={event => { event.preventDefault(); void verifyForStudio(); }}>
            {admin.requirements?.stepUp === "passkey" && <p>Verify your code, then add your first passkey below.</p>}
            <TextField id="admin-code" label="Authenticator code for Studio">
              <Input id="admin-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} disabled={!hydrated}
                required value={stepCode} onChange={event => setStepCode(event.currentTarget.value)} />
            </TextField>
            <Button type="submit" disabled={disabled("admin-code")}>Verify code</Button>
          </form>}
        {Boolean(admin?.passkeys) && !admin?.sessionReady && <div style={S.actions}>
          <Button id="admin-stepup" variant="secondary" style={S.wrapButton} icon={icon(Fingerprint)} disabled={disabled("admin-stepup")} onClick={stepUp}>
            Reauthenticate with passkey for administration
          </Button>
        </div>}
        <Status id="admin-setup-status" message={adminMessage} />
        <Button id="admin-status" variant="ghost" disabled={disabled("admin-status")} onClick={checkStatus}>Refresh setup status</Button>
      </Section>

      <Section id="totp" title="Authenticator application (TOTP)" icon={DeviceMobile}>
        {admin?.managementHost ? <p style={S.muted}>
          Use an authenticator app for six-digit codes. If you lose your only Studio authenticator, contact your Cloudflare account operator for recovery.
        </p> : <p style={S.muted}>
          Enroll and confirm an authenticator app, then store backup codes offline. Nathan only asserts MFA assurance after an actual
          verified authentication ceremony; enabling TOTP alone does not force MFA on social logins.
        </p>}
        <TextField id="password" label="Password (if this account uses password login)">
          <Input id="password" aria-label="Password" type="password" autoComplete="current-password" ref={passwordInput} />
        </TextField>
        <div style={S.actions}>
          <Button id="totp-start" variant="primary" disabled={disabled("totp-start")} onClick={startTotp}>Start TOTP enrollment</Button>
        </div>

        <div id="totp-enroll" hidden={totpUri == null} style={{ display: totpUri == null ? "none" : "grid", gap: 14 }}>
          <h3 style={S.subheading}>Setting up on this phone?</h3>
          <div style={{ display: "grid", gap: 8 }}>
            <p style={{ margin: 0 }}><strong>Google Authenticator, Microsoft Authenticator or 1Password:</strong></p>
            <div style={S.actions}>
              <Button id="totp-copy" type="button" variant="primary" icon={icon(Copy)} disabled={!hydrated || !secret}
                onClick={() => copy(secret, "Key copied. Paste it into your authenticator app, then enter the 6-digit code.")}>Copy key</Button>
            </div>
            <ol style={S.steps}>
              <li>In the app tap <strong>+</strong>.</li>
              <li>Choose <strong>Enter a setup key</strong> and paste the key.</li>
              <li>Keep <strong>Time based</strong> and save.</li>
            </ol>
          </div>
          <div style={{ display: "grid", gap: 8 }}>
            <p style={{ margin: 0 }}><strong>Your phone&apos;s built-in code app:</strong></p>
            <div style={S.actions}>
              <LinkButton id="totp-open" variant="secondary" href={openHref ?? undefined} hidden={!openHref}>Add to built-in authenticator</LinkButton>
            </div>
            <p style={S.muted}>On iPhone this always opens Apple Passwords (iOS sends these links there, not to Google Authenticator); on Android it opens the app that handles authenticator links.</p>
          </div>
          <p style={{ margin: 0 }}>Then come back to this page and enter the 6-digit code the app shows.</p>

          <h3 style={S.subheading}>On a computer?</h3>
          <p style={S.muted}>Scan this code with your phone&apos;s authenticator app (or Yubico Authenticator for a YubiKey):</p>
          <div id="totp-qr" role="img" aria-label="TOTP enrollment QR code" style={S.qr}>
            {qr && qr !== "unavailable" ? <QrCode matrix={qr} /> : null}
            {qr === "unavailable" ? <span>QR code unavailable; enter the key manually.</span> : null}
          </div>
          <div style={{ display: "grid", gap: 4 }}>
            <span>Setup key (time-based, 6 digits):</span>
            <code id="totp-secret" style={S.mono}>{grouped}</code>
          </div>

          <div id="totp-setup" style={{ display: recoveryCodes && !admin?.managementHost ? "grid" : "none", gap: 8 }}>
            <Banner variant="alert" icon={icon(Key)} title="Recovery codes"
              description="Shown once. Copy them to a secure offline manager now; each code works one time." />
            {recoveryCodes && recoveryCodes.length ? (
              <>
                <ol id="recovery-codes" style={S.codes}>{recoveryCodes.map(c => <li key={c}>{c}</li>)}</ol>
                <div style={S.actions}>
                  <Button id="recovery-copy" type="button" variant="secondary" icon={icon(Copy)} disabled={!hydrated}
                    onClick={() => copy(recoveryCodes.join("\n"), "Recovery codes copied. Store them offline.")}>Copy recovery codes</Button>
                </div>
              </>
            ) : null}
          </div>
        </div>

        <TextField id="totp-code" label="Six-digit code">
          <Input id="totp-code" aria-label="Six-digit code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={!hydrated}
            maxLength={6} value={code} onChange={e => setCode(e.currentTarget.value)} />
        </TextField>
        <div style={S.actions}>
          <Button id="totp-verify" variant="primary" disabled={disabled("totp-verify")} onClick={verify}>Verify TOTP</Button>
        </div>
        <Status id="totp-status" message={totpMessage} />
      </Section>

      <Section id="passkeys-section" title="Passkeys" icon={Fingerprint}>
        <p style={S.muted}>Use a platform authenticator or hardware security key. Passkeys may be used as a login method.</p>
        <div style={S.actions}>
          <Button id="passkey-add" variant="primary" icon={icon(Fingerprint)} disabled={disabled("passkey-add")}
            onClick={enrol("passkey-add", "", "Passkey")}>Add passkey</Button>
          <Button id="security-key-add" variant="secondary" icon={icon(Usb)} disabled={disabled("security-key-add")}
            onClick={enrol("security-key-add", "cross-platform", "Security key")}>Add security key (YubiKey)</Button>
          <Button id="passkey-list" variant="ghost" icon={icon(ListBullets)} disabled={disabled("passkey-list")}
            onClick={list}>List my passkeys</Button>
        </div>
        <Status id="passkeys" message={passkeyMessage} />
        {passkeys && passkeys.length ? (
          <ul id="passkey-items" style={S.list}>
            {passkeys.map((k, n) => (
              <li key={k.id ?? n}>
                <LayerCard style={{ padding: "10px 12px", display: "flex", gap: 10, alignItems: "center" }}>
                  {icon(Key)}
                  <span style={{ display: "grid", minWidth: 0 }}>
                    <strong style={{ overflowWrap: "anywhere" }}>{k.name || "Unnamed passkey"}</strong>
                    <span style={{ fontSize: 13, opacity: 0.8 }}>
                      {[k.deviceType === "multiDevice" ? "Synced" : k.deviceType === "singleDevice" ? "Device-bound" : null,
                        k.backedUp ? "backed up" : null,
                        k.createdAt ? "added " + new Date(k.createdAt).toLocaleDateString() : null].filter(Boolean).join(" · ")}
                    </span>
                  </span>
                </LayerCard>
              </li>
            ))}
          </ul>
        ) : null}
      </Section>
    </div>
  );
}
