/**
 * NATH-39: the small toolkit every Studio panel is built from. Stock Kumo components only
 * (DESIGN.md: Studio is an Operate surface and is never themed), structure classes from
 * src/ui/layout.css, Phosphor icons. Everything renders through React, so API data is always
 * escaped text; nothing here injects raw HTML.
 */
import { createContext, useCallback, useContext, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Banner } from "@cloudflare/kumo/components/banner";
import { Button, LinkButton } from "@cloudflare/kumo/components/button";
import { Checkbox } from "@cloudflare/kumo/components/checkbox";
import { Dialog } from "@cloudflare/kumo/components/dialog";
import { Input, InputArea } from "@cloudflare/kumo/components/input";
import { LayerCard } from "@cloudflare/kumo/components/layer-card";
import { Select } from "@cloudflare/kumo/components/select";
import { Table } from "@cloudflare/kumo/components/table";
import { CheckCircle } from "@phosphor-icons/react/dist/ssr/CheckCircle";
import { Info } from "@phosphor-icons/react/dist/ssr/Info";
import { Key } from "@phosphor-icons/react/dist/ssr/Key";
import { Warning } from "@phosphor-icons/react/dist/ssr/Warning";
import { XCircle } from "@phosphor-icons/react/dist/ssr/XCircle";
import { ICON_SIZE, ICON_WEIGHT, iconA11y } from "../../icon-defaults.ts";
import { ApiError } from "./api.ts";
import type { Confirmation } from "./confirmations.ts";

const icon = (Icon: typeof Info) => <Icon size={ICON_SIZE} weight={ICON_WEIGHT} {...iconA11y()} />;

// ---- Layout -------------------------------------------------------------------------------------

export function Panel({ title, description, children }: { title: string; description?: ReactNode; children?: ReactNode }) {
  return (
    <section className="nathan-studio-panel" aria-labelledby="studio-panel-title">
      <header className="nathan-studio-panel-header">
        <h1 id="studio-panel-title" className="nathan-title">{title}</h1>
        {description ? <div className="nathan-studio-prose">{description}</div> : null}
      </header>
      {children}
    </section>
  );
}

export function Section({ title, description, children }: { title: string; description?: ReactNode; children?: ReactNode }) {
  return (
    <LayerCard className="nathan-studio-section">
      <LayerCard.Secondary>
        <h2 className="nathan-studio-section-title">{title}</h2>
      </LayerCard.Secondary>
      <LayerCard.Primary className="nathan-studio-section-body">
        {description ? <div className="nathan-studio-prose">{description}</div> : null}
        {children}
      </LayerCard.Primary>
    </LayerCard>
  );
}

export function Subsection({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="nathan-stack">
      <h3 className="nathan-studio-subtitle">{title}</h3>
      {children}
    </div>
  );
}

export function Row({ children }: { children?: ReactNode }) {
  return <div className="nathan-actions">{children}</div>;
}

export function Prose({ children }: { children?: ReactNode }) {
  return <p className="nathan-text">{children}</p>;
}

export function Code({ children }: { children?: ReactNode }) {
  return <code className="nathan-studio-code">{children}</code>;
}

/** Pretty JSON as escaped text (for detail views and API results). */
export function JsonView({ value, label }: { value: unknown; label?: string }) {
  if (value === undefined) return null;
  return <pre className="nathan-studio-json" aria-label={label}>{JSON.stringify(value, null, 2)}</pre>;
}

/** A form that never navigates; submit runs `onSubmit`. */
export function Form({ onSubmit, children }: { onSubmit: () => void; children?: ReactNode }) {
  return (
    <form className="nathan-stack" noValidate onSubmit={(e: FormEvent) => { e.preventDefault(); onSubmit(); }}>
      {children}
    </form>
  );
}

// ---- Fields -------------------------------------------------------------------------------------

export function TextField(props: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string; type?: string;
  description?: ReactNode; autoComplete?: string; id?: string; min?: number; max?: number; step?: number
}) {
  const { label, value, onChange, type = "text", autoComplete = "off", ...rest } = props;
  return <Input label={label} type={type} value={value} autoComplete={autoComplete} spellCheck={false}
    onChange={e => onChange(e.target.value)} {...rest} />;
}

export function AreaField(props: { label: string; value: string; onChange: (v: string) => void; placeholder?: string; rows?: number; description?: ReactNode }) {
  const { label, value, onChange, rows = 5, ...rest } = props;
  return <InputArea label={label} value={value} rows={rows} spellCheck={false} onValueChange={onChange} {...rest} />;
}

export function SelectField<T extends string>(props: { label: string; value: T; onChange: (v: T) => void; options: Record<T, string>; description?: ReactNode; id?: string }) {
  const { label, value, onChange, options, description, id } = props;
  return (
    <Select<T> label={label} value={value} id={id} description={description} items={options}
      onValueChange={v => { if (v !== null) onChange(v as T); }}>
      {(Object.keys(options) as T[]).map(k => <Select.Option key={k} value={k}>{options[k]}</Select.Option>)}
    </Select>
  );
}

export function CheckField({ label, checked, onChange }: { label: ReactNode; checked: boolean; onChange: (v: boolean) => void }) {
  return <Checkbox label={label} checked={checked} onCheckedChange={v => onChange(v === true)} />;
}

/** Form state for a flat object of fields. */
type Widen<T> = { [K in keyof T]: T[K] extends boolean ? boolean : T[K] };

export function useFields<I extends Record<string, string | boolean>>(initial: I) {
  type T = Widen<I>;
  const [values, setValues] = useState<T>(initial as T);
  const set = useCallback(<K extends keyof T>(key: K, value: T[K]) => setValues(v => ({ ...v, [key]: value })), []);
  const text = (key: { [K in keyof T]: T[K] extends string ? K : never }[keyof T]) => ({
    value: values[key] as string, onChange: (v: string) => set(key, v as T[typeof key])
  });
  const check = (key: { [K in keyof T]: T[K] extends boolean ? K : never }[keyof T]) => ({
    checked: values[key] as boolean, onChange: (v: boolean) => set(key, v as T[typeof key])
  });
  return { values, set, text, check, setValues };
}

// ---- Tables -------------------------------------------------------------------------------------

export interface Column { key: string; label: string; render?: (row: any) => ReactNode }

const cell = (value: unknown): ReactNode => {
  if (value === null || value === undefined || value === "") return <span className="nathan-studio-muted">—</span>;
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
};

export function DataTable({ columns, rows, empty, label, rowKey }: {
  columns: Column[]; rows: any[] | undefined; empty: string; label: string; rowKey?: (row: any, i: number) => string
}) {
  if (!rows) return null;
  if (!rows.length) return <p className="nathan-text nathan-studio-muted">{empty}</p>;
  return (
    <div className="nathan-studio-table" role="region" aria-label={label} tabIndex={0}>
      <Table>
        <Table.Header>
          <Table.Row>{columns.map(c => <Table.Head key={c.key}>{c.label}</Table.Head>)}</Table.Row>
        </Table.Header>
        <Table.Body>
          {rows.map((row, i) => (
            <Table.Row key={rowKey ? rowKey(row, i) : String(row.id ?? i)}>
              {columns.map(c => <Table.Cell key={c.key}>{c.render ? c.render(row) : cell(row[c.key])}</Table.Cell>)}
            </Table.Row>
          ))}
        </Table.Body>
      </Table>
    </div>
  );
}

/** Unix seconds or an ISO/SQL timestamp as "YYYY-MM-DD HH:MM UTC". */
export function when(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  const date = typeof value === "number" ? new Date(value < 1e12 ? value * 1000 : value) : new Date(String(value).replace(" ", "T") + (/Z|[+-]\d\d:?\d\d$/.test(String(value)) ? "" : "Z"));
  return Number.isNaN(date.getTime()) ? String(value) : date.toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

// ---- Outcomes -----------------------------------------------------------------------------------

export type Outcome =
  | { kind: "idle" }
  | { kind: "busy" }
  | { kind: "ok"; message: string; data?: unknown; secret?: boolean }
  | { kind: "error"; error: ApiError | Error };

function recovery(error: ApiError | Error): ReactNode {
  if (!(error instanceof ApiError)) return null;
  if (error.code === "step_up_required") return <LinkButton href="/security" variant="secondary" size="sm">Verify with your passkey</LinkButton>;
  if (error.code === "enrollment_incomplete") return <LinkButton href="/security?setup=admin" variant="secondary" size="sm">Finish admin setup</LinkButton>;
  if (error.code === "unauthenticated") return <LinkButton href="/sign-in" variant="secondary" size="sm">Sign in</LinkButton>;
  return null;
}

export function ErrorBanner({ error }: { error: ApiError | Error }) {
  const issues = error instanceof ApiError && error.issues?.length
    ? error.issues.map(i => (i.path ? i.path + ": " : "") + i.message).join("; ") : undefined;
  return <Banner variant="error" icon={icon(XCircle)} title={error.message} description={issues} action={recovery(error)} />;
}

/**
 * One-time secret display: client secrets and bearer tokens. Kept only in component state, never
 * logged or stored, and dropped when the administrator confirms they stored it (or leaves the panel).
 */
export function SecretOnce({ value, onDone }: { value: unknown; onDone: () => void }) {
  return (
    <div className="nathan-stack" data-nathan-secret="">
      <Banner variant="alert" icon={icon(Key)} title="Shown once"
        description="Copy the secret below to a secrets manager now. Nathan never shows it again." />
      <JsonView value={value} label="One-time secret" />
      <Row><Button variant="secondary" onClick={onDone}>I stored it, hide it</Button></Row>
    </div>
  );
}

const SECRET_KEYS = /^(client_secret|clientSecret|secret|bearerToken|bearer_token|token)$/;

/** True when an API result carries a one-time secret anywhere (client secrets, SCIM bearer tokens). */
export function carriesSecret(value: unknown, depth = 0): boolean {
  if (!value || typeof value !== "object" || depth > 4) return false;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_KEYS.test(k) && typeof v === "string" && v) return true;
    if (carriesSecret(v, depth + 1)) return true;
  }
  return false;
}

export function OutcomeView({ outcome, onClear }: { outcome: Outcome; onClear?: () => void }) {
  if (outcome.kind === "idle") return null;
  if (outcome.kind === "busy") return <p className="nathan-text nathan-studio-muted" role="status">Working…</p>;
  if (outcome.kind === "error") return <div role="alert"><ErrorBanner error={outcome.error} /></div>;
  return (
    <div className="nathan-stack" role="status">
      <Banner variant="default" icon={icon(CheckCircle)} title={outcome.message} />
      {outcome.secret
        ? <SecretOnce value={outcome.data} onDone={() => onClear?.()} />
        : <JsonView value={outcome.data} label="Result" />}
    </div>
  );
}

export function Notice({ title, children, tone = "default", action }: { title: string; children?: ReactNode; tone?: "default" | "alert"; action?: ReactNode }) {
  return <Banner variant={tone} icon={icon(tone === "alert" ? Warning : Info)} title={title} description={children} action={action} />;
}

// ---- Confirmation dialog ------------------------------------------------------------------------

/** Resolves to the confirm value to send ("" when the confirmation has no phrase), or null if cancelled. */
type Ask = (c: Confirmation) => Promise<string | null>;
const ConfirmContext = createContext<Ask>(async () => null);

export function ConfirmProvider({ children }: { children?: ReactNode }) {
  const [pending, setPending] = useState<Confirmation | null>(null);
  const [typed, setTyped] = useState("");
  const resolver = useRef<((v: string | null) => void) | null>(null);
  const finish = (value: string | null) => {
    resolver.current?.(value);
    resolver.current = null;
    setPending(null);
    setTyped("");
  };
  const ask = useCallback<Ask>(c => new Promise(resolve => {
    resolver.current?.(null);
    resolver.current = resolve;
    setTyped("");
    setPending(c);
  }), []);
  const c = pending;
  return (
    <ConfirmContext.Provider value={ask}>
      {children}
      <Dialog.Root open={c !== null} onOpenChange={open => { if (!open) finish(null); }}>
        <Dialog size="lg" className="nathan-studio-dialog">
          {c ? (
            <form className="nathan-stack" onSubmit={e => { e.preventDefault(); finish(c.typed ? typed : c.phrase ?? ""); }}>
              <Dialog.Title className="nathan-studio-section-title">{c.title}</Dialog.Title>
              <Dialog.Description className="nathan-studio-prose nathan-studio-prewrap">{c.question}</Dialog.Description>
              {c.typed && c.phrase ? (
                <Input label={<>Type exactly: <Code>{c.phrase}</Code></>} value={typed} autoComplete="off" spellCheck={false}
                  onChange={e => setTyped(e.target.value)} autoFocus />
              ) : null}
              <Row>
                <Button type="submit" variant={c.destructive ? "destructive" : "primary"}
                  disabled={Boolean(c.typed && !typed)}>{c.confirmLabel ?? "Confirm"}</Button>
                <Button type="button" variant="secondary" onClick={() => finish(null)}>Cancel</Button>
              </Row>
            </form>
          ) : null}
        </Dialog>
      </Dialog.Root>
    </ConfirmContext.Provider>
  );
}

export const useConfirm = () => useContext(ConfirmContext);

// ---- Data hooks ---------------------------------------------------------------------------------

/** Runs writes: optional confirmation, then the call, then an outcome for <OutcomeView>. */
export function useAction() {
  const ask = useConfirm();
  const [outcome, setOutcome] = useState<Outcome>({ kind: "idle" });
  const run = useCallback(async <T,>(
    call: (confirm: string) => Promise<T>,
    opts: { confirm?: Confirmation; message?: string | ((r: T) => string); secret?: boolean | ((r: T) => boolean); after?: (r: T) => void | Promise<void> } = {}
  ) => {
    let phrase = "";
    if (opts.confirm) {
      const answer = await ask(opts.confirm);
      if (answer === null) return;
      phrase = answer;
    }
    setOutcome({ kind: "busy" });
    try {
      const result = await call(phrase);
      const message = typeof opts.message === "function" ? opts.message(result) : opts.message ?? "Saved";
      // Any result carrying a secret is shown once, whatever the caller said.
      const secret = (typeof opts.secret === "function" ? opts.secret(result) : Boolean(opts.secret)) || carriesSecret(result);
      setOutcome({ kind: "ok", message, data: result, secret });
      await opts.after?.(result);
    } catch (error) {
      setOutcome({ kind: "error", error: error instanceof Error ? error : new Error("Request failed") });
    }
  }, [ask]);
  const clear = useCallback(() => setOutcome({ kind: "idle" }), []);
  return { outcome, run, clear, view: <OutcomeView outcome={outcome} onClear={clear} /> };
}

/** Loads data on mount (and on reload()); `enabled` false waits until the caller has an id. */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[] = [], enabled = true) {
  const [state, setState] = useState<{ data?: T; error?: ApiError | Error; loading: boolean }>({ loading: enabled });
  const latest = useRef(load);
  latest.current = load;
  const seq = useRef(0);
  const reload = useCallback(async () => {
    const n = ++seq.current;
    setState(s => ({ ...s, loading: true }));
    try {
      const data = await latest.current();
      if (n === seq.current) setState({ data, loading: false });
      return data;
    } catch (error) {
      if (n === seq.current) setState({ error: error instanceof Error ? error : new Error("Request failed"), loading: false });
      return undefined;
    }
  }, []);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (enabled) void reload(); }, [enabled, reload, ...deps]);
  return { ...state, reload, setData: (data: T) => setState({ data, loading: false }) };
}

/** Loading, error or the children for a useLoad() result. */
export function Loaded<T>({ state, children }: { state: { data?: T; error?: ApiError | Error; loading: boolean }; children: (data: T) => ReactNode }) {
  if (state.error) return <ErrorBanner error={state.error} />;
  if (state.data === undefined) return state.loading ? <p className="nathan-text nathan-studio-muted" role="status">Loading…</p> : null;
  return <>{children(state.data)}</>;
}

export function RefreshButton({ onClick, label = "Refresh" }: { onClick: () => void; label?: string }) {
  return <Button variant="secondary" size="sm" onClick={onClick}>{label}</Button>;
}
