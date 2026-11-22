/**
 * NATH-34: appearance for Nathan's hosted pages (sign-in, consent, MFA, SAML, errors), modelled on
 * Clerk's `appearance` prop: `variables` (colours, radius, font), `layout` (structure), a wordmark
 * and a logo.
 *
 * Nathan's default is stock Kumo everywhere, including these pages: with no appearance set,
 * nothing here emits CSS and the pages use Kumo's own tokens and a plain card layout. An instance
 * operator can set an instance appearance (gmacko's is docs/appearance/gmacko.json) and each OIDC
 * client app can layer its own on top: app over instance over Kumo.
 *
 * Deliberately narrower than Clerk: no free-form `elements` CSS. Arbitrary styling on a credential
 * page is a phishing and clickjacking risk, and the CSP forbids inline styles. Colours are #rrggbb
 * only, so they are safe in the nonce'd style block, and text drawn on a custom fill is derived
 * (ink or white), never chosen. The issuer footer, route line, consent scope text, error reason
 * codes and security warnings are not reachable from this object.
 *
 * Identity Studio, the installer and the gateway pages never use this: they are always stock Kumo.
 */
import { z } from "zod";

export const INK = "#18181B";
export const WHITE = "#FFFFFF";
/** WCAG AA for normal text. */
export const MIN_CONTRAST = 4.5;

/**
 * Kumo 2.19's default tokens as sRGB (theme-kumo.css defines them in oklch). Used to validate an
 * override against the colours it will actually sit next to; never emitted.
 */
export const KUMO_DEFAULTS = {
  light: { text: "#18181B", textMuted: "#737373", background: "#FBFBFB", surface: "#FFFFFF" },
  dark: { text: "#F5F5F5", textMuted: "#A1A1A1", background: "#030303", surface: "#0F0F0F" }
} as const;

/** Self-hosted UI faces an appearance may pick. The CSP allows no remote fonts. */
export const APPEARANCE_FONTS = ["Kumo", "Public Sans", "Inter", "Geist", "IBM Plex Sans"] as const;

const hex = z.string().regex(/^#[0-9a-fA-F]{6}$/, "expected #rrggbb").transform(s => s.toUpperCase());
/** A colour given once, or separately for light and dark. */
const modal = z.union([hex, z.object({ light: hex, dark: hex }).strict()]);

const variablesSchema = z.object({
  colorPlate: modal.optional(),
  colorPlateAccent: modal.optional(),
  colorPrimary: modal.optional(),
  colorBackground: modal.optional(),
  colorSurface: modal.optional(),
  borderRadius: z.union([z.number().int().min(0).max(16), z.literal(999)]).optional(),
  fontFamily: z.enum(APPEARANCE_FONTS).optional()
}).strict();

const layoutSchema = z.object({
  /** "none" is the stock Kumo card. A plate needs a colorPlate somewhere in the layering. */
  platePlacement: z.enum(["left", "top", "none"]).optional(),
  socialButtonsVariant: z.enum(["blockButton", "iconButton"]).optional(),
  /** passkey, email, or provider:<id>; checked against the instance's enabled methods at render. */
  primaryMethod: z.string().regex(/^(passkey|email|provider:[a-z0-9-]{1,32})$/).optional(),
  logoPlacement: z.enum(["plate", "form", "none"]).optional()
}).strict();

export const appearanceSchema = z.object({
  variables: variablesSchema.optional(),
  layout: layoutSchema.optional(),
  /** Plain text shown large on the plate (gmacko: "gmacko"). Rendered as escaped text. */
  wordmark: z.string().min(1).max(24).regex(/^[\p{L}\p{N} ._-]+$/u).optional(),
  /** Id of a logo uploaded to and sanitized by Nathan; never a URL. */
  logo: z.string().regex(/^[a-z0-9-]{1,64}$/).optional()
}).strict();

export type AppearanceInput = z.input<typeof appearanceSchema>;
type Parsed = z.output<typeof appearanceSchema>;

type ModeOverrides = Partial<Record<"plate" | "onPlate" | "plateAccent" | "primary" | "onPrimary" | "background" | "surface", string>>;

export type ResolvedAppearance = {
  /** Only the colours that differ from Kumo's defaults. Empty when nothing is customised. */
  light: ModeOverrides;
  dark: ModeOverrides;
  borderRadius: number | null;
  fontFamily: (typeof APPEARANCE_FONTS)[number];
  layout: { platePlacement: "left" | "top" | "none"; socialButtonsVariant: "blockButton" | "iconButton";
    primaryMethod: string; logoPlacement: "plate" | "form" | "none" };
  wordmark: string | null;
  logo: string | null;
};

function luminance(color: string): number {
  const channel = (i: number) => {
    const v = parseInt(color.slice(i, i + 2), 16) / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

/** WCAG contrast ratio of two #rrggbb colours. */
export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** Ink or white, whichever is readable on `fill`; null when neither reaches 4.5:1. */
export function textOn(fill: string): string | null {
  const ink = contrast(fill, INK), white = contrast(fill, WHITE);
  if (Math.max(ink, white) < MIN_CONTRAST) return null;
  return ink >= white ? INK : WHITE;
}

export class AppearanceError extends Error {
  readonly issues: string[];
  constructor(issues: string[]) { super("Invalid appearance: " + issues.join("; ")); this.issues = issues; }
}

function parse(input: unknown, label: string): Parsed {
  const parsed = appearanceSchema.safeParse(input ?? {});
  if (!parsed.success) throw new AppearanceError(parsed.error.issues.map(i => label + "." + (i.path.join(".") || "") + ": " + i.message));
  return parsed.data;
}

/**
 * Validates the instance appearance and an app's appearance, layers app over instance over Kumo,
 * and returns the result. Throws AppearanceError listing every problem: schema errors, a fill on
 * which neither ink nor white reaches 4.5:1, and a background or surface on which the default
 * text colours fall below 4.5:1.
 */
export function resolveAppearance(instance?: unknown, app?: unknown): ResolvedAppearance {
  const layers = [parse(instance, "instance"), parse(app, "app")];
  const variables: NonNullable<Parsed["variables"]> = Object.assign({}, ...layers.map(l => l.variables ?? {}));
  const layout: NonNullable<Parsed["layout"]> = Object.assign({}, ...layers.map(l => l.layout ?? {}));
  const last = <K extends "wordmark" | "logo">(key: K) => layers.map(l => l[key]).filter(v => v !== undefined).at(-1) ?? null;
  const issues: string[] = [];
  const pick = (v: string | { light: string; dark: string } | undefined, mode: "light" | "dark") =>
    v === undefined ? undefined : typeof v === "string" ? v : v[mode];

  const resolveMode = (mode: "light" | "dark"): ModeOverrides => {
    const out: ModeOverrides = {};
    const fill = (value: string | undefined, key: "plate" | "primary", onKey: "onPlate" | "onPrimary", name: string) => {
      if (value === undefined) return;
      const on = textOn(value);
      if (!on) { issues.push(`variables.${name} (${mode}): neither ink nor white text reaches ${MIN_CONTRAST}:1 on ${value}`); return; }
      out[key] = value; out[onKey] = on;
    };
    fill(pick(variables.colorPlate, mode), "plate", "onPlate", "colorPlate");
    fill(pick(variables.colorPrimary, mode), "primary", "onPrimary", "colorPrimary");
    const accent = pick(variables.colorPlateAccent, mode);
    if (accent !== undefined) out.plateAccent = accent; // decoration on the plate, never text
    const base = KUMO_DEFAULTS[mode];
    for (const [key, name] of [["background", "colorBackground"], ["surface", "colorSurface"]] as const) {
      const value = pick(variables[name], mode);
      if (value === undefined) continue;
      for (const [label, text] of [["text", base.text], ["muted text", base.textMuted]] as const)
        if (contrast(value, text) < MIN_CONTRAST) issues.push(`variables.${name} (${mode}): Kumo ${label} ${text} is below ${MIN_CONTRAST}:1 on ${value}`);
      out[key] = value;
    }
    return out;
  };

  const resolved: ResolvedAppearance = {
    light: resolveMode("light"), dark: resolveMode("dark"),
    borderRadius: variables.borderRadius ?? null,
    fontFamily: variables.fontFamily ?? "Kumo",
    layout: {
      platePlacement: layout.platePlacement ?? "none",
      socialButtonsVariant: layout.socialButtonsVariant ?? "blockButton",
      primaryMethod: layout.primaryMethod ?? "passkey",
      logoPlacement: layout.logoPlacement ?? "none"
    },
    wordmark: last("wordmark"), logo: last("logo")
  };
  if (resolved.layout.platePlacement !== "none" && (!resolved.light.plate || !resolved.dark.plate))
    issues.push("layout.platePlacement: a plate needs variables.colorPlate");
  if (issues.length) throw new AppearanceError(issues);
  return resolved;
}

const FONT_STACK: Record<Exclude<ResolvedAppearance["fontFamily"], "Kumo">, string> = {
  "Public Sans": '"Public Sans", system-ui, sans-serif', Inter: '"Inter", system-ui, sans-serif',
  Geist: '"Geist", system-ui, sans-serif', "IBM Plex Sans": '"IBM Plex Sans", system-ui, sans-serif'
};

const TOKENS: Record<keyof ModeOverrides, string> = {
  plate: "--nathan-plate", onPlate: "--nathan-on-plate", plateAccent: "--nathan-plate-accent",
  primary: "--color-kumo-brand", onPrimary: "--nathan-on-brand",
  background: "--color-kumo-canvas", surface: "--color-kumo-base"
};

/** Kumo tokens (and Nathan's plate tokens) an appearance may set; everything else stays Kumo's. */
export const APPEARANCE_TOKENS = Object.values(TOKENS);

const block = (m: ModeOverrides) =>
  (Object.entries(m) as [keyof ModeOverrides, string][]).map(([k, v]) => `${TOKENS[k]}:${v}`).join(";");

/**
 * CSS for a resolved appearance, emitted after Kumo and theme.css. Returns "" for an empty
 * appearance, so default pages are byte-for-byte stock Kumo. Every value is a validated #rrggbb,
 * an integer radius or a fixed font stack, so the output is safe for the nonce'd style block.
 */
export function appearanceCss(a: ResolvedAppearance): string {
  const shared = [
    a.borderRadius === null ? "" : `--nathan-radius:${a.borderRadius}px`,
    a.fontFamily === "Kumo" ? "" : `--nathan-font:${FONT_STACK[a.fontFamily]}`
  ].filter(Boolean);
  const light = [block(a.light), ...shared].filter(Boolean).join(";");
  const dark = block(a.dark);
  let css = "";
  if (light) css += `[data-theme="nathan"]{${light}}`;
  if (dark) css += `[data-theme="nathan"][data-mode="dark"]{${dark}}` +
    `@media (prefers-color-scheme: dark){[data-theme="nathan"][data-mode="system"]{${dark}}}`;
  return css;
}
