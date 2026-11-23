/**
 * NATH-34: hosted-page appearance (Clerk-style variables + layout), see DESIGN.md. Nathan's default
 * is stock Kumo; gmacko's instance appearance is docs/appearance/gmacko.json.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  resolveAppearance, appearanceCss, contrast, textOn, AppearanceError, KUMO_DEFAULTS, INK, WHITE, MIN_CONTRAST
} from "../src/ui/appearance.ts";

const gmacko = JSON.parse(readFileSync("docs/appearance/gmacko.json", "utf8"));
const issues = fn => { try { fn(); } catch (e) { assert.ok(e instanceof AppearanceError, String(e)); return e.issues; } assert.fail("expected AppearanceError"); };

test("no appearance means stock Kumo: no CSS, the plain card layout", () => {
  const a = resolveAppearance();
  assert.deepEqual(a.light, {});
  assert.deepEqual(a.dark, {});
  assert.equal(a.borderRadius, null);
  assert.equal(a.fontFamily, "Kumo");
  assert.equal(a.layout.platePlacement, "none");
  assert.equal(a.wordmark, null);
  assert.equal(appearanceCss(a), "");
});

test("gmacko's instance appearance is valid and keeps AA contrast in both modes", () => {
  const a = resolveAppearance(gmacko);
  assert.equal(a.light.plate, "#2041D9");
  assert.equal(a.light.onPlate, WHITE);
  assert.equal(a.light.primary, "#FF7A1A");
  assert.equal(a.light.onPrimary, INK);
  assert.equal(a.wordmark, "gmacko");
  assert.equal(a.layout.platePlacement, "left");
  for (const mode of ["light", "dark"]) {
    const m = a[mode];
    assert.ok(contrast(m.plate, m.onPlate) >= MIN_CONTRAST, mode + " text on plate");
    assert.ok(contrast(m.primary, m.onPrimary) >= MIN_CONTRAST, mode + " text on primary");
    for (const ground of [m.background, m.surface])
      for (const text of [KUMO_DEFAULTS[mode].text, KUMO_DEFAULTS[mode].textMuted])
        assert.ok(contrast(ground, text) >= MIN_CONTRAST, mode + " " + text + " on " + ground);
  }
});

test("an app layers over the instance: its values win, the rest is inherited", () => {
  const a = resolveAppearance(gmacko, { variables: { colorPlate: "#ff8fc2", colorPrimary: "#18181b", borderRadius: 999 },
    layout: { platePlacement: "top" }, wordmark: "creator" });
  assert.equal(a.light.plate, "#FF8FC2");
  assert.equal(a.light.onPlate, INK, "text on a custom fill is derived");
  assert.equal(a.light.onPrimary, WHITE);
  assert.equal(a.light.background, "#FAFAFC", "inherited from the instance");
  assert.equal(a.borderRadius, 999);
  assert.equal(a.layout.platePlacement, "top");
  assert.equal(a.wordmark, "creator");
  assert.equal(textOn("#2041D9"), WHITE);
  assert.equal(textOn("#FF7A1A"), INK);
});

test("unreadable fills and grounds are rejected with every reason; a plate needs a colour", () => {
  assert.equal(textOn("#7A7A7A"), null);
  const found = issues(() => resolveAppearance({}, { variables: { colorPrimary: "#7A7A7A", colorBackground: "#202020" } }));
  assert.ok(found.some(i => i.startsWith("variables.colorPrimary (light)")), found.join("\n"));
  assert.ok(found.some(i => i.startsWith("variables.colorBackground (light)")), found.join("\n"));
  assert.ok(issues(() => resolveAppearance({ layout: { platePlacement: "left" } })).some(i => i.startsWith("layout.platePlacement")));
});

test("the schema is closed: unknown keys, CSS, URLs and out-of-range values are refused", () => {
  for (const bad of [
    { elements: { card: "background:red" } },
    { variables: { colorPlate: "red" } },
    { variables: { colorPlate: "#2041D9;}body{display:none" } },
    { variables: { colorText: "#000000" } },
    { variables: { borderRadius: 40 } },
    { variables: { fontFamily: "Comic Sans" } },
    { layout: { platePlacement: "right" } },
    { layout: { primaryMethod: "provider:../../x" } },
    { logo: "https://evil.example/logo.svg" },
    { wordmark: "<script>" },
    { wordmark: "x".repeat(25) }
  ]) assert.throws(() => resolveAppearance({}, bad), AppearanceError, JSON.stringify(bad));
  assert.match(issues(() => resolveAppearance({ variables: { colorPlate: "red" } }))[0], /^instance\.variables\.colorPlate/);
  assert.equal(resolveAppearance({ layout: { primaryMethod: "provider:github" } }).layout.primaryMethod, "provider:github");
});

test("appearanceCss emits only validated values on the nathan theme, light/dark/system", () => {
  const css = appearanceCss(resolveAppearance(gmacko, { variables: { fontFamily: "Inter" } }));
  assert.match(css, /^\[data-theme="nathan"\]\{--nathan-plate:#2041D9;--nathan-on-plate:#FFFFFF;/);
  assert.match(css, /--color-kumo-brand:#FF7A1A;--nathan-on-brand:#18181B/);
  assert.match(css, /--nathan-radius:6px;--nathan-font:"Inter", system-ui, sans-serif\}/);
  assert.match(css, /\[data-theme="nathan"\]\[data-mode="dark"\]\{--nathan-plate:#1F3FCC/);
  assert.match(css, /@media \(prefers-color-scheme: dark\)\{\[data-theme="nathan"\]\[data-mode="system"\]/);
  assert.doesNotMatch(css.replace("@media", ""), /[<>@;]{2}|[<>@]/);
});
