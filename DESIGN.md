---
# gstack: design-md-format=spec
name: Nathan
description: Stock Cloudflare Kumo on every surface, with a Clerk-style appearance layer so each instance and app can restyle its own hosted sign-in pages within safe limits.
colors:
  primary: "#056DFF"
  on-primary: "#FFFFFF"
  background: "#FBFBFB"
  surface: "#FFFFFF"
  text: "#18181B"
  text-muted: "#737373"
  background-dark: "#030303"
  surface-dark: "#0F0F0F"
  text-dark: "#F5F5F5"
  text-muted-dark: "#A1A1A1"
typography:
  body:
    fontFamily: Kumo default (system UI stack)
    fontSize: 0.875rem
    lineHeight: 1.5
rounded:
  md: 8px
spacing:
  sm: 8px
  md: 16px
  lg: 24px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    rounded: "{rounded.md}"
---

# Nathan

## Overview

**Creative North Star:** Nathan looks like Kumo. Every surface uses stock Cloudflare Kumo components and tokens: Identity Studio, the installer, the gateway pages, and by default the hosted sign-in, consent, MFA, SAML and error pages too. Nathan has no brand of its own to impose. Instances and apps bring their brand through the appearance layer.
**Product context:** Nathan is an open-source, self-hosted identity provider. Operators run their own instance, and their apps register as OIDC clients.
**Mode per surface:**
- Studio, installer and gateway pages are Operate surfaces. They are stock Kumo and are never themed.
- The hosted end-user pages are stock Kumo unless an instance or app sets an appearance.

The colour values in the front matter are Kumo 2.19's own defaults converted to sRGB (`src/ui/appearance.ts` `KUMO_DEFAULTS`). They are recorded for validation, never emitted.

## Colors

The defaults come from Kumo, light and dark, following the OS. `src/ui/theme.css` overrides no Kumo colour token. Icons are Phosphor, Regular weight; Fill is only for selected state and Duotone is never used.

## Appearance (hosted pages only, Clerk-style)

The hosted pages can be restyled in two layers. Each layer is validated on the server by `resolveAppearance(instance, app)`:
1. **Instance appearance:** set by the operator; for example gmacko's, in `docs/appearance/gmacko.json`.
2. **App appearance:** set per OIDC client and layered over the instance. Where a key is unset, the instance value applies, then Kumo's.

The object has these parts:
- **`variables`** (light and dark may differ):
  - colours: `colorPlate`, `colorPlateAccent`, `colorPrimary`, `colorBackground`, `colorSurface`;
  - shape and type: `borderRadius` (0–16px or 999px), and `fontFamily` (Kumo, Public Sans, Inter, Geist or IBM Plex Sans, all self-hosted).
- **`layout`:**
  - `platePlacement`: `left`, `top` or `none` (stock card);
  - `socialButtonsVariant`: `blockButton` or `iconButton`;
  - `primaryMethod`: `passkey`, `email` or `provider:<id>`;
  - `logoPlacement`: `plate`, `form` or `none`.
- **`wordmark`:** plain text shown large on the plate.
- **`logo`:** the id of an image uploaded to Nathan and sanitized there.

Rules:
- **Derived text:** text on `colorPlate` and `colorPrimary` is set automatically to ink or white, whichever reaches 4.5:1. A colour where neither does is rejected.
- **Grounds:** `colorBackground` and `colorSurface` must keep Kumo's text and muted text at 4.5:1 or better.
- **No free-form CSS:** there are no `elements` or CSS overrides, unlike Clerk. Arbitrary styling on a credential page is a phishing and clickjacking risk, and the CSP forbids inline styles.
- **Fixed for every instance and app:** the issuer footer, the route line ("app → issuer host"), consent scope text, error reason codes and security warnings.
- **Empty appearance:** `appearanceCss` emits nothing, so the page is stock Kumo byte for byte.

## Instance example: gmacko (id.gmac.io)

The owner's parent instance, defined in `docs/appearance/gmacko.json`:
- **Plate:** cobalt (#2041D9; #1F3FCC in dark mode) on the left 42% of the page, with the white wordmark "gmacko" cropped by its bottom edge and one orange (#FF7A1A) disc as the only decoration.
- **Primary action:** orange with ink text (6.9:1). Passkey is the default primary method.
- **Neutrals:** background #FAFAFC / #0E1116 and surface #FFFFFF / #161A21. These were chosen so Kumo's muted text stays at 4.5:1 or better; #F5F6F8 was rejected at 4.4:1.
- **Faces:** Public Sans for UI. Bricolage Grotesque 800 for the wordmark and Martian Mono for the route line are the plate's own faces (OFL, self-hosted).

gmacko's apps then layer their own appearance on top. For example, creator uses a pink top plate with pill buttons, and fabforge uses no plate with icon buttons.

## Layout

- **Studio:** Kumo Sidebar, Table, Input, Button, Badge, LayerCard and Dialog, all with default spacing.
- **Hosted pages:**
  - Default (`platePlacement: none`): a stock Kumo card centred on the canvas.
  - With a plate: a 42/58 split on desktop (`left`), or a band (`top`). On phones the plate always becomes a band.

## Do's and Don'ts

- **Do** use stock Kumo components and tokens. Reach for a Kumo prop before custom CSS.
- **Do** keep one primary action per hosted page, and show the route line and the issuer footer.
- **Do** put the actual request in the heading of consent pages.
- **Don't** theme Studio, the installer or the gateway pages.
- **Don't** add Nathan-specific colours to `theme.css`.
- **Don't** accept per-app CSS or remote assets.
- **Don't** put orange text on cobalt in gmacko's appearance (2.9:1); orange there is decoration only.

## Motion

Kumo's defaults apply. An appearance with a plate may animate the plate's accent in once on load (600ms ease-out), and does not animate it under reduced motion.

## Decisions Log
| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-11-22 | Nathan defaults to stock Kumo everywhere, hosted pages included | Owner: "Nathan by default should be Kumo management backend with Kumo default for the login pages". gmacko and future operators customise only the hosted pages, through appearance. |
| 2026-11-22 | Clerk-style appearance (variables + layout), no free-form CSS | Owner asked for Clerk-like customisation. Free-form CSS is unsafe on credential pages and incompatible with the CSP. |
| 2026-11-22 | gmacko instance: cobalt plate + orange primary | Owner pick (D8) in the /design-consultation for NATH-34, after rejecting the five-colour "Maker's Kit". The background was moved to #FAFAFC to keep Kumo's muted text at AA. |
