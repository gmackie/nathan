/**
 * NATH-37: Nathan's Phosphor icon map.
 *
 * Imports come one by one from @phosphor-icons/react/dist/ssr: those icons need no React
 * context, so they render the same in the Worker and in islands, and only the icons named here
 * reach a bundle. Icons render as inline SVG, so img-src 'none' stays.
 *
 * Defaults live in src/ui/icon-defaults.ts (weight "regular", 20 px, currentColor; the NATH-34
 * design pass may change them). Icons are decorative (aria-hidden) unless given a `label`.
 * Islands should import single icons, not this map (see icon-defaults.ts).
 */
import type { IconProps, IconWeight } from "@phosphor-icons/react";
import type { ComponentType } from "react";
import { AppleLogo } from "@phosphor-icons/react/dist/ssr/AppleLogo";
import { AppWindow } from "@phosphor-icons/react/dist/ssr/AppWindow";
import { ArrowsClockwise } from "@phosphor-icons/react/dist/ssr/ArrowsClockwise";
import { Buildings } from "@phosphor-icons/react/dist/ssr/Buildings";
import { CheckCircle } from "@phosphor-icons/react/dist/ssr/CheckCircle";
import { DiscordLogo } from "@phosphor-icons/react/dist/ssr/DiscordLogo";
import { Fingerprint } from "@phosphor-icons/react/dist/ssr/Fingerprint";
import { Gear } from "@phosphor-icons/react/dist/ssr/Gear";
import { GithubLogo } from "@phosphor-icons/react/dist/ssr/GithubLogo";
import { GoogleLogo } from "@phosphor-icons/react/dist/ssr/GoogleLogo";
import { IdentificationBadge } from "@phosphor-icons/react/dist/ssr/IdentificationBadge";
import { IdentificationCard } from "@phosphor-icons/react/dist/ssr/IdentificationCard";
import { Info } from "@phosphor-icons/react/dist/ssr/Info";
import { Key } from "@phosphor-icons/react/dist/ssr/Key";
import { Plug } from "@phosphor-icons/react/dist/ssr/Plug";
import { ShieldCheck } from "@phosphor-icons/react/dist/ssr/ShieldCheck";
import { SignOut } from "@phosphor-icons/react/dist/ssr/SignOut";
import { Ticket } from "@phosphor-icons/react/dist/ssr/Ticket";
import { TwitchLogo } from "@phosphor-icons/react/dist/ssr/TwitchLogo";
import { User } from "@phosphor-icons/react/dist/ssr/User";
import { Users } from "@phosphor-icons/react/dist/ssr/Users";
import { Warning } from "@phosphor-icons/react/dist/ssr/Warning";
import { XCircle } from "@phosphor-icons/react/dist/ssr/XCircle";
import { XLogo } from "@phosphor-icons/react/dist/ssr/XLogo";

import { ICON_SIZE, ICON_WEIGHT, iconA11y } from "./icon-defaults.ts";

export { ICON_SIZE, ICON_WEIGHT };
export type PhosphorIcon = ComponentType<IconProps>;

/** Logos for every provider id in src/shared/providers.mjs (tests enforce full coverage). */
export const PROVIDER_ICONS: Readonly<Record<string, PhosphorIcon>> = {
  google: GoogleLogo,
  github: GithubLogo,
  apple: AppleLogo,
  discord: DiscordLogo,
  twitch: TwitchLogo,
  twitter: XLogo,
  // NATH-51: a parent Nathan instance ("Sign in with Nathan").
  nathan: IdentificationBadge
};

/** Shown for a provider without a logo of its own (custom OIDC, enterprise SSO, future ids). */
export const GENERIC_PROVIDER_ICON: PhosphorIcon = IdentificationCard;

export const ICONS = {
  passkey: Fingerprint,
  key: Key,
  "shield-check": ShieldCheck,
  warning: Warning,
  error: XCircle,
  info: Info,
  success: CheckCircle,
  user: User,
  users: Users,
  app: AppWindow,
  token: Ticket,
  mcp: Plug,
  sso: Buildings,
  scim: ArrowsClockwise,
  settings: Gear,
  "sign-out": SignOut
} as const satisfies Record<string, PhosphorIcon>;

export type IconName = keyof typeof ICONS;

export function providerIcon(provider: string): PhosphorIcon {
  return Object.hasOwn(PROVIDER_ICONS, provider) ? PROVIDER_ICONS[provider] : GENERIC_PROVIDER_ICON;
}

interface RenderIconProps {
  size?: number;
  weight?: IconWeight;
  /** Accessible name. Without it the icon is decorative and hidden from assistive technology. */
  label?: string;
  className?: string;
}

function renderIcon(Icon: PhosphorIcon, { size = ICON_SIZE, weight = ICON_WEIGHT, label, className }: RenderIconProps) {
  return <Icon size={size} weight={weight} className={className} {...iconA11y(label)} />;
}

export function NathanIcon({ name, ...props }: RenderIconProps & { name: IconName }) {
  return renderIcon(ICONS[name], props);
}

export function ProviderIcon({ provider, ...props }: RenderIconProps & { provider: string }) {
  return renderIcon(providerIcon(provider), props);
}
