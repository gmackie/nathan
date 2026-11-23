/**
 * NATH-37: example island component. A Kumo primary Button that is disabled in the server
 * markup and enabled once React hydrates it, so it never looks usable without its script.
 * No WebAuthn yet: K1 moves today's passkey calls from src/auth/ui.ts in here verbatim.
 */
import { useEffect, useState } from "react";
import { Button } from "@cloudflare/kumo/components/button";
import { Fingerprint } from "@phosphor-icons/react/dist/ssr/Fingerprint";
import { ICON_SIZE, ICON_WEIGHT, iconA11y } from "../icon-defaults.ts";

export interface PasskeyButtonProps {
  label: string;
}

export function PasskeyButton({ label }: PasskeyButtonProps) {
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => setHydrated(true), []);
  return (
    <Button
      variant="primary"
      icon={<Fingerprint size={ICON_SIZE} weight={ICON_WEIGHT} {...iconA11y()} />}
      disabled={!hydrated}
      data-nathan-passkey=""
      data-hydrated={hydrated ? "true" : "false"}
    >
      {label}
    </Button>
  );
}
