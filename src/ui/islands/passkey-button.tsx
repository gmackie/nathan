/** NATH-37: island bundle for the example passkey button (hydration only, no WebAuthn). */
import { hydrateIslands } from "../client/hydrate.tsx";
import { PasskeyButton } from "../components/PasskeyButton.tsx";

hydrateIslands("passkey-button", PasskeyButton);
