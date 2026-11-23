/** NATH-38: island bundle for /security (administrator onboarding, TOTP enrolment, passkeys). */
import { hydrateIslands } from "../client/hydrate.tsx";
import { SecurityPanel } from "../pages/security/SecurityPanel.tsx";

hydrateIslands("security", SecurityPanel);
