/** NATH-40: island bundle for the hosted installer wizard (src/ui/pages/installer/InstallerWizard.tsx). */
import { hydrateIslands } from "../client/hydrate.tsx";
import { InstallerWizard } from "../pages/installer/InstallerWizard.tsx";

hydrateIslands("installer-wizard", InstallerWizard);
