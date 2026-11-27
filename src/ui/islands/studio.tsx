/** NATH-39: island bundle for Identity Studio, the Kumo SPA served at /studio. */
import { hydrateIslands } from "../client/hydrate.tsx";
import { StudioApp } from "../pages/studio/StudioApp.tsx";

hydrateIslands("studio", StudioApp);
