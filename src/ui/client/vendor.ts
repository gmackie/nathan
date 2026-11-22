/**
 * NATH-37: build-only entry (scripts/build-ui.mjs). It imports what every React island shares so
 * esbuild's code splitting puts it in one cached vendor chunk. Pages never load this file itself.
 */
export { createElement, useEffect, useState } from "react";
export { jsx, jsxs } from "react/jsx-runtime";
export { hydrateRoot } from "react-dom/client";
export { Button } from "@cloudflare/kumo/components/button";
export { hydrateIslands, restoreInlineStyles } from "./hydrate.tsx";
