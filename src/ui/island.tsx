/**
 * NATH-37: server-side island container. Renders `Component` inside a marked <div> and stores its
 * props as JSON in an attribute (React escapes it). The matching bundle in src/ui/islands/
 * hydrates the same component with the same props. Pass the id in renderPage's `islands` too;
 * renderPage refuses a page whose markup and `islands` option disagree.
 *
 * NATH-40: the component is rendered in its own React root, exactly as hydrateIslands() hydrates
 * it. React uses the position in the tree to assign the ids for controls and labels, so both
 * sides use the same root and keep Base UI's accessibility attributes in sync. Both roots disable Base UI's
 * inline stylesheet in favor of the scroll area rule in layout.css. renderPage validates the
 * content of this island along with the rest of the page.
 */
import type { ComponentType } from "react";
import { renderToString } from "react-dom/server";
import { CSPProvider } from "@cloudflare/kumo/primitives/csp-provider";
import type { IslandId } from "./island-ids.ts";

export interface IslandProps<P extends object> {
  id: IslandId;
  component: ComponentType<P>;
  /** Serialisable props; never secrets (they are visible in the page). */
  props: P;
}

export function Island<P extends object>({ id, component: Component, props }: IslandProps<P>) {
  const markup = renderToString(<CSPProvider disableStyleElements><Component {...props} /></CSPProvider>);
  return <div data-nathan-island={id} data-props={JSON.stringify(props)} dangerouslySetInnerHTML={{ __html: markup }} />;
}
