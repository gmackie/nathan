/**
 * NATH-37: server-side island container. Renders `Component` inside a marked <div> and stores its
 * props as JSON in an attribute (React escapes it). The matching bundle in src/ui/islands/
 * hydrates the same component with the same props. Pass the id in renderPage's `islands` too;
 * renderPage refuses a page whose markup and `islands` option disagree.
 *
 * NATH-40: the component is rendered in its own React root, exactly as hydrateIslands() hydrates
 * it (hydrateRoot(container, <Component {...props} />)). React's useId values depend on the
 * position in the tree, so rendering it inside the page tree gave ids (Base UI's label/control,
 * aria-* wiring) that the browser-side root never reproduces. The inner markup is React's own
 * escaped output; renderPage still moves its style attributes to nonce'd classes and runs its
 * CSP checks over the whole document. The inner root has no CSPProvider nonce, so a component
 * that would emit a <style> element fails renderPage's check (closed) instead of shipping it.
 */
import type { ComponentType } from "react";
import { CSPProvider } from "@cloudflare/kumo/primitives/csp-provider";
import { renderToString } from "react-dom/server";
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
