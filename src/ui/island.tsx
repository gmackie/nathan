/**
 * NATH-37: server-side island container. Renders `Component` inside a marked <div> and stores its
 * props as JSON in an attribute (React escapes it). The matching bundle in src/ui/islands/
 * hydrates the same component with the same props. Pass the id in renderPage's `islands` too;
 * renderPage refuses a page whose markup and `islands` option disagree.
 */
import type { ComponentType } from "react";
import type { IslandId } from "./island-ids.ts";

export interface IslandProps<P extends object> {
  id: IslandId;
  component: ComponentType<P>;
  /** Serialisable props; never secrets (they are visible in the page). */
  props: P;
}

export function Island<P extends object>({ id, component: Component, props }: IslandProps<P>) {
  return (
    <div data-nathan-island={id} data-props={JSON.stringify(props)}>
      <Component {...props} />
    </div>
  );
}
