import type { NathanService } from "@nathan/worker";

interface Env {
  IDENTITY: Service<NathanService>;
}

export default {
  fetch(request, env) {
    return env.IDENTITY.handle(request);
  }
} satisfies ExportedHandler<Env>;
