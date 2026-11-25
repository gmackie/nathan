import { AsyncLocalStorage } from "node:async_hooks";
import auth, { NathanScimDirectory as Directory } from "../../../.nathan/build-auth/worker.js";
export * from "../../../.nathan/build-auth/worker.js";

// Only requests carrying a test timestamp use the supplied time. Concurrent requests keep their own clocks.
const clock = new AsyncLocalStorage();
const realNow = Date.now;
Date.now = () => clock.getStore() ?? realNow();

export default {
  ...auth,
  fetch(request, env, ctx) {
    const time = request.headers.get("X-Test-Now");
    if (time === null) return auth.fetch(request, env, ctx);
    return clock.run(Number(time), () => auth.fetch(request, env, ctx));
  }
};

export class NathanScimDirectory extends Directory {
  async alarm() {
    if (this.env.TEST_ALARM) await this.env.TEST_ALARM.fetch("https://test.invalid/alarm");
    return super.alarm();
  }
}
