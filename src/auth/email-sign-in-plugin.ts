import { emailOTP, twoFactor } from "better-auth/plugins";
import { generateRandomString } from "better-auth/crypto";
import { EMAIL_ATTEMPTS, EMAIL_TTL } from "./email-sign-in-policy";

/** Keep just the two server calls the hosted flow uses. The public auth instance never installs this plugin. The database hash covers a 256-bit browser secret as well as the mailed digits. */
export function hostedEmailOTP(proofPrefix?: string) {
  const plugin = emailOTP({
    expiresIn: EMAIL_TTL, allowedAttempts: EMAIL_ATTEMPTS, storeOTP: "hashed",
    generateOTP() {
      if (!proofPrefix) throw Error("Missing hosted sign-in request");
      return proofPrefix + "." + generateRandomString(6, "0-9");
    },
    sendVerificationOTP: async () => { throw Error("Use the hosted email sender"); }
  });
  const { createVerificationOTP, signInEmailOTP } = plugin.endpoints;
  return { ...plugin, endpoints: { createVerificationOTP, signInEmailOTP } };
}

/** The pinned two-factor plugin challenges password sign-ins. Apply the same challenge to the
 * email-OTP primary factor, before the OAuth provider resumes a newly authenticated session. */
export function hostedTwoFactor(issuer: string) {
  const plugin = twoFactor({ allowPasswordless: true, issuer });
  for (const hook of plugin.hooks.after) {
    const matches = hook.matcher;
    hook.matcher = ctx => matches(ctx.path === "/sign-in/email-otp" ? { ...ctx, path: "/sign-in/email" } : ctx);
  }
  return plugin;
}
