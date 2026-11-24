import { readFile } from "node:fs/promises";
import { loadConfig } from "./config.mjs";
import { CloudflareClient, inspectDeployment } from "./cloudflare.mjs";
import { ask, yesNo, secretPrompt } from "./prompts.mjs";
import { createGeneratedConfig, runCli } from "./wrangler.mjs";
import {
  PROVIDER_IDS, getProvider, providerGuide as registryGuide, envBundleName, validateProviderCredentials
} from "../../src/shared/providers.mjs";

/** CLI view of the shared provider registry; the callback comes from the same function as Studio and the installer. */
export function providerGuide(name, hostname) {
  if (!PROVIDER_IDS.includes(name)) throw Error("Unknown upstream OAuth provider. Supported: " + PROVIDER_IDS.join(", "));
  const g = registryGuide(name, hostname);
  return {
    provider: g.id,
    name: g.name,
    consoleUrl: g.consoleUrl,
    consoleHint: g.consoleHint,
    callback: g.callbackUrl,
    responseMode: g.responseMode,
    scopes: g.scopes,
    steps: g.steps,
    instructions: g.steps.map((s, i) => (i + 1) + ". " + s).join("\n"),
    gotchas: g.gotchas,
    emailTrust: g.emailTrust,
    fields: g.fields.map(f => ({ name: f.name, label: f.label, secret: f.secret, hint: f.hint })),
    secretBindings: [envBundleName(g.id)]
  };
}

function printGuide(info) {
  console.log("\n" + info.name + " sign-in setup");
  console.log("Console:  " + (info.consoleUrl || info.consoleHint));
  console.log("Callback: " + info.callback + (info.responseMode === "form_post" ? "  (Apple posts the response: response_mode=form_post)" : ""));
  console.log("Scopes:   " + info.scopes.join(" "));
  console.log("\n" + info.instructions);
  if (info.gotchas.length) console.log("\nWatch out:\n" + info.gotchas.map(g => "- " + g).join("\n"));
  console.log("\nEmail trust: " + info.emailTrust + "\n");
}

/** Collects one provider's fields: masked prompts for secrets, a file path for the Apple .p8 key. */
async function collectCredentials(id) {
  const values = {};
  for (const field of getProvider(id).fields) {
    if (field.secret && field.file) {
      const path = await ask(field.label + " file path (" + field.file + ")");
      values[field.name] = await readFile(path, "utf8");
    } else if (field.secret) values[field.name] = await secretPrompt(field.label + " (masked)");
    else if (field.checkbox) values[field.name] = (await yesNo(field.label + "? " + field.hint)) ? "true" : "";
    else values[field.name] = await ask(field.label + (field.optional ? " (optional)" : "") + (field.hint ? " — " + field.hint : ""));
  }
  return validateProviderCredentials(id, values);
}

/**
 * What `providers add --apply` changed. The Worker secret is the provider's single source of
 * truth from now on: it takes effect on the next request, wins over credentials saved in
 * Identity Studio, voids the previous test sign-in, and keeps a Studio disable in force.
 */
export function cliSecretNotice(id) {
  const name = getProvider(id).name, secret = envBundleName(id);
  return [
    name + " credentials stored in the Cloudflare Worker secret " + secret + ". They take effect on the next sign-in request.",
    "This Worker secret is now the only source of " + name + " credentials: it overrides credentials saved in Identity Studio, and Studio",
    "will refuse to save " + name + " credentials until you delete it (npx wrangler secret delete " + secret + ").",
    "Changing credentials voids the previous test sign-in. In Identity Studio → Social login providers, run a test sign-in as an",
    "administrator before relying on " + name + ". If " + name + " was disabled in Studio, it stays disabled until you enable it there."
  ].join("\n");
}

export async function providerCommand(args, file, apply) {
  const cfg = await loadConfig(file);
  const action = args[0] || "list";
  if (action === "list") {
    console.log(JSON.stringify({ providers: cfg.providers, supported: PROVIDER_IDS }, null, 2));
    return;
  }
  if (action !== "guide" && action !== "add") throw Error("Expected: providers <list|guide|add> <" + PROVIDER_IDS.join("|") + ">");
  const name = args[1];
  const info = providerGuide(name, cfg.hostname);
  printGuide(info);
  if (action === "guide") return;
  if (!apply) throw Error("Credential install requires --apply; no secrets changed");
  if (!cfg.accountId) throw Error("Cloudflare accountId required before configuring providers");
  const api = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN, cfg.accountId);
  const current = await inspectDeployment(api, cfg);
  if (!current.existingAuthWorker || !current.existingDatabase) throw Error("Deploy the Nathan Auth Worker first");
  const databaseId = current.existingDatabase.uuid || current.existingDatabase.id;
  const configPath = await createGeneratedConfig(cfg, databaseId);
  const values = await collectCredentials(name);
  if (!(await yesNo("Store " + info.name + " credentials as the Cloudflare Worker secret " + info.secretBindings[0] + "?"))) throw Error("Cancelled");
  // No secrets are saved in the local manifest or process arguments; the bundle goes over stdin.
  await runCli("npx", ["wrangler", "secret", "put", info.secretBindings[0], "--config", configPath], { input: JSON.stringify(values) });
  console.log(cliSecretNotice(name));
}
