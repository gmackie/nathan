import { loadConfig } from "./config.mjs";
import { CloudflareClient, inspectDeployment } from "./cloudflare.mjs";
import { ask, yesNo, secretPrompt } from "./prompts.mjs";
import { createGeneratedConfig, runCli } from "./wrangler.mjs";

const guides = {
  google: {
    label: "Google OAuth",
    url: "https://console.cloud.google.com/auth/clients",
    fields: ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"],
    instructions: "Create a Web application OAuth client. Configure an OAuth consent screen, choose internal/external audience, add exact redirect URI and paste credentials."
  },
  github: {
    label: "GitHub OAuth",
    url: "https://github.com/settings/developers",
    fields: ["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"],
    instructions: "Choose OAuth Apps → New OAuth App. Set the authorization callback URL exactly and paste client credentials."
  }
};
export function providerGuide(name, hostname) {
  const p = guides[name];
  if (!p) throw Error("Unknown upstream OAuth provider. Supported: google, github");
  return {
    provider: name,
    consoleUrl: p.url,
    callback: "https://" + hostname + "/api/auth/callback/" + name,
    instructions: p.instructions,
    secretBindings: p.fields
  };
}
export async function providerCommand(args, file, apply) {
  const cfg = await loadConfig(file);
  const action = args[0] || "list";
  if (action === "list") {
    console.log(JSON.stringify({ providers: cfg.providers, supported: Object.keys(guides) }, null, 2));
    return;
  }
  const name = args[1];
  const info = providerGuide(name, cfg.hostname);
  console.log(JSON.stringify(info, null, 2));
  if (action === "guide") return;
  if (action !== "add") throw Error("Expected: providers <list|guide|add> <google|github>");
  if (!apply) throw Error("Credential install requires --apply; no secrets changed");
  if (!cfg.accountId) throw Error("Cloudflare accountId required before configuring providers");
  const api = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN, cfg.accountId);
  const current = await inspectDeployment(api, cfg);
  if (!current.existingAuthWorker || !current.existingDatabase) throw Error("Deploy the Nathan Auth Worker first");
  const databaseId = current.existingDatabase.uuid || current.existingDatabase.id;
  const configPath = await createGeneratedConfig(cfg, databaseId);
  if (!(await yesNo("Store provider credentials as Cloudflare Worker secrets?"))) throw Error("Cancelled");
  const clientId = await ask("OAuth client ID");
  const clientSecret = await secretPrompt("OAuth client secret (masked)");
  if (!clientId || !clientSecret) throw Error("Client ID and secret are required");
  // No secrets are saved in the local manifest or process arguments.
  await runCli("npx", ["wrangler", "secret", "put", info.secretBindings[0], "--config", configPath], {input:clientId});
  await runCli("npx", ["wrangler", "secret", "put", info.secretBindings[1], "--config", configPath], {input:clientSecret});
  console.log("Provider credentials stored in Cloudflare. Verify the OAuth callback with a test account.");
}
