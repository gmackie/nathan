import { WorkflowEntrypoint } from "cloudflare:workers";
import { NonRetryableError } from "cloudflare:workflows";
import puppeteer from "@cloudflare/puppeteer";
import { CloudflareClient } from "../../../scripts/lib/cloudflare.mjs";
import { account, applyAndVerify, issuer } from "./registration.mjs";
import { authorizationUrl, completeRegistration, instanceId, isSignIn, issuedVersion,
  registerPublicClient, requireApprovedTarget, verifyRedirect, withIssuedCredential } from "./hosted.mjs";

async function browserProbe(binding, clientId) {
  const url = authorizationUrl(clientId);
  const browser = await puppeteer.launch(binding, {
    recording:false, guardrails:{allowedDomains:[new URL(issuer).hostname]}
  });
  try {
    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    await page.setJavaScriptEnabled(false);
    await page.setRequestInterception(true);
    page.on("request", req => {
      const allow = req.isNavigationRequest() && req.frame() === page.mainFrame() && req.method() === "GET" &&
        (req.url() === url.href || isSignIn(new URL(req.url())));
      void (allow ? req.continue() : req.abort("blockedbyclient")).catch(() => {});
    });
    const response = await page.goto(url.href, {waitUntil:"domcontentloaded",timeout:25000});
    const chain = response?.request().redirectChain() ?? [];
    const first = chain.length ? chain[0].response() : response;
    return verifyRedirect(url, {firstUrl:first?.url(),status:first?.status(),location:first?.headers().location,
      hops:chain.length,finalStatus:response?.status(),finalUrl:response?.url(),
      pageTitle:response?.status() === 400 && !chain.length ? await page.title() : null});
  } catch {
    throw Error("Cloudflare Browser Run could not verify the OAuth sign-in redirect");
  } finally {
    await browser.close();
  }
}

export class EducateOSRegistration extends WorkflowEntrypoint {
  async run(event, step) {
    if (event.instanceId !== instanceId || Object.keys(event.payload ?? {}).length !== 0) {
      throw new NonRetryableError("Only the configured one-time registration is supported");
    }
    const {NATHAN_STAGING_USER_ID:userId, NATHAN_PROBE_CLIENT_ID:originalClient} = this.env;
    try {
      requireApprovedTarget(userId, originalClient);
    } catch {
      throw new NonRetryableError("Configuration does not match the approved staging target");
    }
    const agent = this.env.LLAVERO_NATHAN_CLI_TOKEN;
    if (!agent) throw new NonRetryableError("Hosted nathan-cli identity is not enrolled");
    return completeRegistration(step,originalClient,{
      version:() => issuedVersion(agent),
      apply:() => withIssuedCredential(agent,async value => {
        try {
          return await applyAndVerify(new CloudflareClient(value,account),userId,originalClient);
        } catch (error) {
          if (error.message === "Staging registration needs reconciliation") throw new NonRetryableError(error.message);
          // A provider response may include request details. Persist a fixed error only.
          throw Error("Unable to verify the registration in staging D1");
        }
      }),
      register:() => registerPublicClient(),
      probe:clientId => browserProbe(this.env.BROWSER,clientId)
    });
  }
}

export default {fetch() { return new Response(null,{status:404}); }};
