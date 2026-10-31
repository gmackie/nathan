# Nathan's very serious marketing operation

Static Cloudflare Pages site. No framework, backend, analytics, cookies, signup
service or external font/image requests. The build needs Node.js 22+ and uses
only Node's standard library. It does not build or deploy the identity Workers.

```sh
npm run build:site
```

The generated page is `dist/site/index.html`. Its styles, cost model and browser
interactions are inline. The original naming-lore image has a smaller WebP
derivative; the source PNG under `assets/` is unchanged. The build also exports
a sanitized static/interactive cost report, captured vendor sources, model,
CSVs and figures under `dist/site/reports/`. Internal issue references and
worktree metadata are excluded. `build-manifest.json` records file hashes.

Edit `site/index.html`, `site/styles.css` and `site/site.mjs`, then rebuild.
Price inputs and workload assumptions live in
`plans/reports/nathan-vs-clerk-2026-10-28/`; regenerate that model and report
before updating the site's comparison. The build rejects mismatched saved
baseline results. All headline costs are projections at October 2026 list
prices, not measured invoices or supported capacity.

## Cloudflare Pages

Production: [nathan-site-1eb.pages.dev](https://nathan-site-1eb.pages.dev/).
The Pages project is `nathan-site`, with `main` as its production branch.
`wrangler.jsonc` pins the account used for this static site so deployments
do not select another authenticated account accidentally.

Use a Pages project connected to this repository. Set the build command to
`npm run build:site`, output directory to `dist/site`, and repository root to
the root directory. Configure the actual production branch/domain in your
Cloudflare account. `wrangler.jsonc` describes only this static Pages site;
identity, gateway and installer Workers keep their explicit configurations.

Set Pages build environment variables `NODE_VERSION=22` and
`SKIP_DEPENDENCY_INSTALL=true`. The static build uses no installed packages;
skipping automatic dependency installation keeps it independent of the
authentication Workers' dependencies. Python is only needed for local/CI
verification, not the Pages production build.

For a previously created Pages project, an authenticated operator can deploy
the reviewed output with Wrangler:

```sh
npx wrangler pages deploy dist/site --project-name nathan-site --branch main
```

The command publishes publicly. Run it only when you intend to publish.
The site build itself does not create resources, register a domain, or deploy
the authentication Workers.

Cloudflare applies `_headers` on delivery: hashes allow the exact inline
scripts, and the page makes no runtime network requests. If another CDN serves
the build, apply equivalent response headers there. If changing the build
directory or adding runtime code, review the CSP and site-only scope first.

## Positioning and content

Nathan is an independent open-source authentication blueprint that runs in
the operator's Cloudflare account. It is not a Cloudflare product and is not
affiliated with or endorsed by Cloudflare. Make independence visible above the
fold and in search/social metadata. Describe Cloudflare as the runtime rather
than as Nathan's publisher or sponsor. Lead with the actual stack: Workers runs the identity provider,
D1 holds identities and sessions, Better Auth provides the foundation, and
the operator controls the Cloudflare account, source, deployment and keys.
External apps can connect through explicit OIDC registration; their acceptance
flows are launch goals pending verification. There is no separate Nathan-hosted
auth service to rent.

The public site stands on its own. Do not position it as an intermediary for
another login product, link to a peer's hosted auth, or bring those products
and their creators into disclaimers, FAQs, metadata or exported reports. The
Clerk comparison is the separately requested, sourced economics work.

The campaign leads with “You can see everything”: public Nathan source,
published price inputs and workload assumptions, reproducible calculations,
reviewable agent changes and visible unfinished release work. Credentials,
signing keys and personal data remain private. The claim does not extend to
Cloudflare's proprietary platform or make open source a security guarantee.

Assumed audience overlap with fans of dry, elaborate business comedy informs
the tone; no audience research supports publishing that overlap as a fact.
Use an impersonal project voice: no “we,” “our” or “us,” and no publisher
ownership claims. Describe the MIT license and the operator's control of a
deployment without implying transfer of the upstream copyright. Preserve
third-party quotations and required legal attribution.

Aim the sharper jokes at rent extraction, lock-in, growth theater and the
proposed operating model. The orange/black palette and Workers/D1 section establish
the platform without copying an official Cloudflare website or logo system.

The voice uses original deadpan business satire. The presentation must produce
its evidence: a link to source, arithmetic, ownership terms or release gates.
Keep cultural references implicit. No named celebrity committee, film synopsis,
documentary link or FAQ explaining the joke. Let the headline, original business
satire and product evidence carry it. The existing naming diagram remains
project lore. Do not invent quotes, appointments, endorsements or personal
allegations.

Clerk jokes target its published monthly-retained-user pricing and the model's
arithmetic. Never imply fraud, undisclosed billing, insecurity or equivalent
support/compliance. Keep cases favoring Clerk visible alongside the headline;
self-hosting labor is real. “Clerk's pricing is public. So is the
multiplication” is the editorial premise, not a new measured cost claim.
The serious claims stay literal: MIT license, operator-controlled code/account/
identities/keys, ongoing Cloudflare dependency, operator responsibility,
pre-beta status and unverified launch journeys. Product scope is a release
goal, not a claim that the launch gates have passed. Do not publish a fake
install command, signup flow, testimonial, endorsement or purported funding history.

Editorial references reviewed on 2026-10-29:

- [WIRED: The New Fan's Guide to the Unreal World of Nathan Fielder](https://www.wired.com/story/the-new-fans-guide-to-the-unreal-world-of-nathan-fielder/), Miles Klee, 2026-10-16.
- [WIRED: Nathan Fielder Tells Us Everything](https://www.wired.com/story/nathan-fielder-tells-us-everything/), Katie Drummond, 2026-10-19.
- [Reason: Nathan Fielder Made a Dishonest Movie](https://reason.com/2026/10/26/nathan-fielder-made-a-dishonest-movie/), Christian Britschgi, 2026-10-26.

These informed broad themes of escalating problem solving, trust, incentives
and the cost of the proposed solution. The site uses original copy; it does
not quote his scripts, imitate his exact voice or present the project as his
work. Documentary criticism does not establish product claims, and unrelated
allegations do not belong in the marketing. These editorial references belong
in the notes, rather than an explanation on the product page. The naming image
is existing project lore, with an explicit non-affiliation statement.

The clipboard action copies a review-oriented agent brief. It has a visible
manual-copy fallback and does not authorize agents to deploy or manage live
identity data. A human remains responsible for security decisions.

## Local verification

```sh
npm run verify:site
```

This rebuilds and checks the actual generated HTML/assets, local links,
sanitized report export, CSP hashes, integrity manifest, and all selectable
price scenarios. Inspect desktop and phone layouts plus keyboard navigation
when changing design or interactions. Runtime authentication tests are separate.
