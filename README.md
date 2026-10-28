# nathan 🌭

**Cloudflare-native authentication with Better Auth.** Self-hosted in your account.

> [!WARNING]
> Early development. Not production-ready. Authentication and gateway enforcement require security testing.

Nathan aims to make protecting a Worker as straightforward as adding an app, while also serving as an OIDC identity provider for external applications.

## What we're building

- A Better Auth-based Identity Provider on Cloudflare Workers and D1.
- A guided setup for account selection, DNS/custom hostnames, OAuth providers, SSO and MFA.
- A native service-binding guard and optional gateway for unmodified Workers.
- An application registry for Worker and non-Worker OIDC clients.
- A declarative configuration model and plugin-aware administration UI.
- A resumable, customer-owned deployment wizard inspired by [Coworkers](https://github.com/fayazara/coworkers).

## Status

The repository is being bootstrapped. **Do not use it to secure production applications yet.** The target install is `npx nathan init`, but it is not yet a published command.

## Why “nathan”?

Better Auth + Cloudflare → Benjamin Franklin → hundred-dollar *Franklins* → Ball Park Franks → Nathan’s Famous Hot Dogs → Nathan Fielder.

The original naming-origin image is being prepared for the README; it is not yet committed.

## Design

See [architecture](docs/architecture.md), [security](docs/security.md), and [roadmap](docs/roadmap.md).

## License

License selection pending. Please do not assume an open-source license has been granted.
