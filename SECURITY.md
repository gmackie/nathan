# Security policy

Nathan is **experimental**. Do not rely on it for production authentication, regulated environments, or protecting sensitive assets before the release gates are completed.

## Report a vulnerability

Use GitHub's **Report a vulnerability** feature on the Security tab of the repository if enabled. Do not publish proof-of-concept exploits, credentials, tokens or private account information in public issues.

## Scope and release gates

Read [docs/security.md](docs/security.md). In particular, an IdP requires independent testing of OAuth/OIDC conformance, cross-client token replay, redirect/CSRF state, account recovery and MFA enforcement. A gateway requires proof that every origin route is private, including previews and workers.dev.

No formal compliance certification, penetration-test result, or production audit is claimed. Automated tests cover only a fraction of the required controls.

## Dependencies

Pin Better Auth and official plugin versions together. Review upstream security advisories and use a lockfile before tagging a release. Never run third-party Better Auth plugins inside the IdP without review.
