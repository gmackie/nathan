# Contributing to Nathan

Nathan is intended to be an MIT-licensed, customer-owned Cloudflare blueprint. Please open an issue before a large architectural change, especially identity protocol or deployment decisions.

## Local development

Node 22+; copy `nathan.config.example.json` to `nathan.config.json`; run `npm install` and `npm test`. You can inspect the proposed infrastructure without Cloudflare credentials using `npm run plan`.

Do not put credentials in commits. Do not use test tokens with production IdPs. Never enable public application routes until the origin-bypass threat model has been checked.

## Quality bar

- Tests for new inputs, denials and failure states.
- Strict OAuth issuer/audience/redirect validation.
- Idempotent installer operations with a dry-run diff.
- Document migrations and rollback steps.
- Keep users informed when a feature is scaffolded but not deployable.
- No silent weakening of session, CSRF, MFA or key-management protections.
