# Gatekeeper and Nathan access tokens

<!-- gatekeeper-provider-entry -->
```json
{
  "id": "nathan",
  "kind": "oidc",
  "issuer": "https://login.example.com/api/auth",
  "jwksUri": "https://login.example.com/api/auth/jwks",
  "audience": "https://gatekeeper.example.com/api",
  "algorithms": ["EdDSA"],
  "accessTokenProfile": { "kind": "rfc9068" },
  "kindClaim": { "name": "principal_kind", "values": { "user": "human", "machine": "service", "agent": "agent" } },
  "maxTokenLifetimeSeconds": 900
}
```
