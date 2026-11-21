/** Authenticated identity only. Roles, organization membership and resource facts are PIPs. */
export type PrincipalKind = "anonymous" | "human" | "service" | "agent" | "unknown";
export type SubjectNamespace = "sub" | "access-service-token";
export interface Principal {
  readonly id: string;
  readonly providerId: string;
  readonly issuer: string;
  readonly subject: string;
  readonly subjectNamespace: SubjectNamespace;
  readonly kind: PrincipalKind;
  readonly expiresAt: number;
  /** False unless a configured, verified authentication-assurance mapping establishes MFA. */
  readonly mfa: boolean;
  /** Human-readable identifier from the provider's configured `handleClaim` (e.g. an email). Display and operator-role matching only. */
  readonly handle?: string;
  readonly authentication?: {
    readonly credentialType: "oauth-access-token" | "cloudflare-access";
    readonly issuedAt: number;
    readonly audiences: readonly string[];
    readonly scopes: readonly string[];
    readonly clientId?: string;
  };
}
/** Never key PIP/cache entries by bare sub or email. Access service tokens have empty sub. */
export const principalId = (issuer: string, subject: string, namespace: SubjectNamespace = "sub"): string =>
  `principal:${encodeURIComponent(issuer)}:${namespace}:${encodeURIComponent(subject)}`;
export const anonymous = (): Principal => ({
  id: principalId("gatekeeper:anonymous", "anonymous"),
  providerId: "anonymous", issuer: "gatekeeper:anonymous", subject: "anonymous", subjectNamespace: "sub",
  kind: "anonymous", expiresAt: 0, mfa: false,
});
