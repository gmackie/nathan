/**
 * NATH-24 Studio API v1: enterprise SSO. OIDC connections and domain verification, inbound SAML
 * connections (NATH-10), and Nathan as a SAML IdP for downstream service providers (NATH-12).
 */
import { listSso, registerEnterpriseOidc, requestEnterpriseVerification, verifyEnterpriseDomain } from "../admin-service";
import { listSamlConnections, previewSamlMetadata, createSamlConnection, setSamlConnectionEnabled,
  setSamlProvisioning, addSamlCertificate, retireSamlCertificate } from "../saml-admin";
import { reason as samlReason, SAML_ADMIN_REFUSAL } from "../saml-routes";
import { samlIdpOverview, applySamlIdpOperation, publicMessage as samlIdpMessage, STUDIO_MAX_BYTES as SAML_IDP_MAX_BYTES } from "../saml-idp";
import type { StudioRoute } from "./router";
import { rejected } from "./http";
import {
  noInput, ssoOidcRegisterInput, ssoDomainInput, samlPreviewInput, samlConnectionCreateInput, samlStatusInput,
  samlProvisioningInput, samlCertificateAddInput, samlCertificateRetireInput, samlIdpInput
} from "./schemas";

export const SSO_REFUSAL = "Operation denied or rejected by identity provider";
const samlRefusal = (error: unknown) => rejected(samlReason(error, SAML_ADMIN_REFUSAL));
const SAML_MAX_BYTES = 160_000;

export const routes: StudioRoute[] = [
  { method: "GET", path: "/sso", action: "sso.read", input: noInput, run: async ({ env }) => ({ providers: await listSso(env) }) },
  { method: "POST", path: "/sso/oidc", action: "sso.oidc.register", input: ssoOidcRegisterInput, maxBytes: 16384, fallback: SSO_REFUSAL,
    run: ({ env, auth, request, actor }, body) => registerEnterpriseOidc(auth, env, request.headers, body, actor) },
  { method: "POST", path: "/sso/token", action: "sso.domain.token", input: ssoDomainInput, maxBytes: 16384, fallback: SSO_REFUSAL,
    run: ({ env, auth, request, actor }, body) => requestEnterpriseVerification(auth, env, request.headers, body, actor) },
  { method: "POST", path: "/sso/verify", action: "sso.domain.verify", input: ssoDomainInput, maxBytes: 16384, fallback: SSO_REFUSAL,
    run: ({ env, auth, request, actor }, body) => verifyEnterpriseDomain(auth, env, request.headers, body, actor) },

  { method: "GET", path: "/saml", action: "saml.read", input: noInput,
    run: async ({ env }) => ({ enterpriseSso: env.ENTERPRISE_SSO === "true", connections: await listSamlConnections(env) }) },
  { method: "POST", path: "/saml/preview", action: "saml.preview", input: samlPreviewInput, maxBytes: SAML_MAX_BYTES, refusal: samlRefusal,
    run: ({ env, actor }, body) => previewSamlMetadata(env, body, actor) },
  { method: "POST", path: "/saml/connections", action: "saml.connections.create", input: samlConnectionCreateInput, maxBytes: SAML_MAX_BYTES, refusal: samlRefusal,
    run: ({ env, auth, request, actor }, body) => createSamlConnection(auth, env, request.headers, body, actor) },
  { method: "POST", path: "/saml/status", action: "saml.status", input: samlStatusInput, maxBytes: SAML_MAX_BYTES, refusal: samlRefusal,
    run: ({ env, actor }, body) => setSamlConnectionEnabled(env, body, actor) },
  { method: "POST", path: "/saml/provisioning", action: "saml.provisioning", input: samlProvisioningInput, maxBytes: SAML_MAX_BYTES, refusal: samlRefusal,
    run: ({ env, actor }, body) => setSamlProvisioning(env, body, actor) },
  { method: "POST", path: "/saml/certificates", action: "saml.certificates.add", input: samlCertificateAddInput, maxBytes: SAML_MAX_BYTES, refusal: samlRefusal,
    run: ({ env, actor }, body) => addSamlCertificate(env, body, actor) },
  { method: "POST", path: "/saml/certificates/retire", action: "saml.certificates.retire", input: samlCertificateRetireInput, maxBytes: SAML_MAX_BYTES, refusal: samlRefusal,
    run: ({ env, actor }, body) => retireSamlCertificate(env, body, actor) },

  { method: "GET", path: "/saml-idp", action: "saml-idp.read", input: noInput, run: ({ env }) => samlIdpOverview(env) },
  { method: "POST", path: "/saml-idp", action: "saml-idp.apply", input: samlIdpInput, maxBytes: SAML_IDP_MAX_BYTES,
    refusal: error => rejected(samlIdpMessage(error)), run: ({ env, actor }, body) => applySamlIdpOperation(env, body, actor) }
];
