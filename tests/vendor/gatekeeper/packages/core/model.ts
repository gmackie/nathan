import { principalId, type Principal } from "../principal/model.ts";
export { anonymous, principalId, type Principal, type PrincipalKind } from "../principal/model.ts";
export interface PolicyInput {
  readonly action: string;
  readonly now: number;
  /** Why the caller says it is acting. Empty when the request declares nothing. */
  readonly purpose: string;
  readonly principal: Principal;
  readonly membership: {
    readonly principalId: string;
    readonly tenant: string;
    readonly roles: readonly string[];
    readonly active: boolean;
    readonly emailVerified: boolean;
    readonly observedAt: number;
    readonly expiresAt: number;
  };
  readonly resource: {
    readonly id: string;
    readonly tenant: string;
    readonly visibility: "public" | "private";
    readonly state: "draft" | "approved" | "published";
    /** Forge taxonomy node for the data behind this resource (`data.contact.email`); `data.unknown` when unclassified. */
    readonly dataClass: string;
    /** Derived from the class, never stored beside it: handling only tightens down the taxonomy and unclassified resolves to restricted. */
    readonly handling: string;
    readonly personal: "yes" | "no" | "unknown";
    readonly categories: readonly string[];
    readonly identifiability: string;
    /** Where the record is kept (education, healthcare, …); empty when the resource declares none. */
    readonly recordContext: string;
    readonly version: number;
    readonly legalHold: boolean;
  };
  /** Attributes the organisation declared and its own systems populated. Split by subject so a policy naming
   * `department` on a person can never accidentally read a resource's. `stale` lists keys whose values aged out of
   * their declared freshness window: they are withheld rather than used, and requiring one yields indeterminate. */
  readonly attributes: {
    readonly principal: Readonly<Record<string, readonly string[]>>;
    readonly resource: Readonly<Record<string, readonly string[]>>;
    readonly stale: readonly string[];
  };
  readonly approval: {
    readonly approved: boolean;
    /** Issuer-qualified principal ID, not an email or bare IdP sub. */
    readonly approver: string;
    /** Who the attestation is for. Empty means it vouches for any caller; otherwise only this principal may rely on it. */
    readonly subject: string;
    readonly resourceId: string;
    readonly resourceVersion: number;
    readonly expiresAt: number;
  };
}
/** No org attributes resolved. Explicit rather than optional: the PDP should never have to tell "none recorded"
 * apart from "the resolver forgot to look". */
export const NO_ATTRIBUTES: PolicyInput["attributes"] = {principal: {}, resource: {}, stale: []};
export type Outcome = "allow" | "deny" | "challenge" | "indeterminate";
export type Obligation = "consumeApproval" | "durableAudit" | "versionCheckedWrite";
/** Rule-level explanation emitted by the policy in the same evaluation as the decision. */
export interface PolicyTrace {
  readonly known: boolean;
  readonly decision: string;
  readonly include: readonly {selector: string; values: readonly string[]; matched: boolean}[];
  readonly require: readonly {selector: string; values: readonly string[]; kind: "hard" | "challenge"; satisfied: boolean; key?: string}[];
  readonly facts: Readonly<Record<string, boolean>>;
}
export interface Decision {
  readonly outcome: Outcome;
  readonly reason: string;
  readonly obligations: readonly Obligation[];
  readonly trace?: PolicyTrace;
}
export interface DecisionReceipt extends Decision {
  readonly decisionId: string;
  readonly policyRevision: string;
  readonly action: string;
}
export class GatekeeperError extends Error {
  readonly code: string;
  constructor(code: string, message: string) { super(message); this.code = code; }
}
export function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
export function parseDecision(value: unknown): Decision {
  if (!record(value) || typeof value.outcome !== "string" || !["allow", "deny", "challenge", "indeterminate"].includes(value.outcome) ||
      typeof value.reason !== "string" || value.reason.length > 128 || !Array.isArray(value.obligations) ||
      value.obligations.length > 8 || value.obligations.some(x => !["consumeApproval", "durableAudit", "versionCheckedWrite"].includes(x))) {
    throw new GatekeeperError("InvalidDecision", "Policy returned an unsupported decision");
  }
  const trace = record(value.trace) && typeof value.trace.known === "boolean" && Array.isArray(value.trace.include) && Array.isArray(value.trace.require) && record(value.trace.facts) ? value.trace as unknown as PolicyTrace : undefined;
  return { outcome: value.outcome as Outcome, reason: value.reason, obligations: value.obligations as Obligation[], ...(trace ? {trace} : {}) };
}
export function requireExecutable(decision: Decision): void {
  if (decision.outcome !== "allow") throw new GatekeeperError("NotAllowed", decision.reason);
  if (decision.obligations.length) throw new GatekeeperError("UnfulfilledObligation", "Write executors are not installed in this initial slice");
}
export function assertInputBudget(input: unknown, maxBytes = 32768): void {
  const json = JSON.stringify(input);
  if (json === undefined || new TextEncoder().encode(json).length > maxBytes) {
    throw new GatekeeperError("InputBudgetExceeded", "Authorization input exceeds the configured byte budget");
  }
}
export function snapshotUsable(snapshot: {observedAt: number; expiresAt: number}, now: number, maxAgeMs: number): boolean {
  return Number.isFinite(now) && Number.isFinite(snapshot.observedAt) && Number.isFinite(snapshot.expiresAt) &&
    snapshot.observedAt <= now && now < snapshot.expiresAt && now - snapshot.observedAt < maxAgeMs;
}
export function assertPolicyInput(input: unknown): asserts input is PolicyInput {
  const invalid = (): never => { throw new GatekeeperError("InvalidPolicyInput", "Required authorization facts are malformed"); };
  const text = (x: unknown, empty = false, limit = 512) => typeof x === "string" && x.length <= limit && (empty || x.length > 0);
  const time = (x: unknown) => typeof x === "number" && Number.isFinite(x) && x >= 0;
  if (!record(input)) return invalid();
  const {principal: p, membership: m, resource: r, approval: a} = input;
  if (!record(p) || !record(m) || !record(r) || !record(a)) return invalid();
  if (!text(input.action) || !time(input.now) || !text(input.purpose, true, 128) || !["anonymous","human","service","agent","unknown"].includes(String(p.kind)) ||
      typeof p.kind !== "string" || !text(p.issuer) || !text(p.subject) || !time(p.expiresAt) || typeof p.mfa !== "boolean" ||
      !text(p.providerId) || !["sub", "access-service-token"].includes(String(p.subjectNamespace)) ||
      p.id !== principalId(p.issuer as string, p.subject as string, p.subjectNamespace as Principal["subjectNamespace"])) return invalid();
  if (!text(m.principalId, false, 4096) || !text(m.tenant, true) || !Array.isArray(m.roles) || m.roles.length > 256 || m.roles.some(role => !text(role)) ||
      typeof m.active !== "boolean" || typeof m.emailVerified !== "boolean" || !time(m.observedAt) || !time(m.expiresAt)) return invalid();
  if (!text(r.id) || !text(r.tenant) || !["public","private"].includes(String(r.visibility)) || !text(r.dataClass) || !text(r.handling) || !["yes","no","unknown"].includes(String(r.personal)) || !Array.isArray(r.categories) || r.categories.length > 24 || r.categories.some(c => !text(c)) || !text(r.identifiability) || !text(r.recordContext, true, 64) ||
      !["draft","approved","published"].includes(String(r.state)) || typeof r.legalHold !== "boolean" ||
      !Number.isSafeInteger(r.version) || (r.version as number) < 0) return invalid();
  if (typeof a.approved !== "boolean" || !text(a.approver, true, 4096) || !text(a.subject, true, 4096) || !text(a.resourceId, true) ||
      !Number.isSafeInteger(a.resourceVersion) || (a.resourceVersion as number) < 0 || !time(a.expiresAt)) return invalid();
}
