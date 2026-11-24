/**
 * NATH-39: the Studio SPA's only way to talk to Nathan, the typed JSON API v1 (NATH-24,
 * docs/studio-api.md). Same-origin fetches with the session cookie; writes are JSON POSTs, so the
 * browser sends the Origin header the API checks. Nothing here logs, stores or caches responses:
 * one-time secrets (client secrets, SCIM bearer tokens) live only in the calling component's state.
 */
export const STUDIO_API = "/studio/api/v1";

/** Codes from src/auth/studio-api/schemas.ts, plus "network" and "unexpected" (client side). */
export type ApiErrorCode = string;

export interface ApiIssue { path: string; code: string; message: string }

export class ApiError extends Error {
  constructor(readonly code: ApiErrorCode, message: string, readonly status: number, readonly issues?: ApiIssue[]) {
    super(message);
  }
}

type Query = Record<string, string | number | undefined | null>;

function queryString(query?: Query): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null && v !== "") params.set(k, String(v));
  const s = params.toString();
  return s ? "?" + s : "";
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(STUDIO_API + path, { credentials: "same-origin", cache: "no-store", redirect: "error", ...init });
  } catch {
    throw new ApiError("network", "Nathan could not be reached. Check your connection and try again.", 0);
  }
  const body = await response.json().catch(() => null) as any;
  if (body && body.ok === true && response.ok) return body.data as T;
  const error = body?.error;
  throw new ApiError(
    typeof error?.code === "string" ? error.code : "unexpected",
    typeof error?.message === "string" ? error.message : "Request failed (" + response.status + ")",
    response.status,
    Array.isArray(error?.issues) ? error.issues : undefined
  );
}

export function apiGet<T = any>(path: string, query?: Query): Promise<T> {
  return call<T>(path + queryString(query));
}

export function apiPost<T = any>(path: string, body: unknown): Promise<T> {
  return call<T>(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}
