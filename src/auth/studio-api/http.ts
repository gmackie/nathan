/** NATH-24: the response envelope of the Studio API v1 (see ./schemas.ts for the published types). */
import type { StudioErrorCode, StudioIssue } from "./schemas";

const noStore = { "Cache-Control": "no-store" } as const;

/** A refusal with a stable code. Messages are safe to show: they never contain submitted values. */
export class StudioApiError extends Error {
  constructor(readonly status: number, readonly code: StudioErrorCode, message: string, readonly issues?: StudioIssue[]) {
    super(message);
  }
}

export function studioOk(data: unknown, status = 200): Response {
  return Response.json({ ok: true, data }, { status, headers: noStore });
}

export function studioFail(error: StudioApiError, headers: Record<string, string> = {}): Response {
  const body = { code: error.code, message: error.message, ...(error.issues ? { issues: error.issues } : {}) };
  return Response.json({ ok: false, error: body }, { status: error.status, headers: { ...noStore, ...headers } });
}

export const studioError = (status: number, code: StudioErrorCode, message: string, issues?: StudioIssue[]) =>
  new StudioApiError(status, code, message, issues);

/** The service refused a change: 409 with the area's safe message. */
export const rejected = (message: string) => new StudioApiError(409, "operation_rejected", message);
