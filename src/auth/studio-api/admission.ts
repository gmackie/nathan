/** NATH-24 Studio API v1: account admission mode and invitations (NATH-16). */
import { admissionOverview, applyAdmissionOperation, ADMISSION_ERRORS } from "../admission";
import type { StudioRoute } from "./router";
import { rejected } from "./http";
import { noInput, admissionInput } from "./schemas";

export function admissionRefusalMessage(error: unknown) {
  return error instanceof Error && ADMISSION_ERRORS.test(error.message) ? error.message : "Admission change rejected";
}

export const routes: StudioRoute[] = [
  { method: "GET", path: "/admission", action: "admission.read", input: noInput, run: ({ env }) => admissionOverview(env) },
  { method: "POST", path: "/admission", action: "admission.apply", input: admissionInput, maxBytes: 4096,
    refusal: error => rejected(admissionRefusalMessage(error)), run: ({ env, actor }, body) => applyAdmissionOperation(env, body, actor) }
];
