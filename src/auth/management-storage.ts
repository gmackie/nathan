/** Better Auth dates may be stored as ISO text or as epoch seconds or milliseconds. */
export function epochSeconds(column: "s.expiresAt" | "v.expiresAt" | "u.banExpires") {
  return `CASE WHEN typeof(${column})='text' THEN unixepoch(${column})
    WHEN ${column}<100000000000 THEN ${column} ELSE ${column}/1000 END`;
}

/** Applies at the write boundary, where a prior Access or session check may be stale. */
export const activeManagementUser = `u.role='admin' AND u.emailVerified=1
  AND (COALESCE(u.banned,0)=0 OR ${epochSeconds("u.banExpires")}<=unixepoch())
  AND NOT EXISTS(SELECT 1 FROM nathan_scim_users WHERE user_id=u.id
    AND link_state='deprovisioned' AND override_cause IS NULL)`;
