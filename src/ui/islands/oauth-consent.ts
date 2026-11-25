/**
 * NATH-38: the OIDC consent page's Allow and Deny, moved verbatim from consentPage()'s inline
 * script into a hashed, SRI-pinned module. Plain script, no React. Better Auth's consent endpoint
 * takes JSON with the signed authorization query from this page's URL; it verifies the signature
 * and redirects only to the client's registered redirect URI. Same-origin fetch only.
 */
const root = document.querySelector<HTMLElement>("[data-nathan-oauth-consent]");
if (root) {
  const status = root.querySelector<HTMLElement>("[data-consent-error]");
  async function consent(accept: boolean) {
    try {
      const r = await fetch("/api/auth/oauth2/consent", {
        method: "POST", headers: { "content-type": "application/json" }, credentials: "same-origin",
        body: JSON.stringify({ accept, oauth_query: new URLSearchParams(location.search).toString() })
      });
      const d = await r.json() as { url?: string };
      if (!r.ok) throw Error("Consent failed");
      location.assign(d.url ? d.url : "/");
    } catch (e) {
      if (!status) return;
      const text = status.querySelector<HTMLElement>("[data-text]") ?? status;
      text.textContent = e instanceof Error ? e.message : "Consent failed";
      status.hidden = false;
    }
  }
  for (const button of Array.from(root.querySelectorAll<HTMLButtonElement>("button[data-consent]"))) {
    button.addEventListener("click", () => { void consent(button.dataset.consent === "allow"); });
    // Kumo renders a disabled Button with static disabled-look classes; drop them with the attribute.
    button.disabled = false;
    button.classList.remove("cursor-not-allowed", "opacity-50");
  }
}
