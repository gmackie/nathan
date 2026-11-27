import { apiPost } from "../pages/studio/api";

const root = document.querySelector<HTMLElement>("[data-user-directory]");
if (root) {
  const status = root.querySelector<HTMLElement>("[data-status]")!;
  const invite = root.querySelector<HTMLFormElement>("[data-invite]")!;
  const buttons = root.querySelectorAll<HTMLButtonElement>("button[disabled]");
  const enable = (enabled: boolean) => buttons.forEach(button => {
    button.disabled = !enabled;
    button.classList.toggle("cursor-not-allowed", !enabled);
    button.classList.toggle("opacity-50", !enabled);
  });
  async function save(path: string, body: object) {
    enable(false);
    try {
      await apiPost("/" + path, body);
      location.reload();
    } catch (error) { status.textContent = error instanceof Error ? error.message : "Change could not be saved."; enable(true); }
  }
  invite.addEventListener("submit", event => {
    event.preventDefault();
    void save("admission",{op:"invite",email:new FormData(invite).get("email")});
  });
  for (const button of root.querySelectorAll<HTMLButtonElement>("[data-operation]")) {
    button.addEventListener("click", () => {
      const {operation,email,id} = button.dataset;
      const customerSignIn = root.dataset.classcheck === "true" ? " This address will be reserved for Studio and its ClassCheck customer sign-in will stop." : "";
      if (operation === "grant" && id && email && confirm("Grant Nathan administrator access to " + email + "?" + customerSignIn))
        void save("admins/grant",{id,email,confirm:"CONFIRM GRANT ADMIN " + email.toLowerCase()});
      if (operation === "revoke-admin" && id && confirm("Revoke Nathan administrator access and sign out " + email + "?"))
        void save("admins/revoke",{id,confirm:"CONFIRM REVOKE ADMIN " + id});
      if (operation === "revoke-invite" && id && confirm("Revoke the invitation for " + email + "?"))
        void save("admission",{op:"revoke",id,confirm:"CONFIRM REVOKE INVITATION " + id});
    });
  }
  enable(true);
}
