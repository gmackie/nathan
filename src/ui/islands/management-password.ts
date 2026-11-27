const savePassword = document.querySelector<HTMLFormElement>("[data-save-password]");
const requestLink = document.querySelector<HTMLFormElement>("[data-request-link]");
if (savePassword && requestLink && location.hash.length > 1) {
  const proof = savePassword.elements.namedItem("proof") as HTMLInputElement;
  proof.value = location.hash.slice(1);
  history.replaceState(null, "", location.pathname);
  requestLink.hidden = true;
  savePassword.hidden = false;
}
