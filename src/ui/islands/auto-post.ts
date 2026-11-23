/**
 * NATH-37: submits the AutoPostPage form, like today's SAML auto-POST page. A hashed same-origin
 * script with SRI instead of inline code; without JavaScript the page shows a Continue button.
 * No React, so it does not load the vendor chunk.
 */
const form = document.querySelector("form[data-nathan-autopost]");
if (form instanceof HTMLFormElement) form.submit();
