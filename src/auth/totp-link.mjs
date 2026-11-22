/**
 * The href for "Open in authenticator app" on /security, or null.
 *
 * On a phone there is no second screen to scan the enrolment QR from, so the page links the
 * otpauth URI itself: Google Authenticator, Microsoft Authenticator, 1Password and Yubico
 * Authenticator register the otpauth: scheme on iOS and Android. Only a TOTP URI of bounded
 * length with no whitespace or markup characters is accepted, so the link can never carry
 * another scheme (javascript:, data:, https:) even if the enable response were tampered with.
 *
 * This function is inlined into the page with toString(), so it must stay self-contained.
 */
export function authenticatorLink(uri) {
  if (typeof uri !== "string" || uri.length > 480) return null;
  return /^otpauth:\/\/totp\/[^\s"'<>\\]+$/.test(uri) ? uri : null;
}
