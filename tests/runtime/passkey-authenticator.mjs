/**
 * A software WebAuthn authenticator (ES256, P-256) for runtime tests: it registers a credential
 * as a passkey row and then signs in through Better Auth's real
 * /passkey/generate-authenticate-options and /passkey/verify-authentication endpoints, so the
 * identity Worker's own after-hook records the passkey evidence (no hand-inserted evidence rows).
 */
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { cookiesOf } from "./helpers.mjs";

const b64url = bytes => Buffer.from(bytes).toString("base64url");

export function softwarePasskey() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const x = Buffer.from(jwk.x, "base64url"), y = Buffer.from(jwk.y, "base64url");
  // COSE_Key {1(kty): 2(EC2), 3(alg): -7(ES256), -1(crv): 1(P-256), -2(x), -3(y)}
  const cose = Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), x, Buffer.from([0x22, 0x58, 0x20]), y]);
  const credentialId = b64url(crypto.getRandomValues(new Uint8Array(16)));
  let counter = 0;
  return {
    credentialId,
    /** Value for the passkey table's publicKey column (Better Auth stores base64 COSE). */
    publicKey: cose.toString("base64"),
    /** A WebAuthn assertion for `challenge` at `origin`, with user presence and verification flags. */
    assert(challenge, origin, rpId, userId) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
      counter += 1;
      const authenticatorData = Buffer.concat([createHash("sha256").update(rpId).digest(), Buffer.from([0x05]),
        Buffer.from([counter >>> 24, (counter >>> 16) & 255, (counter >>> 8) & 255, counter & 255])]);
      const signature = sign("sha256", Buffer.concat([authenticatorData, createHash("sha256").update(clientDataJSON).digest()]), privateKey);
      return { id: credentialId, rawId: credentialId, type: "public-key", clientExtensionResults: {}, authenticatorAttachment: "platform",
        response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authenticatorData), signature: b64url(signature),
          userHandle: b64url(Buffer.from(userId)) } };
    }
  };
}

/**
 * Signs in with `passkey` through the identity Worker and returns the new session cookie.
 * The Worker's after-hook on /passkey/verify-authentication writes the evidence row.
 */
export async function passkeySignIn(mf, origin, passkey, userId) {
  const options = await mf.dispatchFetch(origin + "/api/auth/passkey/generate-authenticate-options", { headers: { Origin: origin } });
  if (options.status !== 200) throw Error("authenticate options: " + options.status + " " + await options.text());
  const { challenge, rpId } = await options.json();
  const challengeCookies = Object.entries(cookiesOf(options)).map(([name, { value }]) => name + "=" + value).join("; ");
  const verify = await mf.dispatchFetch(origin + "/api/auth/passkey/verify-authentication", {
    method: "POST",
    headers: { Origin: origin, Cookie: challengeCookies, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin" },
    body: JSON.stringify({ response: passkey.assert(challenge, origin, rpId ?? new URL(origin).hostname, userId) })
  });
  if (verify.status !== 200) throw Error("verify-authentication: " + verify.status + " " + await verify.text());
  const jar = cookiesOf(verify);
  const name = Object.keys(jar).find(n => n.endsWith("nathan.session_token"));
  if (!name) throw Error("no session cookie from passkey sign-in");
  const body = await verify.json();
  return { id: body.session.id, cookie: name + "=" + jar[name].value };
}
