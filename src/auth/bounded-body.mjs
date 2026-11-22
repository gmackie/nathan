/**
 * Request bodies read with a byte limit. request.text() buffers the whole body first, and a
 * chunked request carries no Content-Length to check beforehand, so a 40 MB body would be read in
 * full before any size check. This reader refuses a declared Content-Length over the limit, then
 * counts bytes (not characters) as they arrive and cancels the stream as soon as the limit is
 * passed. Runtime independent (Web Streams), shared by Nathan's own endpoints.
 */

/**
 * The body as UTF-8 text (invalid sequences replaced, like request.text()), or null when it is
 * larger than maxBytes. A request without a body reads as "".
 * @param {Request} request @param {number} maxBytes
 * @returns {Promise<string|null>}
 */
export async function readBoundedText(request, maxBytes) {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && (!/^\d+$/.test(declared.trim()) || Number(declared) > maxBytes)) {
    await request.body?.cancel().catch(() => {});
    return null;
  }
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) { await reader.cancel().catch(() => {}); return null; }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) { all.set(c, at); at += c.byteLength; }
  return new TextDecoder().decode(all);
}
