/**
 * NATH-37: make React/Kumo server output fit Nathan's nonce-only `style-src`.
 *
 * Kumo writes `style="..."` attributes (the Button emphasis custom properties, the visually
 * hidden checkbox input, ...). A CSP without 'unsafe-inline' blocks those, so the renderer moves
 * every declaration list into a generated class (deduplicated) and emits the classes in one
 * nonce'd <style> block. Islands put the declarations back through CSSOM before hydrating
 * (CSSOM is allowed by CSP), see src/ui/client/hydrate.tsx.
 *
 * The tokenizer below understands exactly the HTML that react-dom's renderToString produces:
 * attribute values are always double-quoted and escaped (&amp; &quot; &#x27; &lt; &gt;), and text
 * never contains a raw "<". It still parses quotes, comments and raw-text elements (script, style)
 * generically, and every check fails closed: anything it cannot prove safe throws.
 *
 * Plain TypeScript (no JSX) so node --test can import it directly.
 */

export const INLINE_CLASS_PREFIX = "nathan-inline-";
/** Marks the generated <style> element so islands can find its rules. */
export const INLINE_STYLE_MARKER = "data-nathan-inline";

export interface TagAttribute {
  /** Lowercased attribute name. */
  name: string;
  /** Decoded value, or null for a bare attribute. */
  value: string | null;
  /** The attribute exactly as it appeared, including its leading whitespace. */
  raw: string;
}

export interface Tag {
  /** Lowercased tag name. */
  name: string;
  attributes: TagAttribute[];
  selfClosing: boolean;
}

const REFUSED_ELEMENTS = new Set(["xmp", "iframe", "noembed", "noframes", "plaintext"]);
// Browsers read these elements' content as text up to the matching end tag (raw text or RCDATA).
const RAW_TEXT = new Set(["script", "style", "title", "textarea"]);
const NAME_CHAR = /[^\s"'>/=]/;
const ENTITY = /&(#x[0-9a-fA-F]+|#[0-9]+|amp|quot|apos|lt|gt);/g;
const NAMED: Record<string, string> = { amp: "&", quot: "\"", apos: "'", lt: "<", gt: ">" };

/** Decodes the character references React's attribute escaping produces. */
export function decodeAttribute(value: string): string {
  return value.replace(ENTITY, (_, ref: string) => {
    if (ref[0] !== "#") return NAMED[ref];
    const code = ref[1] === "x" || ref[1] === "X" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
    if (!Number.isInteger(code) || code < 1 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff))
      throw Error("Invalid character reference in attribute");
    return String.fromCodePoint(code);
  });
}

/** Escapes text for an HTML attribute value or text node. */
export function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;").replaceAll("'", "&#x27;");
}

/**
 * Walks every start tag of `html` and lets `visit` replace it. Comments, doctypes, end tags,
 * text and raw-text element bodies are copied unchanged.
 * @param visit returns replacement markup for the tag, or undefined to keep it as is
 */
export function rewriteTags(html: string, visit: (tag: Tag, raw: string) => string | undefined): string {
  const lower = html.toLowerCase();
  let out = "";
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt < 0) { out += html.slice(i); break; }
    out += html.slice(i, lt);
    if (html.startsWith("<!--", lt)) {
      // Only the comment forms React emits. Browsers also end comments at "<!-->" and "--!>",
      // which this scanner would read differently, so anything else fails closed.
      const comment = /^<!--(?: |\$|\/\$|\$\?|\$!)?-->/.exec(html.slice(lt, lt + 12));
      if (!comment) throw Error("Unexpected HTML comment in rendered HTML");
      out += comment[0]; i = lt + comment[0].length; continue;
    }
    if (html[lt + 1] === "!" || html[lt + 1] === "/" || html[lt + 1] === "?") {
      const end = html.indexOf(">", lt);
      if (end < 0) throw Error("Unterminated HTML markup");
      out += html.slice(lt, end + 1); i = end + 1; continue;
    }
    if (!/[A-Za-z]/.test(html[lt + 1] ?? "")) {
      // React never writes a raw "<" in text; refuse rather than guess.
      throw Error("Unexpected '<' in rendered HTML");
    }
    let j = lt + 1;
    while (j < html.length && /[A-Za-z0-9-:]/.test(html[j])) j++;
    const name = html.slice(lt + 1, j).toLowerCase();
    // Elements whose content browsers parse as raw text or differently with scripting on; React
    // pages here never need them, and the scanner would misread what follows.
    if (REFUSED_ELEMENTS.has(name)) throw Error("Refused element <" + name + "> in rendered HTML");
    const attributes: TagAttribute[] = [];
    let selfClosing = false;
    for (;;) {
      const start = j;
      while (j < html.length && /\s/.test(html[j])) j++;
      if (j >= html.length) throw Error("Unterminated tag <" + name + ">");
      if (html[j] === ">") { j++; break; }
      if (html[j] === "/" && html[j + 1] === ">") { selfClosing = true; j += 2; break; }
      if (j === start) throw Error("Malformed attribute in <" + name + ">");
      const nameStart = j;
      while (j < html.length && NAME_CHAR.test(html[j])) j++;
      if (j === nameStart) throw Error("Malformed attribute in <" + name + ">");
      const attrName = html.slice(nameStart, j).toLowerCase();
      let value: string | null = null;
      if (html[j] === "=") {
        j++;
        const quote = html[j];
        if (quote === "\"" || quote === "'") {
          const end = html.indexOf(quote, j + 1);
          if (end < 0) throw Error("Unterminated attribute value in <" + name + ">");
          value = decodeAttribute(html.slice(j + 1, end));
          j = end + 1;
        } else {
          const valueStart = j;
          while (j < html.length && !/[\s>]/.test(html[j])) j++;
          value = decodeAttribute(html.slice(valueStart, j));
        }
      }
      attributes.push({ name: attrName, value, raw: html.slice(start, j) });
    }
    const raw = html.slice(lt, j);
    const replacement = visit({ name, attributes, selfClosing }, raw);
    out += replacement ?? raw;
    i = j;
    if (name === "noscript" && !selfClosing) {
      // With scripting on, a browser ends <noscript> at the first "</noscript", even inside an
      // attribute value. Use the same boundary and scan the content with the same checks.
      const close = lower.indexOf("</noscript", i);
      if (close < 0) throw Error("Unterminated <noscript> element");
      const inner = html.slice(i, close);
      if (lower.slice(i, close).includes("<noscript")) throw Error("Nested <noscript> in rendered HTML");
      out += rewriteTags(inner, visit); i = close; continue;
    }
    if (RAW_TEXT.has(name) && !selfClosing) {
      const close = lower.indexOf("</" + name, i);
      if (close < 0) throw Error("Unterminated <" + name + "> element");
      out += html.slice(i, close); i = close;
    }
  }
  return out;
}

/**
 * Accepts a declaration list only if it cannot leave its rule block: no braces, angle brackets,
 * backslashes, comments or unterminated strings. Anything else throws (fail closed).
 */
export function safeDeclarations(style: string): string {
  const text = style.trim().replace(/;+\s*$/, "");
  if (/[{}<>\\]/.test(text) || text.includes("/*") || text.includes("*/"))
    throw Error("Unsafe inline style declaration");
  let quote: string | null = null;
  for (const ch of text) {
    if (quote) { if (ch === quote) quote = null; else if (ch === "\n" || ch === "\r" || ch === "\f") break; }
    else if (ch === "\"" || ch === "'") quote = ch;
  }
  if (quote) throw Error("Unsafe inline style declaration");
  // Unbalanced ( or [ outside strings would swallow the following generated rules.
  const stack: string[] = [];
  quote = null;
  for (const ch of text) {
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === "\"" || ch === "'") quote = ch;
    else if (ch === "(" || ch === "[") stack.push(ch === "(" ? ")" : "]");
    else if (ch === ")" || ch === "]") { if (stack.pop() !== ch) throw Error("Unsafe inline style declaration"); }
  }
  if (stack.length) throw Error("Unsafe inline style declaration");
  return text;
}

export interface InlineStyleResult {
  /** The HTML with every style attribute replaced by a generated class. */
  html: string;
  /** Rules for the generated classes, for the nonce'd <style> block (empty if none). */
  css: string;
  /** Number of distinct generated classes. */
  classes: number;
}

/** Moves every `style="..."` attribute into a deduplicated generated class. */
export function moveInlineStylesToClasses(html: string): InlineStyleResult {
  const classes = new Map<string, string>();
  const rewritten = rewriteTags(html, tag => {
    const style = tag.attributes.find(a => a.name === "style");
    if (!style) return undefined;
    if (tag.attributes.filter(a => a.name === "style").length > 1 || tag.attributes.filter(a => a.name === "class").length > 1)
      throw Error("Duplicate style or class attribute on <" + tag.name + ">");
    const declarations = safeDeclarations(style.value ?? "");
    let generated = "";
    if (declarations) {
      generated = classes.get(declarations) ?? INLINE_CLASS_PREFIX + classes.size;
      classes.set(declarations, generated);
    }
    let attrs = "";
    let classDone = false;
    for (const attr of tag.attributes) {
      if (attr.name === "style") continue;
      if (attr.name === "class" && generated) {
        const existing = (attr.value ?? "").trim();
        attrs += " class=\"" + escapeHtml(existing ? existing + " " + generated : generated) + "\"";
        classDone = true;
      } else attrs += attr.raw;
    }
    if (generated && !classDone) attrs += " class=\"" + generated + "\"";
    return "<" + tag.name + attrs + (tag.selfClosing ? "/>" : ">");
  });
  let css = "";
  for (const [declarations, name] of classes) css += "." + name + "{" + declarations + "}";
  return { html: rewritten, css, classes: classes.size };
}

/**
 * Final check on a complete page: no style attributes and no inline event handlers anywhere, and
 * every <script>/<style> element carries the page nonce. Throws on the first violation.
 */
export function assertCspSafe(html: string, nonce: string, { allowScripts }: { allowScripts: boolean }): void {
  rewriteTags(html, tag => {
    for (const attr of tag.attributes) {
      if (attr.name === "style") throw Error("Inline style attribute left on <" + tag.name + ">");
      if (/^on[a-z]+$/.test(attr.name)) throw Error("Inline event handler on <" + tag.name + ">");
    }
    if (tag.name === "script" || tag.name === "style") {
      if (tag.name === "script" && !allowScripts) throw Error("Page without islands rendered a <script>");
      const tagNonce = tag.attributes.find(a => a.name === "nonce")?.value;
      if (tagNonce !== nonce) throw Error("<" + tag.name + "> without the page nonce");
    }
    return undefined;
  });
}
