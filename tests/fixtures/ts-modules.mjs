/**
 * Lets node --test import Worker TypeScript modules that use bundler-style imports.
 * - An extensionless relative import ("./admin-service") resolves to the sibling .ts file.
 * - .ts files are compiled with Node's own type stripper in transform mode, which also handles
 *   TypeScript-only syntax such as constructor parameter properties.
 * Import this module first, then load Worker modules with a dynamic import().
 */
import { registerHooks, stripTypeScriptTypes } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

registerHooks({
  resolve(specifier, context, next) {
    if (/^\.\.?\//.test(specifier) && !/\.[a-z]+$/i.test(specifier) && context.parentURL?.startsWith("file:")) {
      const candidate = new URL(specifier + ".ts", context.parentURL);
      if (existsSync(fileURLToPath(candidate))) return next(candidate.href, context);
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url.startsWith("file:") && url.endsWith(".ts")) {
      const source = stripTypeScriptTypes(readFileSync(fileURLToPath(url), "utf8"), { mode: "transform", sourceUrl: url });
      return { format: "module", shortCircuit: true, source };
    }
    return next(url, context);
  }
});
