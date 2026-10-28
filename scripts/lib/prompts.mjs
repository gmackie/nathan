import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";

export async function ask(question, fallback = "") {
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    const suffix = fallback ? " [" + fallback + "]" : "";
    return (await rl.question(question + suffix + ": ")).trim() || fallback;
  } finally { rl.close(); }
}
export async function yesNo(question, defaultNo = true) {
  const response = (await ask(question + (defaultNo ? " [y/N]" : " [Y/n]"))).toLowerCase();
  return response === "y" || response === "yes" || (!defaultNo && !response);
}
export async function secretPrompt(label) {
  if (!stdin.isTTY || !stdout.isTTY || typeof stdin.setRawMode !== "function") {
    throw Error("Masked secret entry requires an interactive TTY; do not pass secrets through CLI arguments");
  }
  stdout.write(label + ": ");
  const wasRaw = stdin.isRaw;
  stdin.setRawMode(true);
  stdin.resume();
  return await new Promise((resolve, reject) => {
    let buffer = "";
    const done = (err, result) => {
      stdin.off("data", onData);
      stdin.setRawMode(Boolean(wasRaw));
      stdout.write("\n");
      if (err) reject(err); else resolve(result);
    };
    function onData(chunk) {
      const str = chunk.toString();
      for (const c of str) {
        if (c === "\r" || c === "\n") return done(null, buffer);
        if (c === "\u0003") return done(Error("Cancelled"));
        if (c === "\u007f" || c === "\b") buffer = buffer.slice(0, -1);
        else if (c >= " " && c !== "\u007f") buffer += c;
      }
    }
    stdin.on("data", onData);
  });
}
