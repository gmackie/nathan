"""Capture official price/limit pages. Research utility; never touches Nathan runtime."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import json

ROOT = Path(__file__).resolve().parent
SOURCES = [
    ("clerk-pricing", "Clerk pricing and feature matrix", "https://clerk.com/pricing"),
    ("workers-pricing", "Cloudflare Workers pricing", "https://developers.cloudflare.com/workers/platform/pricing/index.md"),
    ("d1-pricing", "Cloudflare D1 pricing", "https://developers.cloudflare.com/d1/platform/pricing/index.md"),
    ("d1-limits", "Cloudflare D1 limits and throughput", "https://developers.cloudflare.com/d1/platform/limits/index.md"),
    ("service-bindings", "Cloudflare service bindings", "https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/index.md"),
    ("observability-pricing", "Cloudflare Observability pricing from December 1, 2026", "https://developers.cloudflare.com/observability/pricing/index.md"),
    ("r2-pricing", "Cloudflare R2 pricing", "https://developers.cloudflare.com/r2/pricing/index.md"),
    ("d1-time-travel", "D1 Time Travel recovery", "https://developers.cloudflare.com/d1/reference/time-travel/index.md"),
    ("resend-pricing", "Resend transactional email pricing", "https://resend.com/pricing"),
    ("turnstile-pricing", "Cloudflare Turnstile plans", "https://developers.cloudflare.com/turnstile/plans/index.md"),
    ("workers-runtime", "How Cloudflare Workers uses isolates", "https://developers.cloudflare.com/workers/reference/how-workers-works/index.md"),
    ("workers-logs", "Workers Logs sampling and billing examples", "https://developers.cloudflare.com/workers/observability/logs/workers-logs/index.md"),
]


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript"}:
            self.skip += 1
        if tag in {"h1", "h2", "h3", "h4", "p", "li", "tr", "div", "section", "dt", "dd"}:
            self.parts.append("\n")
        if tag in {"td", "th"}:
            self.parts.append(" | ")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript"}:
            self.skip = max(0, self.skip - 1)

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def fetch(source):
    key, title, url = source
    request = Request(url, headers={"User-Agent": "Nathan-cost-research/1.0", "Accept": "text/markdown,text/html;q=0.9"})
    try:
        with urlopen(request, timeout=40) as response:
            raw = response.read()
            text = raw.decode("utf-8")
            if not text.lstrip().startswith(("---", "#")):
                parser = VisibleText()
                parser.feed(text)
                text = "\n".join(line.strip() for line in "".join(parser.parts).splitlines() if line.strip()) + "\n"
            target = ROOT / "sources" / (key + ".txt")
            target.parent.mkdir(exist_ok=True)
            target.write_text(text)
            return {"id": key, "title": title, "url": url, "retrievedAt": datetime.now(timezone.utc).isoformat(),
                    "httpStatus": response.status, "finalUrl": response.url, "contentType": response.headers.get("Content-Type"),
                    "lastModifiedHeader": response.headers.get("Last-Modified"), "rawSha256": sha256(raw).hexdigest(),
                    "textSha256": sha256(text.encode()).hexdigest(), "snapshot": str(target.relative_to(ROOT))}
    except (HTTPError, OSError, UnicodeError) as error:
        return {"id": key, "title": title, "url": url, "error": str(error)}


if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(fetch, SOURCES))
    (ROOT / "source-ledger.json").write_text(json.dumps(results, indent=2) + "\n")
    for result in results:
        print(result["id"], result.get("httpStatus", result.get("error")))
