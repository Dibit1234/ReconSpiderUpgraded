"""Large synthetic e-commerce site for speed / bounding tests.

* ~30 categories x endless ?page=N pagination x thousands of product pages
* ~80 KB HTML per page (big inline JSON state), identical header/footer
* one ~3 MB JS bundle referenced with a different ?v= on every page
* 20 ms simulated latency per response

    python tests/big_site.py 8830 [path/to/bundle.js]
"""

import json
import random
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WORDS = "red blue green black white oak steel glass linen wool velvet cedar maple brass copper slate ivory amber jade coral".split()
NOUNS = "chair table lamp sofa desk shelf rug mirror bed stool bench cabinet vase clock frame".split()
CATS = [f"{w}-{n}s" for w, n in zip(WORDS * 2, NOUNS * 2)][:30]
LATENCY = 0.02
BUNDLE = None


def bundle():
    global BUNDLE
    if BUNDLE is None:
        if len(sys.argv) > 2:
            BUNDLE = open(sys.argv[2], encoding="utf-8", errors="ignore").read()
        else:
            chunk = "function f%d(e,t){var n={type:'x',password:e.password,user:e.user};return t.map(function(r){return r.id+'%d'}).join(',')}\n"
            BUNDLE = "".join(chunk % (i, i) for i in range(30000))
    return BUNDLE


def page(title, body):
    state = json.dumps({"products": [{"id": random.randint(1, 10**6), "name": f"{random.choice(WORDS)} {random.choice(NOUNS)}", "price": round(random.random() * 900, 2), "desc": " ".join(random.choices(WORDS + NOUNS, k=60))} for _ in range(60)]})
    nav = " ".join(f'<a href="/category/{c}">{c}</a>' for c in CATS)
    return f"""<!doctype html><html><head><title>{title}</title>
<script src="/assets/main.4f8a2c.js?v={random.randint(1, 10**9)}"></script>
<script>window.__STATE__={state}</script></head><body><nav>{nav}</nav>
<main>{body}</main><footer><a href="/about">About</a> <a href="/search?q=chair">Search</a> &copy; Big Store</footer></body></html>"""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    count = 0

    def log_message(self, *a):
        pass

    def send(self, ctype, body, code=200):
        time.sleep(LATENCY)
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        H.count += 1
        path, _, q = self.path.partition("?")
        params = dict(p.split("=", 1) for p in q.split("&") if "=" in p)
        if path.startswith("/assets/") and path.endswith(".js"):
            return self.send("application/javascript", bundle())
        if path == "/":
            return self.send("text/html", page("Home", "<h1>Big Store</h1>"))
        if path.startswith("/category/"):
            n = int(params.get("page", 0))
            rnd = random.Random(path + str(n))
            prods = " ".join(f'<a href="/product/{rnd.choice(WORDS)}-{rnd.choice(NOUNS)}-{rnd.randint(1, 5000)}">p</a>' for _ in range(50))
            return self.send("text/html", page(path, f'{prods}<a href="{path}?page={n + 1}">next</a><a href="{path}?page={n + 1}&sort=price">by price</a>'))
        if path.startswith("/product/"):
            rnd = random.Random(path)
            rel = " ".join(f'<a href="/product/{rnd.choice(WORDS)}-{rnd.choice(NOUNS)}-{rnd.randint(1, 5000)}">r</a>' for _ in range(8))
            return self.send("text/html", page(path, rel))
        if path == "/search":
            return self.send("text/html", page("Search", f'<a href="/search?q={params.get("q", "")}x">more</a>'))
        return self.send("text/html", page("Page", "hello"))


def serve(port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8830
    bundle()
    print(f"big site on http://127.0.0.1:{port}/ (bundle {len(BUNDLE) / 1e6:.1f} MB)")
    serve(port).serve_forever()
