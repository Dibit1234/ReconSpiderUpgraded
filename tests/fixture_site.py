"""Labelled fixture website for precision/recall and performance testing.

All secret-shaped values are generated at runtime from a fixed seed, so no
token-shaped literal is ever committed (GitHub push protection stays quiet).

Run standalone:  python tests/fixture_site.py 8800
"""

import base64
import binascii
import json
import random
import string
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

R = random.Random(1337)
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def rnd(n, alphabet=string.ascii_letters + string.digits):
    return "".join(R.choice(alphabet) for _ in range(n))


def b62(n, width=6):
    s = ""
    while n:
        n, r = divmod(n, 62)
        s = B62[r] + s
    return s.rjust(width, "0")


def gh_token():
    body = rnd(30)
    return "gh" + "p_" + body + b62(binascii.crc32(body.encode()) & 0xFFFFFFFF)


def jwt(payload, header=None):
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{enc(header or {'alg': 'HS256', 'typ': 'JWT'})}.{enc(payload)}.{rnd(43, string.ascii_letters + string.digits + '-_')}"


def pem_body():
    raw = bytes(R.getrandbits(8) for _ in range(600))
    b = base64.b64encode(raw).decode()
    return "\n".join(b[i : i + 64] for i in range(0, len(b), 64))


HEX = "0123456789abcdef"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# ---------------------------------------------------------------- true positives
S = {
    "aws_id": "AK" + "IA" + rnd(16, B32),
    "aws_secret": rnd(18) + "/" + rnd(10) + "+" + rnd(10),
    "gh": gh_token(),
    "slack_hook": "https://hooks.slack" + ".com/services/T" + rnd(8, string.ascii_uppercase + string.digits) + "/B" + rnd(8, string.ascii_uppercase + string.digits) + "/" + rnd(24),
    "stripe": "sk" + "_live_" + rnd(32),
    "sendgrid": "S" + "G." + rnd(22) + "." + rnd(43),
    "mongo_pw": "Mx" + rnd(10) + "9!",
    "supabase_svc": jwt({"iss": "supabase", "ref": rnd(20, string.ascii_lowercase), "role": "service_role", "iat": 1700000000, "exp": 2700000000}),
    "pem": pem_body(),
    "db_password": "Tr0ub4dor&3x",
    "admin_password": "admin123",
    "prefilled": "Winter2024!",
    "basic_user": "svc_report",
    "basic_pw": "R3p0rt!ng2024",
    "telegram": str(R.randint(100000000, 999999999)) + ":A" + "A" + rnd(33, string.ascii_letters + string.digits + "_-"),
    "openai": "sk" + "-proj-" + rnd(64, string.ascii_letters + string.digits + "_-"),
    "api_secret": rnd(32),
    "deploy_pw": "Gh7kLm2pQx9",
    "mailchimp": rnd(32, HEX) + "-us14",
    "gocspx": "GOC" + "SPX-" + rnd(28),
    "azure_key": rnd(86, string.ascii_letters + string.digits + "+/") + "==",
    "env_db": "pr0d-Db-P4ss-77",
}
S["basic_b64"] = base64.b64encode(f"{S['basic_user']}:{S['basic_pw']}".encode()).decode()

# Public-by-design (should be info, not counted as TP or FP)
P = {
    "google_key": "AI" + "za" + rnd(35, string.ascii_letters + string.digits + "_-"),
    "stripe_pk": "pk" + "_live_" + rnd(32),
    "supabase_anon": jwt({"iss": "supabase", "ref": rnd(20, string.ascii_lowercase), "role": "anon", "iat": 1700000000, "exp": 2700000000}),
}

# ---------------------------------------------------------------- decoys
D = {
    "csrf": rnd(40),
    "aws_doc_id": "AKIA" + "IOSFODNN7" + "EXAMPLE",
    "aws_doc_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
    "jwt_sample": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "gh_bad": "gh" + "p_" + rnd(36),
    "sitekey": "6Lc" + rnd(37, string.ascii_letters + string.digits + "_-"),
    "integrity": "sha384-" + rnd(64, string.ascii_letters + string.digits + "+/"),
}

TRUE_POSITIVES = {
    "aws_access_key_id": S["aws_id"],
    "aws_secret_access_key": S["aws_secret"],
    "github_token": S["gh"],
    "slack_webhook": S["slack_hook"],
    "stripe_secret_key": S["stripe"],
    "sendgrid_api_key(sourcemap)": S["sendgrid"],
    "mongodb_url_creds(sourcemap)": S["mongo_pw"],
    "supabase_service_role(/login)": S["supabase_svc"],
    "private_key(/api/v1)": "PRIVATE KEY",
    "internal_ip(header)": "10.20.30.40",
    "internal_ip(comment)": "10.0.0.12",
    "internal_ip(js)": "192.168.50.211",
    "db_password(js)": S["db_password"],
    "admin_password(/settings)": S["admin_password"],
    "prefilled_password": S["prefilled"],
    "basic_auth": S["basic_b64"],
    "telegram_bot_token": S["telegram"],
    "openai_api_key(js chunk)": S["openai"],
    "generic_api_secret": S["api_secret"],
    "https_url_creds": S["deploy_pw"],
    "mailchimp(sitemap-only page)": S["mailchimp"],
    "gocspx(robots-only page)": S["gocspx"],
    "azure_storage_key(depth 3)": S["azure_key"],
    "email_obfuscated": "it-support@acme-corp.com",
    "email_cfemail": "billing@acme-corp.com",
    "email_plain": "jane.smith@acme-corp.com.au",
}
PROBE_TRUE_POSITIVES = {"exposed_env_file": "/.env", "env_db_password": S["env_db"]}
PUBLIC = set(P.values())

# Values that must NOT show up as a finding of severity >= low.
DECOY_VALUES = [
    "logo@2x.png", "available@acme-corp.com", D["csrf"], "Password", "Enter your password", "Token",
    "e.user", "process.env.REACT_APP_API_KEY", "YOUR_API_KEY_HERE", D["aws_doc_id"], D["aws_doc_secret"],
    "pk.data.items", "sk-toggle-collapsed-sidebar", "key-value-store-identifier-x", "12.150.18.40",
    "1.2.3.4", D["jwt_sample"], D["gh_bad"], D["sitekey"], D["integrity"], "access_token", "app.auth.token",
    "user:password", "/reset", "8.8.8.8", "a::before", "12:30:45", "-----BEGIN RSA PRIVATE KEY-----",
]


# ---------------------------------------------------------------- pages
def layout(title, body, extra_head=""):
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<meta name="csrf-token" content="{D['csrf']}">
<meta name="google-site-verification" content="{rnd(43)}">
<link rel="stylesheet" href="/static/css/site.css?v={R.randint(1, 9999)}">
<link rel="icon" href="/static/img/logo@2x.png">
<script src="/static/js/app.js?v={R.randint(1, 9999)}"></script>
<script src="/static/js/vendor/jquery-3.6.0.min.js"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments)}};gtag('config','G-ABCDEF1234');</script>
{extra_head}
<style>a::before{{content:"»"}} .x::after{{content:""}}</style>
</head><body>
<header><nav><a href="/">Home</a> <a href="/about">About</a> <a href="/blog">Blog</a> <a href="/shop">Shop</a>
<a href="/login">Login</a> <a href="/settings">Settings</a> <a href="/staff">Staff</a> <a href="/docs/a">Docs</a>
<a href="/calendar/2026/11">Events</a> <a href="/logout">Log out</a></nav>
<img src="/static/img/logo@2x.png" alt="logo"></header>
<main>{body}</main>
<footer>Our products are available at acme-corp.com and partner stores. Opening hours 09:00 - 17:00.
<svg viewBox="0 0 24 24"><path d="M12.150.18.40L3 4.5.5.5z"/></svg>
&copy; Acme Corp</footer>
</body></html>"""


HOME = layout(
    "Home",
    f"""<h1>Welcome</h1>
<p>Contact <a href="mailto:jane.smith@acme-corp.com.au">Jane</a> or it-support [at] acme-corp [dot] com</p>
<p>Billing: <a href="/cdn-cgi/l/email-protection" class="__cf_email__" data-cfemail="{(lambda k: format(k, '02x') + ''.join(format(ord(c) ^ k, '02x') for c in 'billing@acme-corp.com'))(0x5a)}">[email&#160;protected]</a></p>
<!-- TODO remove: backend db at 10.0.0.12 -->
<script type="application/json" id="__APP_STATE__">{{"notify":{{"webhook":"{S['slack_hook'].replace('/', chr(92) + '/')}"}},"firebase":{{"apiKey":"{P['google_key']}","authDomain":"acme.firebaseapp.com"}}}}</script>
<form><input type="password" name="pw" placeholder="Password"><input type="hidden" name="_wpnonce" value="a1b2c3d4e5"></form>
<div class="g-recaptcha" data-sitekey="{D['sitekey']}"></div>
<script src="https://cdn.example.net/lib.js" integrity="{D['integrity']}"></script>""",
)

ABOUT = layout("About", f"""<p>About us</p><script>var ghCfg = {{ deployToken: "{S['gh']}" }}; var docsExample = "{D['gh_bad']}";</script>""")
LOGIN = layout(
    "Login",
    f"""<form method=post><input name=username><input type=password name=password></form>
<script>const sb = createClient("https://xyz.supabase.co", "{P['supabase_anon']}"); const admin = createClient("https://xyz.supabase.co", "{S['supabase_svc']}");
const sample = "{D['jwt_sample']}";</script>""",
)
SETTINGS = layout("Settings", f"""<script>var cfg = {{ admin_password: "{S['admin_password']}", password_reset_url: "/reset", passwordLabel: "Password" }};</script>""")
STAFF = layout("Staff", f"""<form><input type="password" name="pw" value="{S['prefilled']}"></form><script>var bot = "{S['telegram']}";</script>""")
DOCS_A = layout("Docs A", '<a href="/docs/a/b">Next</a><p>Example connection: mongodb://user:password@localhost:27017/test</p>')
DOCS_B = layout("Docs B", '<a href="/docs/a/b/c">Next</a>')
DOCS_C = layout("Docs C", f"<pre>DefaultEndpointsProtocol=https;AccountName=acmeprod;AccountKey={S['azure_key']};EndpointSuffix=core.windows.net</pre>")
PROMO = layout("Promo", f"<script>window.mc = {{ apiKey: '{S['mailchimp']}' }};</script>")
INTERNAL = layout("Internal tools", f"<script>var oauth = {{ client_secret: '{S['gocspx']}' }};</script>")

APP_JS = f"""/* app bundle */
var config = {{
  aws: {{ accessKeyId: "{S['aws_id']}", secretAccessKey: "{S['aws_secret']}", region: "ap-southeast-2" }},
  docs: {{ accessKeyId: "{D['aws_doc_id']}", secretAccessKey: "{D['aws_doc_secret']}" }},
  dbPassword: "{S['db_password']}",
  apiKey: process.env.REACT_APP_API_KEY,
  placeholderKey: {{ "api_key": "YOUR_API_KEY_HERE" }},
  stripePk: "{P['stripe_pk']}",
  backend: "http://192.168.50.211:8080",
  dns: "8.8.8.8", libVersion: "v1.2.3.4", time: "12:30:45",
}};
const API_SECRET = "{S['api_secret']}";
const TOKEN_KEY = "access_token"; const sessionStorageKey = "app.auth.token";
var i18n = {{ password: "Password", passwordPlaceholder: "Enter your password", token: "Token", csrfToken: "{D['csrf']}" }};
function login(e){{ return {{ user: e.user, password: e.password, secret: true, token: "Bearer " }} }}
var m = this.pk.data.items; var cls = "data-sk-toggle-collapsed-sidebar"; var store = "key-value-store-identifier-x";
var hdrs = {{ "Authorization": "Basic {S['basic_b64']}" }};
var hook = "https://deploy:{S['deploy_pw']}@ci.acme-corp.com/hook";
var PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"; function parsePem(s){{ return s.replace(PEM_HEADER, "").split("\\n").map(function(x){{return x.trim()}}).join(""); }} var PEM_FOOTER = "-----END RSA PRIVATE KEY-----";
fetch("/api/v1/users"); fetch("/api/v1/debug.json");
import("./chunk-3f9a2c7e1b.js");
//# sourceMappingURL=app.js.map
"""
CHUNK_JS = f"""export const payments = {{ key: "{S['stripe']}" }}; export const ai = new OpenAI({{ apiKey: "{S['openai']}" }});"""
SOURCEMAP = json.dumps(
    {
        "version": 3,
        "file": "app.js",
        "sources": ["webpack://acme/src/services/mail.ts", "webpack://acme/src/config.ts", "webpack://acme/node_modules/lib/index.js"],
        "sourcesContent": [
            f'export const sg = new MailService("{S["sendgrid"]}");',
            f'export const MONGO_URI = "mongodb+srv://appuser:{S["mongo_pw"]}@cluster0.ab1cd.mongodb.net/prod";',
            'export const EXAMPLE = "mongodb://user:password@host:27017/db";',
        ],
        "mappings": "AAAA",
    }
)
DEBUG_JSON = json.dumps({"service_account": "deploy", "key": "-----BEGIN RSA PRIVATE KEY-----\n" + S["pem"] + "\n-----END RSA PRIVATE KEY-----\n"})
JQUERY = "/*! jQuery v3.6.0 | (c) OpenJS Foundation */ !function(e){var t='1.2.3.4';var a={password:function(){return 1},user:e.user}}(window);"
ROBOTS = "User-agent: *\nDisallow: /internal-tools/\nDisallow: /*.pdf$\nSitemap: /sitemap.xml\n"
ENV_FILE = f"APP_ENV=production\nDB_HOST=db.internal\nDB_PASSWORD={S['env_db']}\nDEBUG=false\n"


def blog_list(n):
    posts = "".join(f'<li><a href="/blog/how-to-choose-the-right-widget-number-{n * 10 + i}">Post {n * 10 + i}</a></li>' for i in range(10))
    return layout(f"Blog {n}", f'<ul>{posts}</ul><a href="/blog?page={n + 1}">Older</a>')


def shop_list(n):
    items = "".join(f'<a href="/shop/item/{n * 20 + i}">Item</a> ' for i in range(20))
    return layout(f"Shop {n}", f'{items}<a href="/shop?page={n + 1}&sort=price">Next</a>')


def calendar(y, m):
    ny, nm = (y + 1, 1) if m == 12 else (y, m + 1)
    return layout(f"Cal {y}-{m}", f'<a href="/calendar/{ny}/{nm}">Next month</a> <a href="/calendar/{y}/{m}?view=week">Week</a>')


STATIC = {
    "/": ("text/html", HOME, {"X-Backend-Server": "10.20.30.40"}),
    "/about": ("text/html", ABOUT, {}),
    "/login": ("text/html", LOGIN, {}),
    "/settings": ("text/html", SETTINGS, {}),
    "/staff": ("text/html", STAFF, {}),
    "/docs/a": ("text/html", DOCS_A, {}),
    "/docs/a/b": ("text/html", DOCS_B, {}),
    "/docs/a/b/c": ("text/html", DOCS_C, {}),
    "/promo/spring": ("text/html", PROMO, {}),
    "/internal-tools/": ("text/html", INTERNAL, {}),
    "/static/js/app.js": ("application/javascript", APP_JS, {}),
    "/static/js/chunk-3f9a2c7e1b.js": ("application/javascript", CHUNK_JS, {}),
    "/static/js/app.js.map": ("application/json", SOURCEMAP, {}),
    "/static/js/vendor/jquery-3.6.0.min.js": ("application/javascript", JQUERY, {}),
    "/static/css/site.css": ("text/css", "body{color:#333}", {}),
    "/api/v1/debug.json": ("application/json", DEBUG_JSON, {}),
    "/robots.txt": ("text/plain", ROBOTS, {}),
    "/sitemap.xml": ("application/xml", '<?xml version="1.0"?><urlset><url><loc>/promo/spring</loc></url><url><loc>/about</loc></url></urlset>', {}),
    "/.env": ("text/plain", ENV_FILE, {}),
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    count = 0

    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body, headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text") else ""))
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        Handler.count += 1
        path, _, query = self.path.partition("?")
        host = self.headers.get("Host", "127.0.0.1")
        if path == "/sitemap.xml":
            body = STATIC[path][1].replace("<loc>/", f"<loc>http://{host}/")
            return self._send(200, "application/xml", body)
        if path in STATIC:
            ctype, body, hdrs = STATIC[path]
            return self._send(200, ctype, body, hdrs)
        if path == "/blog":
            n = int(dict(p.split("=") for p in query.split("&") if "=" in p).get("page", 0))
            return self._send(200, "text/html", blog_list(n))
        if path.startswith("/blog/"):
            return self._send(200, "text/html", layout("Post", f"<p>{rnd(400, string.ascii_lowercase + ' ')}</p>"))
        if path == "/shop":
            n = int(dict(p.split("=") for p in query.split("&") if "=" in p).get("page", 0))
            return self._send(200, "text/html", shop_list(n))
        if path.startswith("/shop/item/"):
            return self._send(200, "text/html", layout("Item", f"<p>Item {path.rsplit('/', 1)[-1]}</p><a href='/shop'>Back</a>"))
        if path.startswith("/calendar/"):
            parts = path.strip("/").split("/")
            try:
                return self._send(200, "text/html", calendar(int(parts[1]), int(parts[2])))
            except (IndexError, ValueError):
                pass
        if path.startswith("/api/"):
            return self._send(404, "application/json", '{"error":"not found"}')
        if path.startswith("/static/"):
            return self._send(404, "text/plain", "not found")
        # SPA catch-all: unknown paths return the home page with 200 (soft 404)
        return self._send(200, "text/html", HOME)


def serve(port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8800
    print(f"fixture site on http://127.0.0.1:{port}/")
    serve(port).serve_forever()
