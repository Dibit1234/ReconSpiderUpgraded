"""Scrapy spider: bounded, deduplicated discovery from a single start URL."""

import hashlib
import json
import random
import re
import string
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import scrapy

from .detect import Detector, is_vendor, registrable_domain

# --------------------------------------------------------------------------- #
# URL helpers
# --------------------------------------------------------------------------- #

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "utm_source_platform", "_ga", "_gl", "gclid", "fbclid", "mc_cid", "mc_eid", "msclkid",
    "twclid", "ttclid", "gbraid", "wbraid", "yclid", "igshid", "_hsenc", "_hsmi", "ref_src",
    "replytocom", "phpsessid", "sessionid", "jsessionid", "sid", "_", "cb", "nocache",
}
CACHE_BUSTERS = {"v", "ver", "version", "t", "ts", "_v", "hash", "rev", "build"}

SKIP_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".ico", ".avif", ".tif", ".tiff",
    ".mp4", ".webm", ".mov", ".avi", ".mkv", ".mp3", ".wav", ".m4a", ".ogg", ".flac",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".bz2", ".xz", ".iso", ".dmg",
    ".exe", ".msi", ".dll", ".so", ".dylib", ".apk", ".ipa", ".bin", ".deb", ".rpm",
    ".css", ".scss", ".less", ".woff", ".woff2", ".ttf", ".eot", ".otf",
)
ASSET_EXT_RE = re.compile(r"(?i)\.(?:m?js|json|map)$")
# GET requests that change state or end the session
UNSAFE_PATH_RE = re.compile(
    r"(?i)/(?:log[-_]?out|sign[-_]?out|logoff|sign_off|signoff|session/destroy|unsubscribe|delete|remove|destroy|deactivate|cancel[-_]?account)(?:/|$|\?|\.)|[?&](?:action|do|op)=(?:logout|delete|remove)"
)
SEG_NUM = re.compile(r"^\d+$")
SEG_ID = re.compile(r"^(?:[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}|[A-Za-z0-9_-]{22,})$")
DATE_SEG = re.compile(r"^\d{4}-\d{2}(?:-\d{2})?$")

JS_PATH_RE = re.compile(
    r"""["'`]((?:https?:)?(?://[A-Za-z0-9.-]+)?[A-Za-z0-9_./@~+-]{0,250}?\.(?:m?js|json|map))(?:\?[^"'`\s<>]{0,100})?["'`]"""
)
ENDPOINT_RE = re.compile(
    r"""["'`]((?:https?://[A-Za-z0-9.-]+)?/(?:api|apis|v\d{1,2}|graphql|gql|rest|internal|private|admin|auth|oauth2?|services?|rpc|ajax|backend|gateway)(?:/[A-Za-z0-9_.{}:$~@%+-]*){0,12})["'`]"""
)
SOURCEMAP_RE = re.compile(r"(?m)^[ \t]*[/@#*]{1,3}\s*[#@]\s*sourceMappingURL=(\S+?)\s*(?:\*/)?\s*$")
SCRIPT_BLOCK_RE = re.compile(r"(?is)(<script\b[^>]*>)(.*?)(</script\s*>)")
COMMENT_RE = re.compile(r"(?s)<!--(.*?)-->")
META_REFRESH_RE = re.compile(r"(?i)<meta[^>]+http-equiv=[\"']?refresh[^>]+content=[\"'][^\"']*url=([^\"'>]+)")
SITEMAP_LOC_RE = re.compile(r"(?is)<loc>\s*(.*?)\s*</loc>")

PAGE_ABS_URL_RE = re.compile(r"""["'`](https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d{2,5})?(?:/[^\s"'`<>\\]{0,300})?)["'`]""")
JS_NAV_RE = re.compile(r"""(?:location(?:\.href)?\s*=|location\.(?:assign|replace)\(|window\.open\(|navigate\(|router\.push\(|href\s*:)\s*["'`](/[^"'`\s<>]{1,200})["'`]""")
DATA_LINK_RE = re.compile(r"""\bdata-[\w-]*(?:url|href|link|path|src|route)\s*=\s*["']([^"'<>\s]{1,300})["']""", re.I)
NEXT_BUILD_ID_RE = re.compile(r'"buildId"\s*:\s*"([A-Za-z0-9_-]{6,64})"')
WEBPACK_PUBLIC_PATH_RE = re.compile(r"""\.p\s*=\s*["']([^"']{0,200})["']""")
# __webpack_require__.u = e => "static/js/" + e + "." + {12:"a1b2c3d4", ...}[e] + ".chunk.js"
WEBPACK_CHUNK_RE = re.compile(
    r"""["']([\w./-]{0,120})["']\s*\+\s*(?:\(\s*\{[^{}]{0,20000}\}\[\s*\w+\s*\]\s*\|\|\s*\w+\s*\)|\w+)\s*\+\s*["']([.-])["']\s*\+\s*\{([^{}]{4,200000})\}\[\s*\w+\s*\]\s*\+\s*["']([\w.-]{0,40}\.m?js)["']"""
)
WEBPACK_NAMES_RE = re.compile(r"""\+\s*\(\s*\{([^{}]{0,20000})\}\[\s*\w+\s*\]\s*\|\|\s*\w+\s*\)\s*\+""")
CHUNK_PAIR_RE = re.compile(r"""(?:^|,)\s*["']?([\w-]{1,80})["']?\s*:\s*["']([\w-]{4,40})["']""")
CONFIG_ENDPOINT_RE = re.compile(r"(?i)(?:config|settings|env(?:ironment)?|bootstrap|runtime|init|feature-?flags|public-?keys?|well-known)(?:\.json)?/?$")

# --------------------------------------------------------------------------- #
# Probes: (path, check, severity, title). check() gets (text, body, is_html).
# Only GET requests; content is validated so soft-404s / SPA shells never hit.
# --------------------------------------------------------------------------- #


def _json(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def _env_ok(t, b, html):
    return not html and re.search(r"(?m)^[ \t]*(?:export[ \t]+)?[A-Z_][A-Z0-9_]*[ \t]*=", t) is not None


def _spec_ok(t, b, html):
    d = _json(t)
    return isinstance(d, dict) and ("openapi" in d or "swagger" in d) and isinstance(d.get("paths"), dict)


def _json_ok(t, b, html):
    return not html and isinstance(_json(t), (dict, list))


PROBES = [
    # secrets / config
    *[(p, _env_ok, "high", "Exposed environment file") for p in (
        "/.env", "/.env.local", "/.env.production", "/.env.prod", "/.env.development", "/.env.dev",
        "/.env.staging", "/.env.backup", "/.env.bak", "/.env.old", "/.env.save", "/api/.env", "/backend/.env", "/app/.env")],
    ("/.aws/credentials", lambda t, b, h: "aws_access_key_id" in t.lower(), "critical", "Exposed AWS credentials file"),
    ("/.htpasswd", lambda t, b, h: re.search(r"(?m)^[^:\s<]+:\$?[\w./$]{10,}", t) is not None, "high", "Exposed .htpasswd"),
    ("/.npmrc", lambda t, b, h: not h and ("registry" in t or "_auth" in t), "medium", "Exposed .npmrc"),
    ("/.git/config", lambda t, b, h: "[core]" in t, "high", "Exposed .git repository"),
    ("/.git/HEAD", lambda t, b, h: re.match(r"ref: refs/|[0-9a-f]{40}\s*$", t.strip()) is not None, "high", "Exposed .git repository"),
    ("/.svn/entries", lambda t, b, h: not h and (t.strip()[:2].isdigit() or "svn:" in t), "medium", "Exposed .svn metadata"),
    ("/.svn/wc.db", lambda t, b, h: b[:15] == b"SQLite format 3", "medium", "Exposed .svn metadata"),
    ("/.DS_Store", lambda t, b, h: b[:8] == b"\x00\x00\x00\x01Bud1", "low", "Exposed .DS_Store (lists directory contents)"),
    ("/docker-compose.yml", lambda t, b, h: not h and "services:" in t, "medium", "Exposed docker-compose file"),
    ("/docker-compose.yaml", lambda t, b, h: not h and "services:" in t, "medium", "Exposed docker-compose file"),
    ("/web.config", lambda t, b, h: "<configuration" in t.lower(), "medium", "Exposed web.config"),
    ("/sftp-config.json", _json_ok, "high", "Exposed SFTP config"),
    ("/.vscode/sftp.json", _json_ok, "high", "Exposed SFTP config"),
    *[(p, lambda t, b, h: "DB_PASSWORD" in t or "<?php" in t, "critical", "Exposed config backup") for p in (
        "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~", "/wp-config.php.save", "/wp-config.bak", "/config.php.bak")],
    # public config files: reported as info, their contents are scanned for secrets
    *[(p, _json_ok, "info", "Public config file") for p in (
        "/config.json", "/env.json", "/app-config.json", "/appsettings.json", "/appsettings.Development.json",
        "/settings.json", "/assets/config.json", "/assets/env.json", "/static/config.json", "/api/config",
        "/api/v1/config", "/api/settings", "/api/env", "/config")],
    *[(p, lambda t, b, h: not h and ("=" in t or ":" in t), "info", "Public config file") for p in (
        "/config.js", "/env.js", "/__env.js", "/env-config.js", "/runtime-config.js", "/assets/env.js")],
    # API surface
    *[(p, _spec_ok, "low", "API specification exposed") for p in (
        "/swagger.json", "/openapi.json", "/api/swagger.json", "/api/openapi.json", "/v2/api-docs", "/v3/api-docs",
        "/api-docs", "/api/v1/swagger.json", "/swagger/v1/swagger.json", "/api/swagger/v1/swagger.json", "/openapi.yaml.json")],
    *[(p, lambda t, b, h: "swagger-ui" in t.lower() and ("SwaggerUIBundle" in t or "swagger-ui.css" in t), "low", "Swagger UI exposed") for p in (
        "/swagger-ui.html", "/swagger-ui/", "/swagger/", "/api/docs", "/docs", "/api-docs/")],
    *[(p, lambda t, b, h: isinstance(_json(t), dict) and (_json(t).get("data") or {}).get("__typename") is not None, "info", "GraphQL endpoint") for p in (
        "/graphql?query=%7B__typename%7D", "/api/graphql?query=%7B__typename%7D", "/graphql/v1?query=%7B__typename%7D", "/v1/graphql?query=%7B__typename%7D")],
    ("/actuator", lambda t, b, h: isinstance(_json(t), dict) and "_links" in _json(t), "low", "Spring Boot actuator exposed"),
    ("/actuator/env", lambda t, b, h: "propertySources" in t, "high", "Spring Boot actuator /env exposed"),
    ("/actuator/configprops", lambda t, b, h: "contexts" in t and "beans" in t, "medium", "Spring Boot actuator /configprops exposed"),
    ("/actuator/mappings", lambda t, b, h: "dispatcherServlets" in t or "mappings" in t and "contexts" in t, "low", "Spring Boot actuator /mappings exposed"),
    ("/env", lambda t, b, h: "propertySources" in t or "profiles" in t and "systemProperties" in t, "high", "Spring Boot /env exposed"),
    ("/wp-json/wp/v2/users", lambda t, b, h: isinstance(_json(t), list) and bool(_json(t)) and isinstance(_json(t)[0], dict) and "slug" in _json(t)[0], "medium", "WordPress user enumeration"),
    ("/elmah.axd", lambda t, b, h: "Error Log for" in t, "high", "ELMAH error log exposed"),
    ("/trace.axd", lambda t, b, h: "Application Trace" in t, "medium", "ASP.NET trace exposed"),
    ("/phpinfo.php", lambda t, b, h: "phpinfo()" in t or "PHP Version" in t, "medium", "phpinfo() exposed"),
    ("/info.php", lambda t, b, h: "phpinfo()" in t or "PHP Version" in t and "<table" in t, "medium", "phpinfo() exposed"),
    ("/server-status", lambda t, b, h: "Apache Server Status" in t, "low", "Apache server-status exposed"),
    ("/server-info", lambda t, b, h: "Apache Server Information" in t, "low", "Apache server-info exposed"),
    ("/crossdomain.xml", lambda t, b, h: re.search(r"allow-access-from\s+domain=[\"']\*[\"']", t) is not None, "low", "Permissive crossdomain.xml"),
    ("/clientaccesspolicy.xml", lambda t, b, h: re.search(r"<domain\s+uri=[\"']\*[\"']", t) is not None, "low", "Permissive clientaccesspolicy.xml"),
]
BINARY_PROBES = {"/.DS_Store", "/.svn/wc.db"}
# .DS_Store record: UTF-16BE filename followed by a 4-char structure type
DS_STORE_ENTRY_RE = re.compile(
    rb"((?:\x00[\x20-\x7e]){1,255})(?:Iloc|bwsp|lsvp|lsvP|icvp|BKGD|cmmt|dilc|dscl|fwi0|fwsw|fwvh|GRP0|ICVO|icgo|icsp|info|logS|lg1S|lssp|modD|moDD|phyS|ph1S|pict|vstl|vSrn|ptbL|ptbN|extn|kind|mdat|mdcd|lsvt|lsvC)(?:bool|long|shor|type|ustr|blob|comp|dutc)"
)


def sha1(data):
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    return hashlib.sha1(data).digest()


class Scope:
    def __init__(self, start_url, include_subdomains=False):
        p = urlparse(start_url)
        self.scheme = p.scheme or "https"
        self.host = (p.hostname or "").lower()
        self.port = p.port
        self.site = registrable_domain(self.host)
        self.include_subdomains = include_subdomains
        bare = self.host[4:] if self.host.startswith("www.") else self.host
        self.page_hosts = {self.host, bare, "www." + bare}

    def add_host(self, host):
        if host and registrable_domain(host) == self.site:
            self.page_hosts.add(host.lower())

    def page_ok(self, host, port=None, scheme=None):
        host = (host or "").lower()
        # Different port on the same host = different service/target.
        eff = port or (443 if scheme == "https" else 80)
        if self.port and eff != self.port:
            return False
        if not self.port and eff not in (80, 443):
            return False
        if host in self.page_hosts:
            return True
        return self.include_subdomains and (host == self.site or host.endswith("." + self.site))

    def asset_ok(self, host):
        host = (host or "").lower()
        return host in self.page_hosts or host == self.site or host.endswith("." + self.site)


def normalize(url, scope=None):
    """Canonical form used for dedupe keys (not for the request itself)."""
    p = urlparse(url)
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    if scope and host in scope.page_hosts:
        scheme = scope.scheme
        if host.startswith("www.") or ("www." + host) in scope.page_hosts:
            host = host[4:] if host.startswith("www.") else host
    port = p.port
    netloc = host if not port or (scheme, port) in {("http", 80), ("https", 443)} else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", p.path or "/")
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    params = sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k.lower() not in TRACKING_PARAMS)
    return urlunparse((scheme, netloc, path, "", urlencode(params), ""))


def asset_key(url):
    """Assets: also ignore cache-buster params (app.js?v=123 == app.js?v=124)."""
    p = urlparse(url)
    params = sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k.lower() not in TRACKING_PARAMS | CACHE_BUSTERS)
    return urlunparse(((p.scheme or "http").lower(), (p.netloc or "").lower(), p.path or "/", "", urlencode(params), ""))


def template_of(url):
    """Collapse IDs/slugs so /blog/post-1 and /blog/post-2 share a template."""
    p = urlparse(url)
    segs = []
    for seg in (p.path or "/").split("/"):
        if not seg:
            continue
        if SEG_NUM.match(seg) or DATE_SEG.match(seg):
            segs.append("{n}")
        elif seg.count("-") >= 3 or seg.count("_") >= 3 or len(seg) > 40:
            segs.append("{slug}")
        elif SEG_ID.match(seg) and re.search(r"\d", seg):
            segs.append("{id}")
        elif re.search(r"[-_]", seg) and re.search(r"\d", seg) and re.search(r"[A-Za-z]{2}", seg):
            segs.append("{slug}")  # oak-chair-123, post_42, sku-9912-red
        else:
            segs.append(seg.lower())
    keys = ",".join(sorted({k.lower() for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
    return f"{(p.hostname or '').lower()}/{'/'.join(segs)}?{keys}"


def looks_trap(url):
    p = urlparse(url)
    if len(url) > 600:
        return True
    segs = [s for s in p.path.split("/") if s]
    if len(segs) > 12:
        return True
    counts = {}
    for s in segs:
        counts[s] = counts.get(s, 0) + 1
        if counts[s] >= 3:
            return True
    return len(parse_qsl(p.query)) > 8


def is_binary(body):
    return b"\x00" in body[:1024]


# --------------------------------------------------------------------------- #
# Spider
# --------------------------------------------------------------------------- #


class TargetSpider(scrapy.Spider):
    name = "reconspider"

    def __init__(self, target, opts, sink, scheme_assumed=False, extra_seeds=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target = target
        self.extra_seeds = list(extra_seeds or [])
        self.scheme_assumed = scheme_assumed
        self.discovered_hosts = set()  # hosts on the target's registrable domain
        self.external_refs = {}  # host -> {"link", "script", "iframe", "form", "js_ref", "email"}
        self.seeded_hosts = set()
        self.next_build_ids = set()
        self.config_probes = 0
        self.start_ok = False
        self.start_error = None
        self.o = opts
        self.sink = sink  # callback(spider, finding_dict, is_new)
        self.scope = Scope(target, include_subdomains=opts.include_subdomains)
        self.allowed_domains = [self.scope.site] if self.scope.site else []
        extra_suppress = list(opts.suppress_values or [])
        self.det = Detector(
            target_host=self.scope.host,
            entropy=opts.entropy,
            signatures=opts.signatures,
            ignore_patterns=opts.ignore_patterns,
            suppress_values=extra_suppress,
        )
        self.start_ts = time.time()

        # dedupe state
        self.seen_pages = set()
        self.seen_assets = set()
        self.seen_bodies = set()
        self.seen_lines = set()
        self.seen_scripts = set()
        self.seen_headers = set()
        self.seen_sitemaps = set()
        self.template_counts = {}
        self.template_children = {}

        # findings: (rule, value) -> finding
        self.findings = {}
        self.endpoints = set()
        self.js_files = set()
        self.form_fields = set()
        self.comments = set()
        self.crawled_urls = []
        self.redirected_to = None
        self.soft404 = None

        self.stats = {
            "pages_scheduled": 0, "pages_fetched": 0, "assets_scheduled": 0, "assets_fetched": 0,
            "sourcemaps_fetched": 0, "duplicate_bodies": 0, "lines_skipped_dedupe": 0,
            "skipped_template_cap": 0, "skipped_trap": 0, "skipped_unsafe": 0, "skipped_budget": 0,
            "skipped_out_of_scope": 0, "bytes_scanned": 0, "scan_seconds": 0.0, "probes_hit": 0,
            "sitemap_urls": 0, "robots_paths": 0, "errors": 0,
        }

    # ---------------------------------------------------------------- start
    async def start(self):  # Scrapy >= 2.13
        for r in self.start_requests():
            yield r

    def start_requests(self):
        yield scrapy.Request(self.target, callback=self.parse_page, errback=self.on_start_error, priority=1000, meta={"depth": 0, "start": True}, dont_filter=True)
        if not self.scheme_assumed:
            yield from self.seed_requests()

    def seed_requests(self):
        base = f"{self.scope.scheme}://{urlparse(self.target).netloc}"
        # Extra start pages from the target list (same host): always crawled,
        # bypass template caps, depth 0.
        for s in self.extra_seeds:
            p = urlparse(s)
            url = base + (p.path or "/") + (("?" + p.query) if p.query else "")
            key = normalize(url, self.scope)
            if key in self.seen_pages:
                continue
            self.seen_pages.add(key)
            self.stats["pages_scheduled"] += 1
            yield scrapy.Request(url, callback=self.parse_page, errback=self.on_error, priority=950, meta={"depth": 0, "download_maxsize": self.o.max_text_bytes})
        if self.o.seed:
            yield scrapy.Request(base + "/robots.txt", callback=self.parse_robots, errback=self.on_error, priority=900, meta={"depth": 1, "dont_redirect": False})
            for sm in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/wp-sitemap.xml", "/sitemap.xml.gz"):
                r = self.sitemap_request(base + sm, 0)
                if r:
                    yield r
            # Build manifests list every JS chunk (and for some, every route)
            for mf in ("/asset-manifest.json", "/.vite/manifest.json", "/manifest.json", "/build-manifest.json"):
                r = self.asset_request(base + mf, "json", callback=self.parse_build_manifest, priority=60)
                if r:
                    yield r
        if self.o.probe:
            rnd = "".join(random.choices(string.ascii_lowercase, k=14))
            yield scrapy.Request(f"{base}/{rnd}.env", callback=self.parse_baseline, errback=self.on_error, priority=950, dont_filter=True, meta={"depth": 1, "base": base, "handle_httpstatus_all": True})

    # ---------------------------------------------------------------- recording
    def record(self, findings):
        for f in findings:
            key = (f["rule"], f["value"])
            cur = self.findings.get(key)
            if cur is None:
                f["occurrences"] = 1
                f["locations"] = [f["url"]]
                self.findings[key] = f
                self.sink(self, f)
                if f["rule"] == "email":
                    self.note_host("https://" + f["value"].partition("@")[2] + "/", "email")
            else:
                cur["occurrences"] += 1
                if f["url"] not in cur["locations"] and len(cur["locations"]) < 5:
                    cur["locations"].append(f["url"])

    def scan(self, text, url, source):
        t0 = time.perf_counter()
        self.stats["bytes_scanned"] += len(text)
        self.record(self.det.scan(text, url, source))
        self.stats["scan_seconds"] += time.perf_counter() - t0

    def scan_headers(self, response):
        pairs = []
        for k, vals in response.headers.items():
            name = k.decode("latin-1")
            for v in vals:
                value = v.decode("latin-1", "ignore")
                sig = (name.lower(), value)
                if sig in self.seen_headers:
                    continue
                self.seen_headers.add(sig)
                pairs.append((name, value))
        if pairs:
            self.record(self.det.scan_headers(pairs, response.url))

    def on_error(self, failure):
        self.stats["errors"] += 1

    def on_start_error(self, failure):
        """https was assumed for a bare host and failed: fall back to http."""
        self.stats["errors"] += 1
        self.start_error = failure.getErrorMessage()[:200]
        req = failure.request
        if self.scheme_assumed and req.url.startswith("https://"):
            self.scheme_assumed = False
            self.target = "http://" + req.url[len("https://") :]
            self.scope = Scope(self.target, include_subdomains=self.o.include_subdomains)
            yield scrapy.Request(self.target, callback=self.parse_page, errback=self.on_start_error, priority=1000, meta={"depth": 0, "start": True}, dont_filter=True)
            yield from self.seed_requests()

    # ---------------------------------------------------------------- scheduling
    def page_request(self, url, response, priority=0, source="link"):
        if not url or not url.startswith(("http://", "https://")):
            return None
        url = url.split("#", 1)[0]
        p = urlparse(url)
        if not self.scope.page_ok(p.hostname, p.port, p.scheme):
            self.stats["skipped_out_of_scope"] += 1
            return None
        path_l = p.path.lower()
        if path_l.endswith(SKIP_EXT):
            return None
        if ASSET_EXT_RE.search(path_l):
            return self.asset_request(url, "json" if path_l.endswith(".json") else "js")
        if UNSAFE_PATH_RE.search(url):
            self.stats["skipped_unsafe"] += 1
            return None
        if looks_trap(url):
            self.stats["skipped_trap"] += 1
            return None
        depth = (response.meta.get("depth", 0) if response is not None else 0) + 1
        if depth > self.o.max_depth:
            self.stats["skipped_depth"] = self.stats.get("skipped_depth", 0) + 1
            return None
        key = normalize(url, self.scope)
        if key in self.seen_pages:
            return None
        tpl = self.adaptive_template(template_of(key))
        n = self.template_counts.get(tpl, 0)
        if n >= self.o.max_per_template:
            self.stats["skipped_template_cap"] += 1
            return None
        if self.stats["pages_scheduled"] >= self.o.max_pages:
            self.stats["skipped_budget"] += 1
            return None
        self.seen_pages.add(key)
        self.template_counts[tpl] = n + 1
        self.stats["pages_scheduled"] += 1
        # Favour pages whose template is new: breadth across site sections.
        prio = priority + (20 if n == 0 else 0)
        return scrapy.Request(url, callback=self.parse_page, errback=self.on_error, priority=prio, meta={"download_maxsize": self.o.max_text_bytes})

    def asset_request(self, url, kind, callback=None, priority=50):
        url = url.split("#", 1)[0]
        p = urlparse(url)
        if p.scheme not in {"http", "https"} or not self.scope.asset_ok(p.hostname):
            return None
        key = asset_key(url)
        if key in self.seen_assets:
            return None
        if self.stats["assets_scheduled"] >= self.o.max_assets:
            self.stats["skipped_budget"] += 1
            return None
        self.seen_assets.add(key)
        self.stats["assets_scheduled"] += 1
        maxsize = self.o.max_map_bytes if kind == "map" else self.o.max_asset_bytes
        cb = callback or (self.parse_sourcemap if kind == "map" else self.parse_asset)
        # Assets don't consume crawl depth.
        return scrapy.Request(url, callback=cb, errback=self.on_error, priority=priority, cb_kwargs={"kind": kind}, meta={"download_maxsize": maxsize, "depth": 0})

    # ---------------------------------------------------------------- pages
    def parse_page(self, response):
        self.stats["pages_fetched"] += 1
        self.crawled_urls.append(response.url)
        if response.meta.get("start"):
            self.start_ok = True
            self.start_error = None
            if self.scheme_assumed:
                # https worked for a bare host: seeds were deferred until now
                self.scheme_assumed = False
                yield from self.seed_requests()
            host = urlparse(response.url).hostname
            if host and host.lower() not in self.scope.page_hosts:
                if registrable_domain(host) == self.scope.site:
                    self.scope.add_host(host)
                else:
                    self.redirected_to = response.url
                    return
        self.scan_headers(response)

        ctype = response.headers.get("Content-Type", b"").decode("latin-1").lower()
        body = response.body
        if "javascript" in ctype or "ecmascript" in ctype:
            yield from self.parse_asset(response, kind="js")
            return
        if "json" in ctype:
            yield from self.parse_asset(response, kind="json")
            return
        if not ("html" in ctype or "xml" in ctype or ctype.startswith("text") or not ctype) or is_binary(body):
            return

        h = sha1(body)
        if h in self.seen_bodies:
            self.stats["duplicate_bodies"] += 1
            return
        self.seen_bodies.add(h)
        text = response.text

        # 1. inline scripts: scan each unique block once (layouts repeat them)
        def _strip(m):
            code = m.group(2)
            if code.strip():
                sh = sha1(code)
                if sh not in self.seen_scripts:
                    self.seen_scripts.add(sh)
                    self.scan(code, response.url, "inline_js")
                    yield_list.extend(self.discover_in_js(code, response.url))
            return m.group(1) + m.group(3)

        yield_list = []
        remainder = SCRIPT_BLOCK_RE.sub(_strip, text)

        # 2. HTML remainder: only lines not seen on earlier pages (header/footer/nav dedupe)
        fresh = []
        for line in remainder.splitlines():
            if len(line) < 8:
                continue
            lh = sha1(line)
            if lh in self.seen_lines:
                self.stats["lines_skipped_dedupe"] += 1
                continue
            self.seen_lines.add(lh)
            fresh.append(line)
        if fresh:
            self.scan("\n".join(fresh), response.url, "html")

        if self.o.include_comments:
            for c in COMMENT_RE.findall(remainder):
                c = c.strip()
                if c and len(self.comments) < 2000:
                    self.comments.add(c[:500])

        yield from yield_list

        # 3. links
        try:
            sel = response
            anchors = sel.css("a::attr(href), area::attr(href)").getall()
            frames = sel.css("iframe::attr(src), frame::attr(src)").getall()
            forms = sel.css("form::attr(action)").getall()
            link_rel = sel.xpath("//link[@href]")
            scripts = sel.css("script::attr(src)").getall()
            self.form_fields.update(x for x in sel.css("input::attr(name), textarea::attr(name), select::attr(name)").getall() if len(self.form_fields) < 5000)
        except (ValueError, AttributeError):
            return
        hrefs = anchors + frames + forms
        # Links hidden in data-* attributes and onclick / JS navigation
        hrefs += [m.group(1) for m in DATA_LINK_RE.finditer(text)]
        hrefs += [m.group(1) for m in JS_NAV_RE.finditer(text)]
        for kind, vals in (("link", anchors), ("iframe", frames), ("form", forms)):
            for v in vals:
                self.note_host(response.urljoin(v.strip()), kind)

        for bid in NEXT_BUILD_ID_RE.findall(text)[:2]:
            if bid not in self.next_build_ids and "/_next/" in text:
                self.next_build_ids.add(bid)
                origin = f"{urlparse(response.url).scheme}://{urlparse(response.url).netloc}"
                for name in ("_buildManifest.js", "_ssgManifest.js"):
                    r = self.asset_request(f"{origin}/_next/static/{bid}/{name}", "js", callback=self.parse_build_manifest, priority=70)
                    if r:
                        yield r

        for src in scripts:
            url = response.urljoin(src.strip())
            self.note_host(url, "script")
            self.js_files.add(url)
            r = self.asset_request(url, "js")
            if r:
                yield r
        for el in link_rel:
            rel = (el.attrib.get("rel") or "").lower()
            href = response.urljoin(el.attrib.get("href", "").strip())
            as_ = (el.attrib.get("as") or "").lower()
            if "modulepreload" in rel or ("preload" in rel and as_ == "script"):
                self.js_files.add(href)
                r = self.asset_request(href, "js")
            elif "manifest" in rel:
                r = self.asset_request(href, "json")
            elif "stylesheet" in rel or "icon" in rel or "preconnect" in rel or "dns-prefetch" in rel or "font" in as_:
                r = None
            else:
                r = self.page_request(href, response, priority=-10)
            if r:
                yield r
        m = META_REFRESH_RE.search(text)
        if m:
            hrefs.append(m.group(1).strip())
        depth = response.meta.get("depth", 0)
        for href in hrefs:
            href = href.strip()
            if not href or href.startswith(("javascript:", "data:", "#", "tel:", "sms:")):
                continue
            if href.startswith("mailto:"):
                self.record(self.det.scan(href, response.url, "html"))
                continue
            r = self.page_request(response.urljoin(href), response, priority=-depth * 10)
            if r:
                yield r
        yield from self.drain_subdomain_seeds()

    MAX_CHILDREN = 25

    def adaptive_template(self, tpl):
        """Once a folder has many distinct children (/category/<30 names>,
        /product/<slug>), treat its last segment as a variable so the
        per-template cap applies to the rest."""
        path, _, q = tpl.partition("?")
        parent, _, last = path.rpartition("/")
        if not parent or last.startswith("{"):
            return tpl
        kids = self.template_children.setdefault((parent, q), set())
        if last in kids:
            return tpl
        if len(kids) < self.MAX_CHILDREN:
            kids.add(last)
            return tpl
        return f"{parent}/{{var}}?{q}"

    # ---------------------------------------------------------------- hosts
    def note_host(self, url, kind):
        """Track every host the site references (inventory, lookalike and
        dangling-domain checks) and queue newly seen subdomains."""
        try:
            p = urlparse(url)
            host = (p.hostname or "").lower().rstrip(".")
        except ValueError:
            return
        if not host or "." not in host or p.scheme not in {"http", "https", ""}:
            return
        if registrable_domain(host) == self.scope.site:
            if host not in self.scope.page_hosts:
                self.discovered_hosts.add(host)
            return
        refs = self.external_refs.get(host)
        if refs is None:
            if len(self.external_refs) >= 3000:
                return
            refs = self.external_refs[host] = set()
        refs.add(kind)

    def drain_subdomain_seeds(self):
        if not self.o.include_subdomains:
            return
        for host in sorted(self.discovered_hosts - self.seeded_hosts):
            if len(self.seeded_hosts) >= self.o.max_subdomains:
                return
            self.seeded_hosts.add(host)
            r = self.page_request(f"{self.scope.scheme}://{host}/", None, priority=5, source="subdomain")
            if r:
                yield r

    # ---------------------------------------------------------------- assets
    def parse_asset(self, response, kind="js"):
        self.stats["assets_fetched"] += 1
        body = response.body
        if response.status >= 400 or not body or is_binary(body):
            return
        head = body[:200].lstrip().lower()
        if head.startswith((b"<!doctype", b"<html", b"<head", b"<body")):
            return  # SPA catch-all / soft 404 returning the index page
        h = sha1(body)
        if h in self.seen_bodies:
            self.stats["duplicate_bodies"] += 1
            return
        self.seen_bodies.add(h)
        self.scan_headers(response)
        try:
            text = response.text
        except AttributeError:
            text = body.decode("utf-8", "ignore")
        self.scan(text, response.url, kind)
        if kind in {"js", "json"}:
            yield from self.discover_in_js(text, response.url)
            smap = None
            for hname in (b"SourceMap", b"X-SourceMap"):
                if response.headers.get(hname):
                    smap = response.headers.get(hname).decode("latin-1")
            m = None if smap else SOURCEMAP_RE.search(text[-4000:])
            if m:
                smap = m.group(1)
            if smap:
                if smap.startswith("data:"):
                    yield from self._inline_sourcemap(smap, response.url)
                else:
                    r = self.asset_request(urljoin(response.url, smap), "map", priority=40)
                    if r:
                        yield r
            elif self.o.probe_sourcemaps and kind == "js" and not is_vendor(response.url):
                r = self.asset_request(response.url.split("?", 1)[0] + ".map", "map", priority=30)
                if r:
                    yield r

    def discover_in_js(self, text, base_url):
        out = []
        base = urlparse(base_url)
        origin = f"{base.scheme}://{base.netloc}"
        new_endpoints = []
        if len(self.endpoints) < 3000:
            for m in ENDPOINT_RE.finditer(text):
                ep = m.group(1)[:300]
                if ep not in self.endpoints:
                    self.endpoints.add(ep)
                    new_endpoints.append(ep)
        # Config-style API endpoints (/api/config, /api/v1/settings) often
        # return keys; GET them when --probe is on. Bounded and read-only.
        if self.o.probe:
            for ep in new_endpoints:
                if self.config_probes >= 30 or "{" in ep or "$" in ep or not CONFIG_ENDPOINT_RE.search(ep.split("?", 1)[0]):
                    continue
                url = ep if ep.startswith("http") else origin + ep
                r = self.asset_request(url, "json", priority=35)
                if r:
                    self.config_probes += 1
                    out.append(r)
        # Absolute URLs: inventory every host; same-site pages get crawled
        if "://" in text:
            n_pages = 0
            for m in PAGE_ABS_URL_RE.finditer(text):
                u = m.group(1)
                self.note_host(u, "js_ref")
                p = urlparse(u)
                if n_pages < 50 and self.scope.page_ok(p.hostname, p.port, p.scheme) and not ASSET_EXT_RE.search(p.path) and "${" not in u and "{" not in p.path:
                    r = self.page_request(u, None, priority=-30, source="js")
                    if r:
                        n_pages += 1
                        out.append(r)
        # Webpack runtime chunk maps: lazy chunks never appear as literal paths
        if "+" in text and ("webpack" in text or "chunk" in text):
            out.extend(self._webpack_chunks(text, base_url, origin))
        for m in JS_PATH_RE.finditer(text):
            path = m.group(1)
            fname = path.rsplit("/", 1)[-1]
            if "/" not in path and not re.search(r"[.-][0-9a-f]{6,}\.m?js$", fname):
                continue
            if path.startswith(("//", "http://", "https://")):
                url = urljoin(base_url, path)
            elif path.startswith("/"):
                url = origin + path
            elif path.startswith("static/") and "/_next/" in base.path:
                url = origin + "/_next/" + path
            else:
                url = urljoin(base_url, path)
            kind = "map" if path.endswith(".map") else "json" if path.endswith(".json") else "js"
            r = self.asset_request(url, kind, priority=45)
            if r:
                out.append(r)
        return out

    def _webpack_chunks(self, text, base_url, origin):
        out = []
        pm = WEBPACK_PUBLIC_PATH_RE.search(text)
        public = pm.group(1) if pm else "/"
        if public.startswith(("http://", "https://", "//")):
            root = urljoin(base_url, public)
        elif public.startswith("/"):
            root = origin + public
        elif public in ("", "auto", "./"):
            root = base_url.rsplit("/", 1)[0] + "/"
            # CRA/Next put the runtime in static/js/ while the template is
            # rooted at the site root ("static/js/" + id ...)
        else:
            root = origin + "/" + public
        for m in WEBPACK_CHUNK_RE.finditer(text):
            prefix, sep, hashes, suffix = m.group(1), m.group(2), m.group(3), m.group(4)
            names = {}
            nm = WEBPACK_NAMES_RE.search(m.group(0))
            if nm:
                names = dict(CHUNK_PAIR_RE.findall(nm.group(1)))
            pairs = CHUNK_PAIR_RE.findall(hashes)
            if not pairs:
                continue
            if prefix.startswith("/"):
                stem = origin + prefix
            elif prefix.startswith(("static/", "_next/")) and public in ("", "auto", "./"):
                stem = origin + "/" + ("_next/" if "/_next/" in base_url and prefix.startswith("static/") else "") + prefix
            else:
                stem = urljoin(root, prefix)
            for cid, h in pairs[:400]:
                url = f"{stem}{names.get(cid, cid)}{sep}{h}{suffix}"
                self.js_files.add(url)
                r = self.asset_request(url, "js", priority=42)
                if r:
                    out.append(r)
                    self.stats["webpack_chunks"] = self.stats.get("webpack_chunks", 0) + 1
        return out

    def parse_build_manifest(self, response, kind="json"):
        """CRA asset-manifest.json, Vite .vite/manifest.json and Next.js
        _buildManifest.js: every JS chunk, and (Next) every page route."""
        self.stats["assets_fetched"] += 1
        body = response.body
        if response.status >= 400 or not body or body[:200].lstrip().lower().startswith((b"<!doctype", b"<html")):
            return
        text = body.decode("utf-8", "ignore")
        origin = f"{urlparse(response.url).scheme}://{urlparse(response.url).netloc}"
        self.scan(text, response.url, "json" if kind == "json" else "js")
        files, routes = set(), set()
        if response.url.endswith((".js",)):
            # Next.js: self.__BUILD_MANIFEST = {"/about": ["static/chunks/pages/about-123.js"], ...}
            routes.update(re.findall(r"""["'](/[A-Za-z0-9_./\[\]-]*)["']\s*:\s*\[""", text))
            files.update("/_next/" + f for f in re.findall(r"""["'](static/[\w./\[\]%-]+\.js)["']""", text))
        else:
            d = _json(text)
            if isinstance(d, dict):
                if isinstance(d.get("files"), dict):  # CRA
                    files.update(v for v in d["files"].values() if isinstance(v, str))
                    files.update(v for v in d.get("entrypoints", []) if isinstance(v, str))
                else:  # Vite: {"src/main.ts": {"file": "assets/main-abc.js", "imports": [...]}}
                    for v in d.values():
                        if isinstance(v, dict) and isinstance(v.get("file"), str):
                            files.add(v["file"])
                            files.update(x for x in v.get("dynamicImports", []) if isinstance(x, str) and x.endswith(".js"))
                if d.get("start_url") and isinstance(d.get("start_url"), str):  # web app manifest
                    routes.add(d["start_url"])
        for f in sorted(files)[:800]:
            if not f.endswith((".js", ".mjs", ".json", ".map")):
                continue
            url = urljoin(origin + "/", f.lstrip("./")) if not f.startswith("http") else f
            self.js_files.add(url)
            r = self.asset_request(url, "map" if f.endswith(".map") else "js", priority=44)
            if r:
                yield r
        for route in sorted(routes)[:300]:
            if "[" in route or route.startswith("/_"):
                continue  # dynamic segment or internal page
            r = self.page_request(origin + route, None, priority=-15, source="manifest")
            if r:
                yield r

    def _inline_sourcemap(self, data_uri, js_url):
        import base64

        try:
            payload = data_uri.split(",", 1)[1]
            raw = base64.b64decode(payload) if ";base64" in data_uri[:80] else payload.encode()
            yield from self._scan_sourcemap_json(raw, js_url + "#inline-map")
        except (ValueError, IndexError):
            return

    def parse_sourcemap(self, response, kind="map"):
        self.stats["assets_fetched"] += 1
        if response.status >= 400 or not response.body:
            return
        h = sha1(response.body)
        if h in self.seen_bodies:
            return
        self.seen_bodies.add(h)
        yield from self._scan_sourcemap_json(response.body, response.url)

    def _scan_sourcemap_json(self, raw, map_url):
        try:
            data = json.loads(raw)
        except ValueError:
            return
        if not isinstance(data, dict):
            return
        self.stats["sourcemaps_fetched"] += 1
        sources = data.get("sources") or []
        contents = data.get("sourcesContent") or []
        for name, content in zip(sources, contents):
            if not content or not isinstance(content, str):
                continue
            if not self.o.include_vendor and (is_vendor("/" + str(name)) or "node_modules" in str(name) or str(name).startswith(("webpack/", "(webpack)"))):
                continue
            h = sha1(content)
            if h in self.seen_scripts:
                continue
            self.seen_scripts.add(h)
            self.scan(content, f"{map_url}#{name}", "sourcemap")
            if len(self.endpoints) < 3000:
                for m in ENDPOINT_RE.finditer(content):
                    self.endpoints.add(m.group(1)[:300])
        return
        yield  # pragma: no cover - make this a generator

    # ---------------------------------------------------------------- seeding
    def parse_robots(self, response):
        if response.status >= 400 or b"<html" in response.body[:500].lower():
            return
        text = response.text if hasattr(response, "text") else response.body.decode("utf-8", "ignore")
        self.scan(text, response.url, "config")
        base = f"{self.scope.scheme}://{urlparse(response.url).netloc}"
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            low = line.lower()
            if low.startswith("sitemap:"):
                r = self.sitemap_request(urljoin(response.url, line.split(":", 1)[1].strip()), 0)
                if r:
                    yield r
            elif low.startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and "*" not in path and "$" not in path:
                    self.stats["robots_paths"] += 1
                    r = self.page_request(base + path, response, priority=-5, source="robots")
                    if r:
                        yield r

    def sitemap_request(self, url, level):
        if not url.startswith(("http://", "https://")) or url in self.seen_sitemaps or len(self.seen_sitemaps) >= 60:
            return None
        if not self.scope.asset_ok(urlparse(url).hostname):
            return None
        self.seen_sitemaps.add(url)
        return scrapy.Request(url, callback=self.parse_sitemap, errback=self.on_error, priority=-50 - level * 10, dont_filter=True, meta={"sitemap_level": level, "download_maxsize": 30_000_000})

    def parse_sitemap(self, response):
        if response.status >= 400:
            return
        body = response.body
        if response.url.endswith(".gz") or body[:2] == b"\x1f\x8b":
            import gzip

            try:
                body = gzip.decompress(body)
            except OSError:
                return
        text = body.decode("utf-8", "ignore")
        if "<urlset" not in text and "<sitemapindex" not in text:
            return
        level = response.meta.get("sitemap_level", 0)
        locs = SITEMAP_LOC_RE.findall(text)
        if "<sitemapindex" in text:
            if level >= 2:
                return
            # Prefer page/post sitemaps over image/video/tag ones
            locs = sorted(locs, key=lambda u: bool(re.search(r"(?i)image|video|tag|author|attachment", u)))
            for loc in locs[:25]:
                r = self.sitemap_request(loc.strip(), level + 1)
                if r:
                    yield r
            return
        for loc in locs:
            self.stats["sitemap_urls"] += 1
            r = self.page_request(loc.strip(), response, priority=-40, source="sitemap")
            if r:
                yield r

    # ---------------------------------------------------------------- probes
    def parse_baseline(self, response):
        self.soft404 = (response.status, len(response.body), sha1(response.body))
        base = response.meta["base"]
        for path, check, sev, title in PROBES:
            yield scrapy.Request(
                base + path, callback=self.parse_probe, errback=self.on_error, priority=800,
                meta={"depth": 1, "probe": (path, check, sev, title), "dont_redirect": True, "handle_httpstatus_list": [200], "download_maxsize": 5_000_000},
            )

    def _is_soft404(self, body):
        if not self.soft404:
            return False
        st, ln, h = self.soft404
        return sha1(body) == h or (st == 200 and abs(len(body) - ln) <= max(32, ln * 0.03))

    def parse_probe(self, response):
        path, check, sev, title = response.meta["probe"]
        body = response.body
        if response.status != 200 or not body or self._is_soft404(body):
            return
        if is_binary(body) and path not in BINARY_PROBES:
            return
        text = body.decode("utf-8", "ignore")
        is_html = text[:300].lstrip().lower().startswith(("<!doctype", "<html", "<head", "<body"))
        try:
            ok = check(text, body, is_html)
        except (ValueError, TypeError, AttributeError, IndexError, KeyError):
            ok = False
        if not ok:
            return
        self.stats["probes_hit"] += 1
        extra = self._probe_extra(path, text, response.url, body)
        f = {
            "rule": "exposed_file" if sev != "info" else "public_config", "title": f"{title}: {urlparse(response.url).path}",
            "category": "exposure", "severity": sev, "confidence": "high", "value": response.url, "url": response.url,
            "source": "probe", "context": re.sub(r"\s+", " ", text[:160]) if path not in BINARY_PROBES else "",
            "reasons": ["content_validated", "not_soft_404"],
        }
        if extra:
            f["extra"] = extra
        self.record([f])
        if path not in BINARY_PROBES:
            self.scan(text, response.url, "probe")
        if path.endswith((".js", ".json")) or _json(text) is not None:
            yield from self.discover_in_js(text, response.url)
        if "graphql" in path:
            q = "%7B__schema%7BqueryType%7Bname%7DmutationType%7Bname%7Dtypes%7Bname%7D%7D%7D"
            yield scrapy.Request(response.url.split("?", 1)[0] + "?query=" + q, callback=self.parse_introspection, errback=self.on_error, priority=790, dont_filter=True, meta={"depth": 1, "handle_httpstatus_list": [200, 400]})

    def _probe_extra(self, path, text, url, body=b""):
        if path.startswith(("/swagger", "/openapi", "/api", "/v2/api-docs", "/v3/api-docs")) and _spec_ok(text, b"", False):
            d = _json(text)
            base = ""
            if isinstance(d.get("servers"), list) and d["servers"] and isinstance(d["servers"][0], dict):
                base = str(d["servers"][0].get("url", "")).rstrip("/")
            elif d.get("basePath"):
                base = str(d["basePath"]).rstrip("/")
            paths = list(d["paths"].keys())
            for p in paths[:2000]:
                self.endpoints.add((base + p)[:300])
            info = d.get("info") if isinstance(d.get("info"), dict) else {}
            return {"title": info.get("title"), "version": info.get("version"), "path_count": len(paths), "sample_paths": paths[:15]}
        if path == "/wp-json/wp/v2/users":
            users = _json(text) or []
            return {"users": [u.get("slug") for u in users[:50] if isinstance(u, dict)]}
        if path == "/.DS_Store" and body:
            names = sorted({m.group(1).decode("utf-16-be", "ignore") for m in DS_STORE_ENTRY_RE.finditer(body)})
            for n in names[:200]:
                if n and "/" not in n and not n.startswith("."):
                    self.endpoints.add(urlparse(url).path.rsplit("/", 1)[0] + "/" + n)
            return {"entries": names[:100]} if names else None
        return None

    def parse_introspection(self, response):
        d = _json(response.text) if response.status == 200 else None
        schema = ((d or {}).get("data") or {}).get("__schema") if isinstance(d, dict) else None
        if not schema:
            return
        types = [t.get("name") for t in schema.get("types") or [] if isinstance(t, dict) and not str(t.get("name", "")).startswith("__")]
        self.record([{
            "rule": "graphql_introspection", "title": "GraphQL introspection enabled", "category": "exposure",
            "severity": "medium", "confidence": "high", "value": response.url.split("?", 1)[0], "url": response.url,
            "source": "probe", "context": f"{len(types)} types; mutations: {bool(schema.get('mutationType'))}",
            "reasons": ["introspection_query_answered"], "extra": {"type_count": len(types), "sample_types": types[:30], "has_mutations": bool(schema.get("mutationType"))},
        }])

    # ---------------------------------------------------------------- status
    def status(self):
        return {
            "target": self.target,
            "pages": self.stats["pages_fetched"],
            "assets": self.stats["assets_fetched"],
            "findings": len(self.findings),
            "elapsed": time.time() - self.start_ts,
        }
