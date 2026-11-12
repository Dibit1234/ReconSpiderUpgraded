"""Scrapy spider: bounded, deduplicated discovery from a single start URL."""

import hashlib
import json
import random
import re
import string
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import scrapy

from .detect import Detector, ENV_LINE_RE, is_vendor, registrable_domain

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

PROBE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.prod", "/.env.development", "/.env.backup",
    "/.env.bak", "/.env.old", "/api/.env", "/backend/.env",
    "/config.json", "/config.js", "/env.js", "/env.json", "/__env.js", "/env-config.js",
    "/runtime-config.js", "/app-config.json", "/appsettings.json", "/appsettings.Development.json",
    "/settings.json", "/assets/config.json", "/assets/env.json", "/static/config.json",
    "/.git/config", "/.npmrc", "/.aws/credentials", "/docker-compose.yml", "/docker-compose.yaml",
    "/web.config", "/sftp-config.json", "/.vscode/sftp.json", "/wp-config.php.bak", "/wp-config.php.old",
    "/wp-config.php~", "/config.php.bak", "/.htpasswd", "/server-status", "/phpinfo.php",
]
PROBE_SEVERITY = {".env": "high", ".git/config": "medium", ".aws/credentials": "critical", ".htpasswd": "high", ".npmrc": "medium", "wp-config": "critical", "phpinfo": "medium", "server-status": "low"}


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

    def __init__(self, target, opts, sink, scheme_assumed=False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target = target
        self.scheme_assumed = scheme_assumed
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
        self.template_counts = {}

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
        if self.o.seed:
            yield scrapy.Request(base + "/robots.txt", callback=self.parse_robots, errback=self.on_error, priority=900, meta={"depth": 1, "dont_redirect": False})
            yield scrapy.Request(base + "/sitemap.xml", callback=self.parse_sitemap, errback=self.on_error, priority=-50, meta={"depth": 1, "sitemap_level": 0})
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
        tpl = template_of(key)
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
            hrefs = sel.css("a::attr(href), area::attr(href), iframe::attr(src), frame::attr(src), form::attr(action), [data-href]::attr(data-href), [data-url]::attr(data-url)").getall()
            link_rel = sel.xpath("//link[@href]")
            scripts = sel.css("script::attr(src)").getall()
            self.form_fields.update(x for x in sel.css("input::attr(name), textarea::attr(name), select::attr(name)").getall() if len(self.form_fields) < 5000)
        except (ValueError, AttributeError):
            return

        for src in scripts:
            url = response.urljoin(src.strip())
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
        if len(self.endpoints) < 3000:
            for m in ENDPOINT_RE.finditer(text):
                self.endpoints.add(m.group(1)[:300])
        base = urlparse(base_url)
        origin = f"{base.scheme}://{base.netloc}"
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
                r = scrapy.Request(urljoin(response.url, line.split(":", 1)[1].strip()), callback=self.parse_sitemap, errback=self.on_error, priority=-50, meta={"sitemap_level": 0})
                yield r
            elif low.startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and "*" not in path and "$" not in path:
                    self.stats["robots_paths"] += 1
                    r = self.page_request(base + path, response, priority=-5, source="robots")
                    if r:
                        yield r

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
            for loc in locs[:10]:
                yield scrapy.Request(loc.strip(), callback=self.parse_sitemap, errback=self.on_error, priority=-60, meta={"sitemap_level": level + 1})
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
        for path in PROBE_PATHS:
            yield scrapy.Request(base + path, callback=self.parse_probe, errback=self.on_error, priority=800, meta={"depth": 1, "probe": path, "dont_redirect": True, "handle_httpstatus_list": [200]})

    def parse_probe(self, response):
        if response.status != 200 or not response.body or is_binary(response.body):
            return
        path = response.meta["probe"]
        body = response.body
        if self.soft404 and (sha1(body) == self.soft404[2] or (self.soft404[0] == 200 and abs(len(body) - self.soft404[1]) <= max(32, self.soft404[1] * 0.03))):
            return
        text = body.decode("utf-8", "ignore")
        head = text[:300].lstrip().lower()
        is_html = head.startswith(("<!doctype", "<html", "<head", "<body"))
        ok = False
        if path.startswith("/.env") or path.endswith("/.env"):
            ok = not is_html and len(ENV_LINE_RE.findall(text)) >= 1 and re.search(r"(?m)^[A-Z_][A-Z0-9_]*=", text) is not None
        elif path == "/.git/config":
            ok = "[core]" in text
        elif path == "/.aws/credentials":
            ok = "aws_access_key_id" in text.lower()
        elif path == "/.htpasswd":
            ok = re.search(r"(?m)^[^:\s]+:\$?[\w./$]{10,}", text) is not None
        elif path == "/.npmrc":
            ok = "registry" in text or "_auth" in text
        elif path.endswith(".json"):
            try:
                ok = isinstance(json.loads(text), (dict, list)) and not is_html
            except ValueError:
                ok = False
        elif path.endswith((".yml", ".yaml")):
            ok = not is_html and "services:" in text
        elif path == "/web.config":
            ok = "<configuration" in text.lower()
        elif path.endswith(".js"):
            ok = not is_html and ("=" in text or ":" in text)
        elif "wp-config" in path or path.endswith((".bak", ".old", "~")):
            ok = "DB_PASSWORD" in text or "<?php" in text
        elif path == "/phpinfo.php":
            ok = "phpinfo()" in text or "PHP Version" in text
        elif path == "/server-status":
            ok = "Apache Server Status" in text
        if not ok:
            return
        self.stats["probes_hit"] += 1
        sev = next((s for k, s in PROBE_SEVERITY.items() if k in path), "medium")
        self.record([{
            "rule": "exposed_file", "title": f"Exposed sensitive file {path}", "category": "exposure",
            "severity": sev, "confidence": "high", "value": response.url, "url": response.url,
            "source": "probe", "context": re.sub(r"\s+", " ", text[:160]), "reasons": ["content_validated", "not_soft_404"],
        }])
        self.scan(text, response.url, "probe")
        if path.endswith((".js", ".json")):
            yield from self.discover_in_js(text, response.url)

    # ---------------------------------------------------------------- status
    def status(self):
        return {
            "target": self.target,
            "pages": self.stats["pages_fetched"],
            "assets": self.stats["assets_fetched"],
            "findings": len(self.findings),
            "elapsed": time.time() - self.start_ts,
        }
