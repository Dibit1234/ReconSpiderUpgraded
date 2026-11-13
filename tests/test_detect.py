"""Unit tests for the detection engine and URL helpers.  Run: python -m pytest -q"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

import fixture_site as fx  # noqa: E402
from reconspider.crawl import asset_key, looks_trap, normalize, template_of  # noqa: E402
from reconspider.detect import Detector, classify_key, value_rejection  # noqa: E402
from reconspider.rules import crc32_base62_ok  # noqa: E402


def scan(text, source="js", url="https://acme.com/static/js/app.js", host="acme.com"):
    return Detector(target_host=host).scan(text, url, source)


def shown(findings):
    return [f for f in findings if f["severity"] != "info"]


def values(findings):
    return {f["value"] for f in findings}


# ---------------------------------------------------------------- provider rules
@pytest.mark.parametrize(
    "rule,value",
    [
        ("aws_access_key_id", fx.S["aws_id"]),
        ("stripe_secret_key", fx.S["stripe"]),
        ("sendgrid_api_key", fx.S["sendgrid"]),
        ("openai_api_key", fx.S["openai"]),
        ("telegram_bot_token", fx.S["telegram"]),
        ("mailchimp_api_key", fx.S["mailchimp"]),
        ("google_oauth_client_secret", fx.S["gocspx"]),
        ("github_token", fx.S["gh"]),
    ],
)
def test_provider_true_positives(rule, value):
    fs = scan(f'const x = "{value}";')
    assert any(f["rule"] == rule and f["value"] == value and f["severity"] != "info" for f in fs), fs


def test_github_checksum():
    assert crc32_base62_ok(fx.S["gh"], 4)
    assert not crc32_base62_ok(fx.D["gh_bad"], 4)
    bad = [f for f in scan(f'"{fx.D["gh_bad"]}"') if f["rule"] == "github_token"]
    assert bad and bad[0]["severity"] == "info"


@pytest.mark.parametrize(
    "text",
    [
        'aws = { accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }',
        "var m = this.pk.data.items;",
        'cls = "data-sk-toggle-collapsed-sidebar"',
        'store = "key-value-store-identifier-x"',
        'var PEM = "-----BEGIN RSA PRIVATE KEY-----"; function p(s){return s.replace(PEM,"").split("\\n").map(function(x){return x.trim()}).join("")} var END="-----END RSA PRIVATE KEY-----";',
        f'const sample = "{fx.D["jwt_sample"]}";',
    ],
)
def test_provider_decoys_not_reported(text):
    assert shown(scan(text)) == []


def test_jwt_roles():
    fs = {f["value"]: f for f in scan(f'a("{fx.P["supabase_anon"]}"); b("{fx.S["supabase_svc"]}")')}
    assert fs[fx.P["supabase_anon"]]["severity"] == "info"
    assert fs[fx.S["supabase_svc"]]["severity"] == "critical"


def test_private_key_with_body():
    text = '{"key": "-----BEGIN RSA PRIVATE KEY-----\\n' + fx.S["pem"].replace("\n", "\\n") + '\\n-----END RSA PRIVATE KEY-----\\n"}'
    assert any(f["rule"] == "private_key" for f in scan(text, "json"))


def test_escaped_json_is_decoded():
    hook = fx.S["slack_hook"].replace("/", "\\/")
    assert any(f["rule"] == "slack_webhook" for f in scan(f'{{"webhook":"{hook}"}}', "inline_js"))


def test_html_entities_decoded():
    text = f'<div data-config="{{&quot;stripe&quot;:&quot;{fx.S["stripe"]}&quot;}}"></div>'
    assert any(f["rule"] == "stripe_secret_key" for f in scan(text, "html"))


# ---------------------------------------------------------------- generic key/value
@pytest.mark.parametrize(
    "key,kind",
    [
        ("dbPassword", "password"), ("DB_PASSWORD", "password"), ("admin_password", "password"),
        ("smtpPass", "password"), ("client_secret", "secret"), ("apiKey", "secret"), ("API_KEY", "secret"),
        ("data-api-key", "secret"), ("accessToken", "secret"), ("privateKey", "secret"), ("username", "username"),
        ("passwordLabel", None), ("passwordPlaceholder", None), ("password_reset_url", None), ("csrfToken", None),
        ("keyCode", None), ("primaryKey", None), ("cacheKey", None), ("sitekey", None), ("publishableKey", None),
        ("isPasswordVisible", None), ("tokenExpiry", None), ("showPassword", None), ("bypass", None), ("compass", None),
    ],
)
def test_classify_key(key, kind):
    assert classify_key(key)[0] == kind


@pytest.mark.parametrize(
    "value,kind",
    [
        ("Password", "password"), ("Enter your password", "password"), ("YOUR_API_KEY_HERE", "secret"),
        ("process.env.API_KEY", "secret"), ("${API_KEY}", "secret"), ("{{ secret }}", "secret"),
        ("********", "password"), ("app.auth.token", "secret"), ("auth/missing-app-credential", "secret"),
        ("__reactResources$", "secret"), ("object", "password"), ("/reset", "password"), ("API_KEY", "secret"),
        ("changeme", "password"), ("xxxxxxxxxxxxxxxx", "secret"),
    ],
)
def test_value_rejected(value, kind):
    assert value_rejection(value, kind, "k") is not None


@pytest.mark.parametrize("value,kind", [("Tr0ub4dor&3x", "password"), ("admin123", "password"), ("admin", "password"), (fx.S["api_secret"], "secret")])
def test_value_accepted(value, kind):
    assert value_rejection(value, kind, "k") is None


def test_generic_assignment_contexts():
    fs = scan('var c = { dbPassword: "Tr0ub4dor&3x", label: "x", user: e.user, password: e.password, secret: true };')
    assert values(shown(fs)) == {"Tr0ub4dor&3x"}
    assert shown(scan('if (typeof t.password === "object") {}')) == []
    assert values(scan('if (pwd === "letmein99") login()')) == {"letmein99"}


def test_env_lines_only_in_config_sources():
    env = "APP_ENV=production\nDB_PASSWORD=pr0d-Db-P4ss-77\n"
    assert values(scan(env, "config", url="https://acme.com/.env")) == {"pr0d-Db-P4ss-77"}


def test_username_requires_paired_credential():
    assert shown(scan('cfg = { username: "svc_backup" }')) == []
    paired = scan('cfg = { username: "svc_backup", password: "B4ckup!2024" }')
    assert {"svc_backup", "B4ckup!2024"} <= values(paired)


# ---------------------------------------------------------------- URL creds / basic auth
def test_url_credentials():
    fs = scan('const u = "mongodb+srv://app:S3cr3tPw9@cluster0.mongodb.net/db"; const d = "postgres://user:password@localhost/db";')
    assert [f["severity"] for f in fs if f["rule"] == "url_credentials"] == ["critical"]


def test_basic_auth_decoded():
    fs = scan(f'headers: {{ Authorization: "Basic {fx.S["basic_b64"]}" }}')
    f = next(f for f in fs if f["rule"] == "basic_auth_header")
    assert f["extra"]["decoded"] == f'{fx.S["basic_user"]}:{fx.S["basic_pw"]}'


# ---------------------------------------------------------------- IPs
def test_internal_ips():
    text = 'backend: "http://192.168.50.211:8080", db: "10.0.0.12", lib: "v1.2.3.4", dns: "8.8.8.8", net: "10.0.0.0"'
    assert values(shown(scan(text))) == {"192.168.50.211", "10.0.0.12"}


def test_ip_noise():
    assert shown(scan('<svg><path d="M12.150.18.40L3 4z"/></svg>', "html")) == []
    assert scan('t="12:30:45"; a::before{}', "html") == []
    assert scan('s("2.5.29.14","subjectKeyIdentifier")') == []
    assert shown(scan("// e.g. 192.168.1.5 bypasses the proxy\nvar x=1;")) == []


def test_header_ip():
    fs = Detector().scan_headers([("X-Backend-Server", "10.20.30.40"), ("Server", "nginx/1.25.3")], "u")
    assert values(fs) == {"10.20.30.40"}


# ---------------------------------------------------------------- emails
def test_emails():
    html = (
        '<img src="logo@2x.png"> Our products are available at acme-corp.com. '
        'Contact it-support [at] acme-corp [dot] com or <a href="mailto:jane@acme.com">x</a> '
        "sentry: 0123456789abcdef0123456789abcdef@o1.ingest.sentry.io"
    )
    assert values(scan(html, "html")) == {"it-support@acme-corp.com", "jane@acme.com"}


def test_offsite_emails_in_js_dropped():
    fs = scan('/*! lib by dev@lib-author.org */ var c="sales@acme.com";')
    assert values(fs) == {"sales@acme.com"}


# ---------------------------------------------------------------- URL helpers
def test_url_helpers():
    assert normalize("HTTP://Acme.com:80/a/?utm_source=x&b=2&a=1#frag") == "http://acme.com/a?a=1&b=2"
    assert asset_key("https://acme.com/app.js?v=1") == asset_key("https://acme.com/app.js?v=2")
    assert template_of("https://acme.com/blog/how-to-choose-the-right-widget-12") == template_of("https://acme.com/blog/why-we-moved-to-a-new-office")
    assert template_of("https://acme.com/item/123?page=2") == template_of("https://acme.com/item/999?page=7")
    assert template_of("https://acme.com/about") != template_of("https://acme.com/contact")
    assert looks_trap("https://acme.com/a/b/a/b/a/b/c")
    assert not looks_trap("https://acme.com/docs/a/b/c")


# ================================================================ v4.1: real-world FP shapes
def test_datadog_rum_token_is_public_but_api_key_is_not():
    rum = scan(f'DD_RUM.init({{ clientToken: "{fx.P["dd_rum"]}", applicationId: "3816bfdf-6698-4c50-aafa-f16770d1a433" }})', "inline_js")
    assert [(f["rule"], f["severity"]) for f in rum] == [("datadog_client_token", "info")]
    api = scan(f'var m = {{ datadog_api_key: "{fx.S["dd_api"]}" }}')
    assert any(f["rule"] == "datadog_api_key" and f["severity"] == "critical" for f in api)


def test_scheme_as_username_is_not_credentials():
    fs = scan('<a href="http://mailto:dareenquiries@seniors.com.au">x</a>', "html")
    assert [f["rule"] for f in fs] == ["email"]


def test_header_only_and_truncated_jwt_rejected():
    for v in ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJhbGciOiJIUzI1Ni"):
        assert shown(scan(f'{{"access_token":"{v}","token_type":"bearer"}}')) == []


def test_mock_bundle_downgraded_and_flagged():
    fs = scan(fx.MSW_BUNDLE, "js", url="https://acme.com/static/js/browser-D74W5xup.js")
    assert [f["rule"] for f in shown(fs)] == ["mock_api_handlers"]
    assert {f["value"] for f in fs if f["severity"] == "info"} >= {"kag0Uk2wvbMTOPi", "10.10.10.10"}


def test_placeholder_context_downgrades_generic():
    fs = scan('le.json({ClientID:12345678,QuoteID:87654321,EvolveUpdatePaymentDetailsToken:"kag0Uk2wvbMTOPi"})')
    assert [(f["severity"], f["confidence"]) for f in fs] == [("low", "low")]


def test_bulk_ip_list_collapsed():
    fs = scan(fx.BLOCKLIST, "html", url="https://acme.com/downloads/blocklist.txt")
    assert len(fs) == 1 and fs[0]["rule"] == "public_ip_list" and fs[0]["extra"]["count"] > 50


@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"h":"<a href=\\"mailto:info@acme.com.au\\u0022\\u003einfo@acme.com.au\\u003c/a\\u003e"} mailto:x%40acme.com', {"info@acme.com.au", "x@acme.com"}),
        ("write to %20enquiries@oaic.gov.au today", {"enquiries@oaic.gov.au"}),
        ("service@koganlifeinsurance.com.auyou can call", {"service@koganlifeinsurance.com.au"}),
        ("hi sales@acme.comPlease reply", {"sales@acme.com"}),
        ("team@acme.insurance and ops@acme.cafe", {"team@acme.insurance", "ops@acme.cafe"}),
    ],
)
def test_email_cleanup(text, expected):
    assert values(scan(text, "html")) == expected


# ================================================================ v4.1: run-level analysis
def test_one_edit_distance():
    from reconspider.domains import _one_edit

    assert _one_edit("realifecover", "reallifecover")
    assert _one_edit("acme-crop", "acme-corp")
    assert _one_edit("acmecorp", "acmecorq")
    assert not _one_edit("seniors", "nzseniors")
    assert not _one_edit("acme", "acme")


def test_lookalike_needs_established_counterpart():
    from reconspider.domains import lookalike_findings

    def res(emails):
        return [{"target": "https://t/", "findings": [{"rule": "email", "value": e, "url": "https://t/p", "locations": ["https://t/p"]} for e in emails], "discovered_hosts": [], "external_hosts": {}}]

    hits = lookalike_findings(res(["a@reallifecover.com.au", "b@reallifecover.com.au", "c@reallifecover.com.au", "s@realifecover.com.au"]))
    assert [(f["value"], f["extra"]["likely_intended"]) for f in hits] == [("realifecover.com.au", "reallifecover.com.au")]
    assert lookalike_findings(res(["a@realifecover.com.au", "b@reallifecover.com.au"])) == []


def test_target_list_merges_same_host():
    from types import SimpleNamespace

    from reconspider.cli import load_targets

    args = SimpleNamespace(targets=["https://a.com/x", "https://www.a.com/y", "a.com/x", "https://b.com/", "https://a.com:8443/"], list=None)
    got = load_targets(args)
    assert [(u, seeds) for u, _, seeds in got] == [("https://a.com/x", ["https://www.a.com/y"]), ("https://b.com/", []), ("https://a.com:8443/", [])]
    assert len(load_targets(args, merge=False)) == 4


# ================================================================ v4.1: discovery
def _spider(target="https://acme.com/", **over):
    from types import SimpleNamespace

    from reconspider.crawl import TargetSpider

    o = dict(include_subdomains=False, max_subdomains=15, entropy=False, signatures=True, ignore_patterns=[], suppress_values=[],
             max_assets=400, max_pages=300, max_depth=4, max_per_template=8, max_text_bytes=10**6, max_asset_bytes=10**6,
             max_map_bytes=10**6, probe=False, seed=True, probe_sourcemaps=False, include_vendor=False)
    o.update(over)
    return TargetSpider(target, SimpleNamespace(**o), sink=lambda s, f: None)


def test_webpack_chunk_map_reconstruction():
    sp = _spider()
    urls = [r.url for r in sp.discover_in_js(fx.RUNTIME_JS, "https://acme.com/static/js/runtime.4c3b2a19.js")]
    assert "https://acme.com/static/js/345.9f8e7d6c.chunk.js" in urls and "https://acme.com/static/js/346.aa00bb11.chunk.js" in urls
    named = 'a.p="/_next/";a.u=function(e){return"static/chunks/"+({12:"framework",34:"main"}[e]||e)+"."+{12:"1a2b3c4d5e",34:"6f7a8b9c0d"}[e]+".js"}'
    urls = [r.url for r in _spider().discover_in_js(named, "https://acme.com/_next/static/chunks/webpack-1.js")]
    assert "https://acme.com/_next/static/chunks/framework.1a2b3c4d5e.js" in urls


def test_host_inventory_and_subdomain_seeding():
    sp = _spider(include_subdomains=True, max_subdomains=1)
    js = 'fetch("https://api.acme.com/v1/x");var q="https://quote.uat.acme.com/";var cdn="https://cdn.vendor.net/a.js"'
    sp.discover_in_js(js, "https://acme.com/static/js/app.js")
    assert sp.discovered_hosts == {"api.acme.com", "quote.uat.acme.com"}
    assert sp.external_refs == {"cdn.vendor.net": {"js_ref"}}
    seeded = [r.url for r in sp.drain_subdomain_seeds()]
    assert len(seeded) == 1  # capped by max_subdomains


def test_html_hidden_links_regexes():
    from reconspider.crawl import DATA_LINK_RE, JS_NAV_RE

    html = '<div data-target-url="/offers"></div><button onclick="location.href=\'/quote\'">x</button><a data-href="/b">'
    assert [m.group(1) for m in DATA_LINK_RE.finditer(html)] == ["/offers", "/b"]
    assert [m.group(1) for m in JS_NAV_RE.finditer(html)] == ["/quote"]


def test_template_collapse_for_product_slugs_and_wide_folders():
    assert template_of("https://a.com/product/oak-chair-123") == template_of("https://a.com/product/red-lamp-77")
    sp = _spider()
    tpls = {sp.adaptive_template(template_of(f"https://acme.com/category/name{i}x")) for i in range(40)}
    assert "acme.com/category/{var}?" in tpls and len(tpls) == 26
