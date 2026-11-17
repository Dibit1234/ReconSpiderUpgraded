"""Detection engine. Pure Python, no Scrapy dependency, so it can be unit-tested
and reused on files (``python -m reconspider.detect FILE``).

Design goals
------------
* Precision first: a generic key/value hit needs BOTH a secret-like key name
  (tokenised, with a deny-list of label/UI/hash words) AND a value that looks
  like a real literal (not a label, placeholder, identifier, path or variable).
* Recall: JSON/JS/HTML-entity escaped text is decoded and rescanned, URL
  credentials of any scheme are caught, AWS key IDs are paired with nearby
  secret keys, weak-but-real passwords are kept (no complexity requirement).
* Speed: keyword prefilters skip rules whose vendor prefix is absent, the
  generic key/value regex only matches keys that contain secret-ish words, and
  per-key classification is cached.
"""

import functools
import html
import ipaddress
import math
import re
from collections import Counter

from .rules import RULES, SEVERITY_RANK

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def shannon(s):
    if not s:
        return 0.0
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def char_classes(s):
    return sum(
        [
            any(c.islower() for c in s),
            any(c.isupper() for c in s),
            any(c.isdigit() for c in s),
            any(not c.isalnum() for c in s),
        ]
    )


_SEQ = ("0123456789", "1234567890", "abcdefghij", "ABCDEFGHIJ", "qwertyuiop", "9876543210")
_DECOY_WORDS = re.compile(
    r"(?i)example|sample|dummy|fake|placeholder|redacted|insert|replace|your[_-]?|changeme|xxxxxx|\*{4,}|<[^>]+>"
)


def is_decoy(value):
    """Docs/test/dummy values that match a real token shape."""
    if _DECOY_WORDS.search(value):
        return True
    if any(seq in value for seq in _SEQ):
        return True
    if re.search(r"(.)\1{9,}", value) and not value.startswith("AAAAAAAAAAAAAAAAAAAAA"):
        return True
    core = re.sub(r"^[A-Za-z]{2,8}[_-]", "", value)
    if len(core) >= 16 and len(set(core)) / len(core) < 0.2:
        return True
    return False


def _js_unescape(text):
    text = text.replace("\\/", "/")
    text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    return text


def decoded_variant(text):
    """Return a decoded copy of ``text`` if it contains escapes, else None."""
    out = text
    if "\\/" in out or "\\u00" in out or "\\x" in out:
        out = _js_unescape(out)
    if "&quot;" in out or "&#" in out or "&amp;" in out or "&apos;" in out:
        out = html.unescape(out)
    return out if out != text else None


def snippet(text, start, end, radius=60):
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    s = re.sub(r"\s+", " ", text[left:right]).strip()
    return s[:220]


# --------------------------------------------------------------------------- #
# Key-name classification for generic assignments
# --------------------------------------------------------------------------- #

PASSWORD_HEADS = {"password", "passwd", "pwd", "passphrase", "passcode", "pass", "pw"}
SECRET_HEADS = {"secret", "token", "apikey", "credential", "credentials", "key", "pat"}
USERNAME_HEADS = {"username", "user", "login", "userid", "uname"}

PASS_QUALIFIERS = {
    "db", "admin", "user", "root", "smtp", "mail", "ftp", "sql", "mysql", "ldap", "redis", "proxy",
    "basic", "auth", "login", "app", "api", "ssh", "sftp", "email", "rabbit", "rabbitmq", "amqp",
    "mongo", "mongodb", "pg", "postgres", "keystore", "store", "database", "service", "account",
}
KEY_QUALIFIERS = {
    "api", "secret", "private", "access", "auth", "signing", "sign", "encryption", "encrypt",
    "master", "license", "app", "client", "service", "admin", "write", "server", "hmac", "jwt",
    "consumer", "webhook", "account", "session", "cipher", "aes", "crypto", "shared", "root",
    "deploy", "ssh", "rsa", "gpg", "subscription", "management", "mgmt", "integration", "partner",
    "merchant", "developer", "dev", "x", "ocp", "apim", "storage", "sas",
}
COMPOUND_HEADS = ["password", "passwd", "secret", "token", "apikey", "key", "pass", "pwd", "username", "login"]

DENY_WORDS = {
    "label", "labels", "placeholder", "text", "title", "msg", "message", "messages", "error",
    "errors", "err", "hint", "help", "desc", "description", "tooltip", "tip", "url", "uri", "path",
    "link", "route", "routes", "endpoint", "field", "fields", "input", "regex", "regexp",
    "pattern", "policy", "length", "len", "min", "max", "strength", "reset", "forgot", "forgotten",
    "confirm", "confirmation", "validation", "validator", "valid", "invalid", "required",
    "require", "requirements", "requirement", "type", "types", "mode", "visible", "visibility",
    "show", "hide", "toggle", "icon", "class", "classname", "selector", "id", "ids", "header",
    "headers", "param", "params", "prefix", "suffix", "format", "expiry", "expires", "expiration",
    "expire", "expired", "ttl", "timeout", "lifetime", "age", "storage", "cookie", "event",
    "events", "action", "actions", "status", "state", "count", "enabled", "enable", "disabled",
    "rule", "rules", "changed", "change", "updated", "created", "date", "time", "file", "filename",
    "location", "version", "csrf", "xsrf", "nonce", "captcha", "recaptcha", "hcaptcha",
    "turnstile", "site", "sitekey", "public", "publishable", "pub", "integrity", "hash", "hashed",
    "checksum", "digest", "etag", "fingerprint", "sha", "sha1", "sha256", "md5", "size", "char",
    "chars", "characters", "score", "meter", "level", "complexity", "generator", "manager",
    "provider", "kind", "method", "scope", "scopes", "audience", "issuer", "algorithm", "alg",
    "column", "attr", "attribute", "prop", "property", "i18n", "translation", "translations",
    "lang", "locale", "button", "btn", "modal", "dialog", "form", "page", "screen", "view",
    "component", "container", "wrapper", "section", "step", "tab", "menu", "nav", "keys", "index",
    "idx", "cache", "sort", "primary", "foreign", "unique", "query", "search", "filter", "row",
    "item", "list", "entity", "callback", "handler", "listener", "fn", "func", "function",
    "lookup", "meta", "position", "pos", "mask", "masked", "hidden", "strength", "pending",
    "loading", "loaded", "request", "response", "res", "req", "result", "endpoint", "host",
    "domain", "port", "dir", "folder", "namespace", "ns", "prompt", "question", "answer",
    "dictionary", "dict", "map", "mapping", "spec", "schema", "example", "sample", "demo",
    "default", "defaults", "test", "mock", "fake", "dummy", "stub", "template", "tpl", "store",
    "storekey", "sessionstorage", "localstorage", "shortcut", "hotkey", "keyboard", "press",
    "down", "up", "code", "codes", "map", "tracking", "analytics", "gtm", "pixel", "measurement",
    "sender", "bucket", "project", "region", "zone", "auth0domain", "redirect", "callbackurl",
    "verification", "verify", "verified", "recovery", "otp", "mfa", "twofa", "2fa", "hint",
}
BOOL_PREFIX = {"is", "has", "should", "can", "use", "allow", "with", "no", "needs", "did", "will", "was", "toggle", "set", "get", "on", "handle", "update", "submit", "check", "validate", "render", "fetch", "load", "save", "clear", "remove", "delete", "create", "generate"}
TRAILING_NOISE = {"value", "val", "str", "string", "raw", "b64", "base64", "enc", "encoded", "plain", "plaintext", "prod", "production", "live", "dev", "staging", "stg", "v1", "v2", "1", "2", "3", "env"}


@functools.lru_cache(maxsize=20000)
def tokenize_key(key):
    k = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    k = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", k)
    words = [w for w in re.split(r"[^A-Za-z0-9]+", k.lower()) if w]
    out = []
    for w in words:
        split = False
        for head in COMPOUND_HEADS:
            if w.endswith(head) and w != head:
                prefix = w[: -len(head)]
                if prefix in PASS_QUALIFIERS or prefix in KEY_QUALIFIERS or prefix in {"user", "db", "api"}:
                    out.extend([prefix, head if head != "apikey" else "apikey"])
                    split = True
                    break
        if not split:
            out.append(w)
    # "apikey" -> api key
    final = []
    for w in out:
        if w == "apikey":
            final.extend(["api", "key"])
        else:
            final.append(w)
    return tuple(final)


@functools.lru_cache(maxsize=20000)
def classify_key(key):
    """Return (kind, strength) for a key name, or (None, 0).

    kind: password | secret | username. strength 2 = strong qualifier
    (db_password, client_secret, api_key), 1 = bare head (password, token).
    """
    words = list(tokenize_key(key))
    if not words or len(words) > 7:
        return None, 0
    if words[0] in BOOL_PREFIX and len(words) > 1:
        return None, 0
    while len(words) > 1 and words[-1] in TRAILING_NOISE:
        words.pop()
    head = words[-1]
    quals = set(words[:-1])

    if any(w in DENY_WORDS for w in words):
        # "user name" / "account name" are the only allowed uses of "name"
        return None, 0
    if head in {"name"} and quals & {"user", "account", "login", "db", "admin"}:
        return "username", 2

    if head in PASSWORD_HEADS:
        if head in {"pass", "pw"} and not (quals & PASS_QUALIFIERS) and len(words) > 1:
            return None, 0
        return "password", 2 if (quals & PASS_QUALIFIERS) else 1
    if head == "key":
        if quals & KEY_QUALIFIERS:
            return "secret", 2
        return None, 0
    if head in {"secret", "credential", "credentials"}:
        return "secret", 2 if quals else 1
    if head == "token":
        if quals & {"access", "auth", "api", "bearer", "refresh", "personal", "service", "bot", "admin", "deploy", "github", "slack", "session", "oauth", "private", "secret", "client", "app", "integration", "management"}:
            return "secret", 2
        return "secret", 1
    if head == "pat" and quals:
        return "secret", 2
    if head in USERNAME_HEADS:
        return "username", 2 if quals & PASS_QUALIFIERS or head == "username" else 1
    return None, 0


# --------------------------------------------------------------------------- #
# Value plausibility
# --------------------------------------------------------------------------- #

_PLACEHOLDER_FULL = re.compile(
    r"(?ix)^(?:"
    r"x+|\*+|\.+|-+|_+|\#+|•+|0+|1+|null|nil|none|undefined|true|false|n/?a|tbd|todo|"
    r"password\d{0,3}|passw0rd|pass|pwd|passwd|secret|token|apikey|api[_ -]?key|key|value|string|"
    r"test\w{0,8}|demo|example\w*|sample\w*|dummy\w*|fake\w*|changeme|change[_ -]?me|"
    r"default|admin|root|user|username|guest|qwerty|letmein|foo|bar|foobar|hello|world|"
    r"abc\d*|abcdef\w*|12345\d*|123|1234|asdf\w*|secret\w{0,3}|mypassword|yourpassword|"
    r"bearer|basic|redacted|hidden|private|empty|blank|required|optional|unknown|anonymous|"
    r"object|string|number|boolean|function|symbol|bigint|text|on|off|yes|no|enabled|disabled"
    r")$"
)
_PLACEHOLDER_PART = re.compile(
    r"(?i)\$\{|\{\{|\}\}|%s|%\(|%[0-9]*[sd]\b|<%|<[a-z_ -]+>|\[[a-z_ -]+\]|process\.env|import\.meta|"
    r"os\.environ|getenv|your[_ -]|_here\b|replace[_ ]?(?:me|with|this)|insert[_ ]|enter[_ ]|"
    r"xxxx|\*\*\*\*|example|placeholder|dummy|sample|lorem|ipsum|changeme|not[_ -]?set|"
    r"\b(?:fixme|todo)\b"
)
_IDENT_CAMEL = re.compile(r"^[a-z]+(?:[A-Z][a-z0-9]+)+$")
_IDENT_SNAKE = re.compile(r"^[a-z][a-z0-9]*(?:[_.-][a-z0-9]+)+$")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_FILEISH = re.compile(r"(?i)\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|ico|json|html?|php|aspx?|map|woff2?|ttf)(?:$|[?#])")
_CSS_UNIT = re.compile(r"^-?\d+(?:\.\d+)?(?:px|em|rem|%|vh|vw|s|ms)$")


def value_rejection(value, kind, key=""):
    """Return a reason string if the value is NOT a plausible secret, else None."""
    v = value.strip()
    if not v:
        return "empty"
    if v.startswith("eyJ") and v.count(".") < 2:
        # JWT header alone ({"alg":"HS256","typ":"JWT"}) or a truncated token:
        # no payload/signature, so nothing usable. Full JWTs are handled by
        # the jwt rule.
        return "jwt_fragment"
    low = v.lower()
    if _PLACEHOLDER_FULL.match(v) and not (kind == "password" and low in {"admin", "root", "guest", "letmein", "qwerty"}):
        # Default creds like admin/root are real findings for a password key.
        return "placeholder"
    if _PLACEHOLDER_PART.search(v):
        return "placeholder_part"
    if key and (low == key.lower() or low.replace(" ", "") == key.lower().replace("_", "").replace("-", "")):
        return "equals_key"
    if "://" in v:
        return "url"
    if _FILEISH.search(v) or v.startswith(("/", "./", "../", "#", "data:", "javascript:", "mailto:", "tel:")):
        return "path_or_uri"
    if _CSS_UNIT.match(v) or re.fullmatch(r"#[0-9a-fA-F]{3,8}", v):
        return "css_value"
    if _ENV_NAME.match(v):
        return "env_var_name"
    if re.search(r"[\(\)\{\};]|=>|&&|\|\|", v):
        return "code_expression"
    if " " in v:
        # Natural-language label/message ("Enter your password", "Password")
        if kind != "password" or v.count(" ") >= 2 or re.search(r"[.:!?]$", v):
            return "natural_language"
        if re.match(r"^[A-Z][a-z]+(?: [A-Za-z][a-z]+)+$", v):
            return "natural_language"
    if re.fullmatch(r"[A-Z][a-z]{2,}", v) or re.fullmatch(r"[A-Z][a-z]+(?: [A-Z]?[a-z]+)*", v):
        # Capitalised dictionary-ish word: "Password", "Contraseña", "Token"
        return "label_word"
    if re.search(r"(?i)pass(?:word)?|secret|token|api.?key|usuario|contrase|mot de passe|passwort", v) and len(v) < 24 and not re.search(r"\d", v):
        return "contains_field_name"

    if kind == "password":
        if len(v) < 4 or len(v) > 128:
            return "length"
        if _IDENT_CAMEL.match(v) and len(v) > 12:
            return "identifier"
        return None

    if kind == "username":
        if not re.fullmatch(r"[A-Za-z0-9._@+-]{3,64}", v):
            return "username_shape"
        if low in {"guest", "anonymous", "username", "user", "name", "email", "login"}:
            return "placeholder"
        return None

    # secrets / tokens
    if len(v) < 12:
        return "too_short"
    if " " in v:
        return "has_space"
    if _IDENT_CAMEL.match(v) or _IDENT_SNAKE.match(v):
        return "identifier"
    if re.fullmatch(r"[a-z]+", v) or re.fullmatch(r"[A-Z]+", v):
        return "single_case_alpha"
    if re.fullmatch(r"[A-Za-z_$][A-Za-z_$]*", v) and len(v) < 32:
        # Identifier with no digits (__reactResources$, someInternalKeyName).
        # Random 12-31 char secrets almost always contain a digit.
        return "identifier_no_digits"
    if re.fullmatch(r"[a-z0-9/_.:-]+", v) and all(re.fullmatch(r"[a-z]+\d{0,2}", s) for s in re.split(r"[/_.:-]+", v) if s):
        return "slug_identifier"  # auth/missing-app-credential, app.auth.token
    if v.count(".") >= 2 and not v.startswith("eyJ") and re.fullmatch(r"[\w.-]+", v) and not re.search(r"\d", v):
        return "dotted_identifier"
    ent = shannon(v)
    if _UUID.match(v) or _HEX.match(v):
        # Hex/UUID secrets exist (Datadog, Heroku, Algolia) - allowed only for
        # strongly named keys, and only if not too short.
        if len(v) < 20:
            return "short_hex"
        return None
    if ent < (3.0 if len(v) < 24 else 3.4):
        return f"low_entropy({ent:.2f})"
    if char_classes(v) < 2:
        return "low_charset"
    if is_decoy(v):
        return "decoy"
    return None


# --------------------------------------------------------------------------- #
# Regexes for structural / generic detection
# --------------------------------------------------------------------------- #

# Generic key/value detection is anchor-first: find a secret-ish word, expand
# to the surrounding identifier, then parse "<op> <quote>value<quote>" after it.
# A single regex with a variable-length key prefix backtracks at every
# position and was ~20x slower on multi-MB bundles.
KEY_ANCHOR_RE = re.compile(r"pass|pwd|secret|token|key|auth|cred|user|login|bearer")  # run on lowered text
KEY_ANCHOR_RE_I = re.compile(r"(?i)pass|pwd|secret|token|key|auth|cred|user|login|bearer")
ALL_KEYWORDS = sorted({k for r in RULES for k in r.keywords})
KEY_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$-")
POST_KEY_RE = re.compile(r"[\"']?[ \t]{0,3}(===?|:=|=>|=|:)[ \t]{0,3}([\"'`])")
DOC_KV_RE = re.compile(
    r"(?im)^[ \t\-*•]*(?P<key>[A-Za-z][A-Za-z0-9_.-]*(?:[ \t][A-Za-z0-9_.-]+){0,3})[ \t]*(?::|=|\|)[ \t]*[\"'“]?(?P<val>[^\s\"'”]{3,128})[\"'”]?[ \t]*$"
)
DOC_INLINE_RE = re.compile(
    r"(?i)\b(?P<key>(?:(?:admin|root|db|database|wifi|wi-fi|vpn|portal|default|temp(?:orary)?|service|account|login)\s+)?(?:password|passwd|passcode|pwd|pin|username|user\s?name|login|api\s?key|secret))"
    r"\s+(?:is|was|=|:)\s+[\"'“]?(?P<val>[^\s\"'”,;]{4,128})"
)
ENV_LINE_RE = re.compile(
    r"(?m)^[ \t]*(?:export[ \t]+)?(?P<key>[A-Za-z_][A-Za-z0-9_.-]{1,64})[ \t]*[=:][ \t]*(?P<q>[\"']?)(?P<val>[^\r\n#\"']{1,512}?)(?P=q)[ \t]*(?:#.*)?$"
)
INPUT_TAG_RE = re.compile(r"(?is)<input\b[^>]*>")
URL_SCHEME_BACK = re.compile(r"(?i)[a-z][a-z0-9+.-]{1,24}$")
URL_USERINFO_FWD = re.compile(
    r"(?P<user>[^\s:@/\"'<>{}\\|^`]{1,64}):(?P<pw>[^\s@/\"'<>{}\\|^`]{1,128})@(?P<host>[A-Za-z0-9.-]{2,253}(?::\d{1,5})?)"
)
BTOA_RE = re.compile(r"btoa\(\s*[\"'`](?P<user>[^\"'`:]{1,64}):(?P<pw>[^\"'`]{1,128})[\"'`]\s*\)")
QUOTED_B64_40 = re.compile(r"[\"'`](?P<v>[A-Za-z0-9/+]{40})[\"'`]")
HIGH_ENTROPY_LITERAL = re.compile(r"[\"'`](?P<v>[A-Za-z0-9_+/=.\-]{20,200})[\"'`]")

URI_SCHEMES_AS_USER = {"mailto", "tel", "sms", "callto", "http", "https", "ftp", "javascript", "data", "file", "skype", "whatsapp", "viber", "maps", "geo"}

# Mock / fixture code shipped to the browser (MSW, Mirage, axios-mock-adapter).
# Values inside are test data, but the file itself maps the real API.
MOCK_FILE_RE = re.compile(
    r"\[MSW\]|mockServiceWorker|setupWorker\s*\(|msw/browser|from\s*[\"']msw[\"']|miragejs|"
    r"new\s+MockAdapter\s*\(|createServer\(\{\s*routes|__MOCKS__|mock-service-worker"
)
PLACEHOLDER_CTX_RE = re.compile(
    r"(?i)(?<![\w.])(?:123456(?:7|78|789|7890)?|87654321|1234567890|0{8,}|1{8,}|9{8,}|11223344)(?![\w.])|"
    r"\b(?:mock(?:ed|s)?|dummy|fake|fixture|stub(?:bed)?|lorem|placeholder)\b"
)

DB_SCHEMES = {
    "postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongodb+srv", "redis", "rediss",
    "amqp", "amqps", "mssql", "sqlserver", "oracle", "ftp", "ftps", "sftp", "smtp", "smtps",
    "ldap", "ldaps", "jdbc", "couchdb", "cassandra", "neo4j", "elasticsearch", "memcached", "nats",
}

# --------------------------------------------------------------------------- #
# IP addresses
# --------------------------------------------------------------------------- #

# Simple patterns with a digit/hex first-char so the regex engine can skip
# quickly; boundaries and octet ranges are checked in Python.
IPV4_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
IPV6_FULL_RE = re.compile(r"[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}")
_IP_LEFT_BAD = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-")
_HEXCOLON = frozenset("0123456789abcdefABCDEF:")
_VERSION_CTX = re.compile(r"(?i)(?:\b(?:v|version|ver|build|rel|release|rev|semver|sdk|lib)|@)[\s\"'`:=_/-]{0,4}$")
_SVG_OPEN = re.compile(r"""\b(?:d|points|viewBox|transform|path)\s*[=:]\s*["'][^"']*$""")
NOISE_IPS = {
    "0.0.0.0", "255.255.255.255", "127.0.0.1", "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "208.67.222.222", "208.67.220.220", "1.2.3.4", "4.3.2.1", "10.0.0.0",
    "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255",
    "169.254.0.0", "169.254.255.255", "100.64.0.0", "100.127.255.255", "224.0.0.0",
    "239.255.255.255", "240.0.0.0", "127.0.0.0", "198.18.0.0", "192.0.0.0", "192.88.99.0",
}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
INTERNAL_NETS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")
]

# --------------------------------------------------------------------------- #
# Emails
# --------------------------------------------------------------------------- #

EMAIL_LOCAL_BACK = re.compile(r"(?i)[a-z0-9._%+-]{1,64}$")
EMAIL_DOMAIN_FWD = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])")
OBFUSCATED_EMAIL_RE = re.compile(
    r"(?i)(?<![\w.])([a-z0-9][a-z0-9._+-]{0,63})\s*(?:\[\s*at\s*\]|\(\s*at\s*\)|\{\s*at\s*\}|\s+at\s+)\s*"
    r"([a-z0-9-]{1,63}(?:\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}|\s+dot\s+|\.)\s*[a-z0-9-]{1,63}){1,4})\b"
)
CFEMAIL_RE = re.compile(r"data-cfemail=[\"']([0-9a-fA-F]{6,})[\"']")
FILE_TLDS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "avif", "js", "mjs", "css", "map",
    "json", "html", "htm", "php", "asp", "aspx", "jsp", "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "webm", "mp3", "wav", "pdf", "zip", "gz", "xml", "txt", "md", "vue", "jsx", "tsx", "ts",
    "scss", "less", "min", "local", "internal", "lan", "test", "invalid", "localhost", "example",
}
PLACEHOLDER_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net", "domain.com", "yourdomain.com", "yourcompany.com",
    "company.com", "email.com", "mail.com", "test.com", "website.com", "mysite.com", "site.com",
    "acme.com", "sentry.io", "sentry.wixpress.com", "sentry-next.wixpress.com", "wixpress.com",
    "ingest.sentry.io", "users.noreply.github.com", "noreply.github.com", "2x.png", "3x.png",
}
PLACEHOLDER_EMAIL_LOCALS = {
    "you", "your", "yourname", "your.name", "your-email", "youremail", "your_email", "name",
    "first.last", "firstname.lastname", "john.doe", "jane.doe", "johndoe", "janedoe", "user",
    "username", "email", "someone", "somebody", "test", "example", "foo", "bar",
}


EMAIL_FULL_RE = re.compile(r"[a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}")
KNOWN_TLDS = {
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "io", "co", "ai", "app", "dev", "xyz",
    "online", "site", "tech", "store", "shop", "cloud", "company", "agency", "email", "group", "insurance",
    "bank", "health", "finance", "financial", "solutions", "services", "digital", "media", "global", "world",
    "life", "live", "news", "blog", "pro", "name", "mobi", "asia", "travel", "jobs", "museum", "aero", "coop",
    "community", "network", "systems", "software", "consulting", "partners", "capital", "legal", "law",
    "care", "clinic", "dental", "realty", "properties", "homes", "energy", "studio", "design", "marketing",
    "academy", "school", "university", "education", "foundation", "charity", "church", "events", "today",
    "support", "center", "centre", "technology", "security", "works", "zone", "space", "website", "page",
    "plus", "one", "top", "vip", "club", "fun", "art", "photo", "games", "money", "credit", "loans", "fund",
    "tax", "accountants", "auto", "cars", "pet", "pets", "vet", "london", "sydney", "melbourne", "nyc", "berlin",
}
_TLD_GLUE_PREFIXES = ("com", "net", "org", "edu", "gov", "info", "biz")


def repair_email_domain(domain):
    """Return a cleaned domain, or None if the TLD is clearly bogus.

    Text with a missing space glues the next word onto the TLD:
    "service@acme.com.auyou can" -> "acme.com.au", "a@b.comPlease" -> "b.com".
    """
    labels = domain.split(".")
    tld = labels[-1]
    if len(tld) == 2 or tld in KNOWN_TLDS:
        return domain
    second = labels[-2] if len(labels) >= 3 else ""
    if second in {"com", "net", "org", "co", "gov", "edu", "ac", "asn", "id", "ltd", "or", "ne", "go"} and len(tld) > 2:
        return ".".join(labels[:-1] + [tld[:2]])
    for p in _TLD_GLUE_PREFIXES:
        if tld.startswith(p) and len(tld) > len(p):
            return ".".join(labels[:-1] + [p])
    if len(tld) <= 6:
        return domain  # long tail of real gTLDs (.cafe, .codes ...)
    return None


def _registrable(host):
    host = (host or "").lower().strip(".").strip("[]")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"com", "net", "org", "gov", "edu", "co", "ac", "asn", "id", "ltd", "plc", "or", "ne", "go"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


registrable_domain = _registrable

VENDOR_PATH_RE = re.compile(
    r"(?i)(?:/node_modules/|/vendor/|/vendors?[~.-]|/bower_components/|webpack/runtime|/polyfills?[.-]|"
    r"jquery|bootstrap(?:\.bundle)?\.min|lodash|moment(?:\.min)?\.js|react-dom|angular(?:\.min)?\.js|"
    r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js|chunk-vendors|/framework-[0-9a-f]+\.js|/wp-includes/js/|"
    r"swiper|gsap|three(?:\.module)?(?:\.min)?\.js|chart(?:\.umd)?(?:\.min)?\.js|recaptcha|gtag|gtm\.js|"
    r"analytics\.js|fbevents\.js|hotjar|intercom|zendesk|hubspot|clarity\.js)"
)


def is_vendor(url):
    return bool(VENDOR_PATH_RE.search(url or ""))


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #

GENERIC_RULES = {"generic_password", "generic_secret", "bearer_header", "high_entropy_string", "env_secret"}


class Detector:
    def __init__(self, target_host="", entropy=False, signatures=True, ignore_patterns=None, suppress_values=None, emails=True, ips=True):
        self.target_host = (target_host or "").lower()
        self.target_site = registrable_domain(self.target_host) if self.target_host else ""
        self.entropy = entropy
        self.signatures = signatures
        self.ignore = [re.compile(p) for p in (ignore_patterns or [])]
        self.suppress_values = {v for v in (suppress_values or []) if v and len(v) >= 6}
        self.emails = emails
        self.ips = ips
        self.rejections = Counter()  # observability: why candidates were dropped

    # ------------------------------------------------------------------ API
    def scan(self, text, url="", source="html"):
        if not text:
            return []
        findings = []
        self._scan_once(text, url, source, findings)
        alt = decoded_variant(text)
        if alt:
            self._scan_once(alt, url, source, findings)
        out = self._finalize(findings)
        mock = source in {"js", "inline_js", "sourcemap", "json"} and MOCK_FILE_RE.search(text) is not None
        return self._apply_context(out, mock, url, source)

    def _apply_context(self, findings, mock, url, source):
        weak = {"generic_password", "generic_secret", "bearer_header", "high_entropy_string", "username", "internal_ip", "url_credentials", "basic_auth_header", "basic_auth_btoa"}
        for f in findings:
            if f.get("public") or f["severity"] == "info":
                continue
            if mock:
                if f["rule"] in weak:
                    f.update(severity="info", confidence="low")
                    f["reasons"].append("mock_handlers_file")
                    self.rejections["downgraded:mock_file"] += 1
                else:
                    # A real-looking vendor key inside mocks is still worth a look.
                    f["confidence"] = "medium"
                    f["reasons"].append("in_mock_file")
            elif f["rule"] in weak and PLACEHOLDER_CTX_RE.search(f.get("context", "")):
                f.update(severity="low", confidence="low")
                f["reasons"].append("placeholder_context")
                self.rejections["downgraded:placeholder_ctx"] += 1
        if mock:
            findings.append(
                self._mk(
                    "mock_api_handlers", "Mock API handlers shipped to the browser", "low", "high", url, url, source,
                    "", ["mock_framework_marker"], category="exposure",
                    note="Test-only code in a deployed bundle. Its handlers list real API routes and response shapes; check whether production ships it too.",
                )
            )
        return findings

    def scan_headers(self, headers, url=""):
        """headers: iterable of (name, value) str pairs."""
        findings = []
        for name, value in headers:
            lname = name.lower()
            if lname in {"set-cookie", "cookie", "content-security-policy", "content-security-policy-report-only", "report-to", "nel", "link", "strict-transport-security", "permissions-policy"}:
                continue
            line = f"{name}: {value}"
            if self.signatures:
                self._scan_rules(line, url, "header", findings)
            if self.ips:
                for f in self._scan_ips(line, url, "header"):
                    f["extra"] = {"header": name}
                    if f["severity"] == "info":
                        f["severity"] = "low"
                        f["title"] = "Public IP in response header (possible origin IP)"
                    findings.append(f)
            m = re.search(r"(?i)^(?:x-)?(?:api[-_]?key|auth[-_]?token|access[-_]?token|secret)$", name)
            if m and not value_rejection(value, "secret"):
                findings.append(self._mk("generic_secret", "Secret in response header", "high", "medium", value, url, "header", line, ["header_name"], category="secret"))
        return self._finalize(findings)

    # ------------------------------------------------------------- internals
    def _mk(self, rule, title, severity, confidence, value, url, source, context, reasons, category="secret", extra=None, public=False, note="", pos=None):
        f = {
            "rule": rule,
            "title": title,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "value": value,
            "url": url,
            "source": source,
            "context": context,
            "reasons": list(reasons or []),
        }
        if extra:
            f["extra"] = extra
        if public:
            f["public"] = True
        if note:
            f["note"] = note
        if pos is not None:
            f["_pos"] = pos
        return f

    def _scan_once(self, text, url, source, findings):
        vendor = is_vendor(url)
        lower = text.lower()
        if self.signatures:
            self._scan_rules(text, url, source, findings, lower=lower)
        self._scan_url_creds(text, url, source, findings)
        self._scan_generic(text, url, source, findings, vendor, lower=lower)
        if source in {"probe", "config", "sourcemap", "document"} or re.search(r"(?i)\.(?:env|ini|cfg|conf|properties|ya?ml|toml|txt)(?:$|\?)", url or ""):
            self._scan_env_lines(text, url, source, findings)
        if source == "document":
            self._scan_doc_lines(text, url, source, findings)
        if source in {"html", "probe"} and "<input" in lower and "password" in lower:
            self._scan_password_inputs(text, url, source, findings)
        if self.ips and not vendor:
            findings.extend(self._scan_ips(text, url, source))
        if self.emails and (not vendor or source == "html"):
            findings.extend(self._scan_emails(text, url, source))
        if self.entropy and source in {"js", "inline_js", "sourcemap", "json"} and not vendor:
            self._scan_entropy(text, url, source, findings)

    def _scan_rules(self, text, url, source, findings, lower=None):
        lower = lower if lower is not None else text.lower()
        present = {k for k in ALL_KEYWORDS if k in lower}
        if not present:
            return
        for rule in RULES:
            if not any(k in present for k in rule.keywords):
                continue
            for m in rule.pattern.finditer(text):
                value = m.group("v") if "v" in rule.pattern.groupindex else m.group(0)
                if rule.id not in {"private_key", "putty_private_key", "jwt", "basic_auth_header"} and is_decoy(value):
                    self.rejections["decoy:" + rule.id] += 1
                    continue
                sev, conf, title, public = rule.severity, rule.confidence, rule.title, rule.public
                reasons, extra = ["provider_signature"], None
                if rule.validator:
                    res = rule.validator(value, {"match": m, "text": text})
                    if res is None:
                        self.rejections["validator:" + rule.id] += 1
                        continue
                    sev = res.get("severity", sev)
                    conf = res.get("confidence", conf)
                    title = res.get("title", title)
                    public = res.get("public", public)
                    reasons += res.get("reasons", [])
                    extra = res.get("extra")
                if rule.id == "private_key":
                    value = m.group(0)[:120] + "..."
                findings.append(
                    self._mk(rule.id, title, sev, conf, value, url, source, snippet(text, m.start(), m.end()), reasons, category=rule.category, extra=extra, public=public, note=rule.note, pos=m.start())
                )
                if rule.id == "aws_access_key_id":
                    self._pair_aws_secret(text, m, url, source, findings)

    def _pair_aws_secret(self, text, m, url, source, findings):
        window_start = max(0, m.start() - 500)
        window = text[window_start : m.end() + 500]
        for sm in QUOTED_B64_40.finditer(window):
            v = sm.group("v")
            if char_classes(v) >= 3 and shannon(v) >= 4.0 and not is_decoy(v):
                findings.append(
                    self._mk("aws_secret_access_key", "AWS secret access key (paired with key ID)", "critical", "medium", v, url, source, snippet(window, sm.start(), sm.end()), ["paired_with_access_key_id"], pos=window_start + sm.start())
                )

    def _iter_url_creds(self, text):
        i = text.find("://")
        while i >= 0:
            m = URL_USERINFO_FWD.match(text, i + 3)
            if m:
                sm = URL_SCHEME_BACK.search(text, max(0, i - 25), i)
                if sm:
                    yield sm.start(), m.end(), sm.group(0).lower(), m.group("user"), m.group("pw"), m.group("host")
            i = text.find("://", i + 3)

    def _scan_url_creds(self, text, url, source, findings):
        if "://" not in text or "@" not in text:
            return
        for start, end, scheme, user, pw, host in self._iter_url_creds(text):
            whole = text[start:end]
            if user.lower() in URI_SCHEMES_AS_USER:
                # href="http://mailto:x@y" / "https://tel:..." - broken link, not creds
                self.rejections["url_creds_scheme_as_user"] += 1
                continue
            if value_rejection(pw, "password") or (user.lower(), pw.lower()) in {("user", "pass"), ("user", "password"), ("username", "password"), ("admin", "admin")}:
                self.rejections["url_creds_placeholder"] += 1
                continue
            if host.lower() in {"host", "hostname", "server", "localhost", "example.com", "domain.com"} or "example" in host.lower():
                self.rejections["url_creds_placeholder_host"] += 1
                continue
            if scheme in {"http", "https"} and pw.isdigit() and len(pw) <= 5:
                continue  # user:8080@ style artefacts
            sev = "critical" if scheme.split(":")[0] in DB_SCHEMES or scheme.startswith("jdbc") else "high"
            findings.append(
                self._mk("url_credentials", f"Credentials in {scheme}:// URL", sev, "high", whole, url, source, snippet(text, start, end), ["url_userinfo"], category="credential", extra={"username": user, "password": pw, "host": host}, pos=start)
            )
        for m in BTOA_RE.finditer(text):
            if value_rejection(m.group("pw"), "password"):
                continue
            findings.append(
                self._mk("basic_auth_btoa", "Hardcoded Basic credentials (btoa)", "high", "high", f"{m.group('user')}:{m.group('pw')}", url, source, snippet(text, m.start(), m.end()), ["btoa_literal"], category="credential", pos=m.start())
            )

    def _emit_kv(self, key, val, op, text, start, end, url, source, findings, vendor, strong_source=False):
        kind, strength = classify_key(key)
        if kind is None:
            return
        val = val.strip()
        reason = value_rejection(val, kind, key)
        if reason:
            self.rejections[f"{kind}:{reason}"] += 1
            return
        if val in self.suppress_values:
            return
        ctx = snippet(text, start, end)
        reasons = [f"key={key}", f"op={op}"]
        if op in {"==", "==="}:
            reasons.append("client_side_comparison")
        if kind == "username":
            findings.append(self._mk("username", "Username in config", "low", "low", val, url, source, ctx, reasons, category="username", pos=start))
            return
        if kind == "password":
            conf = "high" if (strength == 2 or strong_source) and len(val) >= 6 else "medium"
            if vendor:
                conf = "low"
            findings.append(self._mk("generic_password", "Hardcoded password", "high", conf, val, url, source, ctx, reasons, category="credential", pos=start))
            return
        ent = shannon(val)
        reasons.append(f"entropy={ent:.2f}")
        conf = "high" if strength == 2 and ent >= 3.5 and len(val) >= 20 else "medium"
        if strength == 1 and (_HEX.match(val) or _UUID.match(val)):
            conf = "low"
        if vendor:
            conf = "low"
        sev = "high" if strength == 2 else "medium"
        findings.append(self._mk("generic_secret", "Hardcoded secret / API key", sev, conf, val, url, source, ctx, reasons, category="secret", pos=start))

    def _scan_generic(self, text, url, source, findings, vendor, lower=None):
        n = len(text)
        last_end = -1
        kc = KEY_CHARS
        # Case-sensitive alternation over lowered text is several times faster
        # than (?i); only valid when lower() preserved offsets.
        anchors = KEY_ANCHOR_RE.finditer(lower) if lower is not None and len(lower) == n else KEY_ANCHOR_RE_I.finditer(text)
        for m in anchors:
            s = m.start()
            if s < last_end:
                continue  # same identifier as the previous anchor (passwordToken)
            j = s
            while j > 0 and s - j < 40 and text[j - 1] in kc:
                j -= 1
            k = m.end()
            lim = k + 40
            while k < n and k < lim and text[k] in kc:
                k += 1
            last_end = k
            key = text[j:k]
            if not key or not (key[0].isalpha() or key[0] in "_$"):
                continue
            if classify_key(key)[0] is None:
                continue
            pm = POST_KEY_RE.match(text, k)
            if not pm:
                continue
            op, q = pm.group(1), pm.group(2)
            if op.startswith("==") and text[max(0, j - 8) : j].rstrip("( ").endswith("typeof"):
                continue  # typeof x.password === "string"
            vs = pm.end()
            ve = text.find(q, vs, vs + 513)
            if ve <= vs:
                continue
            val = text[vs:ve]
            if "\n" in val or "\r" in val:
                continue
            self._emit_kv(key, val, op, text, j, ve + 1, url, source, findings, vendor)

    def _scan_env_lines(self, text, url, source, findings):
        for m in ENV_LINE_RE.finditer(text):
            self._emit_kv(m.group("key"), m.group("val"), "=", text, m.start(), m.end(), url, source, findings, False, strong_source=True)

    def _scan_doc_lines(self, text, url, source, findings):
        """Prose and tables: "Admin password: Winter2026!", "the PIN is 4417",
        "Username | svc_backup" (xlsx/csv rows arrive as "Header: value")."""
        for m in DOC_KV_RE.finditer(text):
            key = re.sub(r"\s+", "_", m.group("key").strip())
            self._emit_kv(key, m.group("val"), ":", text, m.start(), m.end(), url, source, findings, False, strong_source=True)
        for m in DOC_INLINE_RE.finditer(text):
            key = re.sub(r"\s+", "_", m.group("key").strip())
            self._emit_kv(key, m.group("val").rstrip(".)"), "is", text, m.start(), m.end(), url, source, findings, False)

    def _scan_password_inputs(self, text, url, source, findings):
        for tag in INPUT_TAG_RE.findall(text):
            if not re.search(r"(?i)type\s*=\s*[\"']?password", tag):
                continue
            m = re.search(r"(?i)\bvalue\s*=\s*[\"']([^\"']{1,128})[\"']", tag)
            if m and not value_rejection(m.group(1), "password"):
                findings.append(self._mk("prefilled_password", "Pre-filled password input", "high", "high", m.group(1), url, source, tag[:200], ["input_type_password_value"], category="credential"))

    def _scan_entropy(self, text, url, source, findings):
        for m in HIGH_ENTROPY_LITERAL.finditer(text):
            v = m.group("v")
            if len(v) < 24 or _HEX.match(v) or _UUID.match(v) or v.startswith(("sha256-", "sha384-", "sha512-")):
                continue
            if value_rejection(v, "secret") or char_classes(v) < 3 or shannon(v) < 4.3:
                continue
            findings.append(self._mk("high_entropy_string", "High-entropy string literal", "low", "low", v, url, source, snippet(text, m.start(), m.end()), [f"entropy={shannon(v):.2f}"], pos=m.start()))

    # ------------------------------------------------------------ IPs
    def _scan_ips(self, text, url, source):
        out = []
        seen = set()
        n = len(text)
        for m in IPV4_RE.finditer(text):
            ip_s = m.group(0)
            s, e = m.start(), m.end()
            if ip_s in seen or (s > 0 and text[s - 1] in _IP_LEFT_BAD):
                continue
            if e < n and (text[e].isalnum() or text[e] in "_.-" or (text[e] == "/" and text[e + 1 : e + 2].isdigit())):
                continue
            if any(len(o) > 1 and o[0] == "0" for o in ip_s.split(".")) or any(int(o) > 255 for o in ip_s.split(".")):
                continue
            before = text[max(0, m.start() - 24) : m.start()]
            after = text[m.end() : m.end() + 6]
            if _VERSION_CTX.search(before) or re.match(r"^(?:-[A-Za-z]|\.[A-Za-z])", after):
                self.rejections["ip:version_ctx"] += 1
                continue
            if _SVG_OPEN.search(text[max(0, m.start() - 300) : m.start()]):
                self.rejections["ip:svg"] += 1
                continue
            if source in {"js", "sourcemap"}:
                ls = text.rfind("\n", max(0, m.start() - 300), m.start())
                prefix = text[(ls + 1) if ls >= 0 else max(0, m.start() - 300) : m.start()]
                if re.search(r"(?<![:\\])//|^\s*\*|/\*(?!.*\*/)", prefix):
                    # Library doc comments: "// e.g. 192.168.1.5". Minified
                    # bundles strip comments, so this rarely hides real leaks.
                    self.rejections["ip:js_comment"] += 1
                    continue
            f = self._classify_ip(ip_s, text, s, e, url, source)
            if f:
                seen.add(ip_s)
                out.append(f)
        for s, e in self._ipv6_candidates(text):
            cand = text[s:e]
            if cand in seen or not re.search(r"[0-9a-fA-F]{2,}", cand):
                continue
            groups = [g for g in cand.split(":") if g]
            if len(groups) < 2 or all(g.isdigit() and len(g) <= 2 for g in groups):
                continue  # ::1, times / ratios 12:30:45
            if not any(re.search(r"[a-fA-F]", g) for g in groups) and len(groups) < 4:
                continue
            f = self._classify_ip(cand, text, s, e, url, source)
            if f:
                seen.add(cand)
                out.append(f)
        return self._collapse_ip_lists(out, url, source)

    BULK_IP_THRESHOLD = 50

    def _collapse_ip_lists(self, found, url, source):
        """A document with dozens of IPs is an IP list (blocklist, allowlist,
        CDN ranges): report it once, not thousands of times."""
        out = []
        for rule, title, sev in (("public_ip", "Bulk public IP list", "info"), ("internal_ip", "Bulk internal IP list", "low")):
            group = [f for f in found if f["rule"] == rule]
            if len(group) <= self.BULK_IP_THRESHOLD:
                out.extend(group)
                continue
            self.rejections[f"ip:collapsed_{rule}"] += len(group)
            sample = [f["value"] for f in group[:25]]
            out.append(
                self._mk(
                    f"{rule}_list", f"{title} ({len(group)} addresses)", sev, "high", f"{url}#{rule}_list", url, source,
                    " ".join(sample[:8]), [f"count={len(group)}"], category="ip", extra={"count": len(group), "sample": sample},
                )
            )
        return out

    @staticmethod
    def _ipv6_candidates(text):
        """Anchor on '::' (compressed form) plus the full 8-group form."""
        n = len(text)
        i = text.find("::")
        while i >= 0:
            s = i
            while s > 0 and i - s < 39 and text[s - 1] in _HEXCOLON:
                s -= 1
            e = i + 2
            while e < n and e - i < 39 and text[e] in _HEXCOLON:
                e += 1
            left_ok = s == 0 or not (text[s - 1].isalnum() or text[s - 1] in "_.")
            right_ok = e == n or not (text[e].isalnum() or text[e] in "_.")
            if left_ok and right_ok and text.count(":", s, e) >= 2:
                yield s, e
            i = text.find("::", e)
        if text.count(":") > 7:
            for m in IPV6_FULL_RE.finditer(text):
                s, e = m.start(), m.end()
                if (s == 0 or not (text[s - 1].isalnum() or text[s - 1] in "_:.")) and (e == n or not (text[e].isalnum() or text[e] in "_:.")):
                    yield s, e

    def _classify_ip(self, ip_s, text, start, end, url, source):
        if ip_s in NOISE_IPS:
            self.rejections["ip:noise"] += 1
            return None
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            return None
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or any(ip in n for n in DOC_NETS):
            self.rejections["ip:non_routable"] += 1
            return None
        if ip.version == 4 and (ip_s.endswith(".255") or ip_s.startswith("255.")):
            return None
        ctx = snippet(text, start, end)
        if any(ip in n for n in INTERNAL_NETS):
            title = "Cloud metadata / link-local IP" if ip_s.startswith("169.254.") else "Internal IP address disclosed"
            return self._mk("internal_ip", title, "low", "high", str(ip), url, source, ctx, ["rfc1918_or_internal"], category="ip")
        if ip.is_global:
            if ip.version == 4 and int(ip_s.split(".", 1)[0]) <= 2:
                self.rejections["ip:oid_like"] += 1  # ASN.1 OIDs 1.3.6.1 / 2.5.29.14
                return None
            return self._mk("public_ip", "Public IP address", "info", "medium", str(ip), url, source, ctx, ["public_ip"], category="ip")
        return None

    # ------------------------------------------------------------ emails
    def _email_ok(self, email):
        email = email.strip(".").lower()
        if not EMAIL_FULL_RE.fullmatch(email):
            self.rejections["email:malformed"] += 1
            return None
        local, _, domain = email.partition("@")
        if not local or "." not in domain:
            return None
        domain = repair_email_domain(domain)
        if domain is None:
            self.rejections["email:bad_tld"] += 1
            return None
        email = f"{local}@{domain}"
        tld = domain.rsplit(".", 1)[-1]
        if tld in FILE_TLDS:
            self.rejections["email:file_tld"] += 1
            return None
        on_target = bool(self.target_site) and registrable_domain(domain) == self.target_site
        if not on_target and (domain in PLACEHOLDER_EMAIL_DOMAINS or any(domain.endswith("." + d) for d in ("example.com", "sentry.io", "wixpress.com"))):
            self.rejections["email:placeholder_domain"] += 1
            return None
        if re.fullmatch(r"[0-9a-f]{16,}", local):
            self.rejections["email:hex_local"] += 1
            return None
        if local in PLACEHOLDER_EMAIL_LOCALS and (domain.split(".")[0] in {"domain", "company", "email", "example", "yourdomain", "test", "mail"}):
            return None
        if re.search(r"@\d+x\.", "@" + domain):
            return None
        return email

    def _scan_emails(self, text, url, source):
        out = []
        seen = set()

        def add(raw, reason, start, end):
            e = self._email_ok(raw)
            if not e or e in seen:
                return
            seen.add(e)
            domain = e.partition("@")[2]
            on_target = bool(self.target_site) and registrable_domain(domain) == self.target_site
            if source in {"js", "sourcemap"} and not on_target:
                self.rejections["email:offsite_in_js"] += 1
                return
            out.append(self._mk("email", "Email address", "info", "high" if on_target else "medium", e, url, source, snippet(text, start, end), [reason] + (["target_domain"] if on_target else []), category="email", extra={"on_target_domain": on_target}))

        i = text.find("@")
        while i > 0:
            nxt, prv = text[i + 1 : i + 2], text[i - 1]
            if not (nxt.isalnum() and (prv.isalnum() or prv in "._%+-")):
                i = text.find("@", i + 1)
                continue
            dm = EMAIL_DOMAIN_FWD.match(text, i + 1)
            if dm:
                lm = EMAIL_LOCAL_BACK.search(text, max(0, i - 64), i)
                if lm:
                    # "%20enquiries@" (URL-encoded space) -> "enquiries@"
                    local = re.sub(r"^(?:.*%[0-9a-fA-F]{2})", "", lm.group(0)).lstrip("._%+-")
                    ls = i - len(local)
                    if local and (ls == 0 or text[ls - 1] not in "\\/"):
                        add(f"{local}@{dm.group(0)}", "email_pattern", ls, dm.end())
            i = text.find("@", i + 1)
        if "@" in text:
            if "%40" in text:
                from urllib.parse import unquote

                for m in re.finditer(r"mailto:([^\"'\s>?<&\\]+)", text):
                    for part in unquote(m.group(1)).split(","):
                        add(part.strip(), "mailto", m.start(), m.end())
        low = text.lower()
        if " at " in low or "[at]" in low or "(at)" in low or "{at}" in low:
            for m in OBFUSCATED_EMAIL_RE.finditer(text):
                sep = text[m.start(): m.end()].lower()
                # Plain "x at y.com" is everyday prose ("available at mysite.com").
                # Only accept bracketed separators or explicit "dot" wording.
                if not re.search(r"[\[\(\{]\s*at\s*[\]\)\}]", sep) and " dot " not in sep:
                    self.rejections["email:prose_at"] += 1
                    continue
                domain = re.sub(r"(?i)\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}|\s+dot\s+|\.)\s*", ".", m.group(2))
                add(f"{m.group(1)}@{domain}", "obfuscated_email", m.start(), m.end())
        if "data-cfemail" in text:
            for m in CFEMAIL_RE.finditer(text):
                blob = m.group(1)
                try:
                    key = int(blob[:2], 16)
                    dec = "".join(chr(int(blob[i : i + 2], 16) ^ key) for i in range(2, len(blob), 2))
                except ValueError:
                    continue
                add(dec, "cloudflare_cfemail", m.start(), m.end())
        return out

    # ------------------------------------------------------------ finalize
    def _finalize(self, findings):
        """Dedupe within one document and apply cross-finding rules."""
        # 1. Username findings survive only when paired with a credential nearby.
        cred_pos = [f.get("_pos") for f in findings if f["category"] in {"credential", "secret"} and f.get("_pos") is not None]
        kept = []
        for f in findings:
            if f["rule"] == "username":
                p = f.get("_pos")
                if p is None or not any(abs(p - c) <= 300 for c in cred_pos):
                    self.rejections["username:unpaired"] += 1
                    continue
                f["reasons"].append("paired_with_credential")
            kept.append(f)

        # 2. One finding per value: specific provider rules beat generic ones.
        by_value = {}
        for f in kept:
            v = f["value"]
            if any(p.search(v) or p.search(f.get("url", "")) for p in self.ignore):
                continue
            if v in self.suppress_values:
                continue
            cur = by_value.get(v)
            if cur is None or _better(f, cur):
                by_value[v] = f
        out = []
        for f in by_value.values():
            f.pop("_pos", None)
            out.append(f)
        return out


_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def _better(a, b):
    a_generic, b_generic = a["rule"] in GENERIC_RULES, b["rule"] in GENERIC_RULES
    if a_generic != b_generic:
        return not a_generic
    return (_CONF_RANK[a["confidence"]], SEVERITY_RANK[a["severity"]]) < (_CONF_RANK[b["confidence"]], SEVERITY_RANK[b["severity"]])


if __name__ == "__main__":  # quick file scanner
    import json
    import sys

    det = Detector()
    for path in sys.argv[1:]:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for f in det.scan(fh.read(), url=path, source="config" if path.endswith((".env", ".txt", ".yml", ".yaml")) else "js"):
                print(json.dumps(f))
