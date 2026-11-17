"""Provider-specific secret signatures.

Every rule is anchored on a vendor prefix or a fixed structure, so a match is
already strong evidence. Each rule carries:

* ``keywords``  - cheap lowercase substrings checked before the regex runs
                  (keyword prefilter, as used by gitleaks/trufflehog). A rule
                  whose keywords are absent from a document is skipped.
* ``severity``  - impact if the value is live.
* ``public``    - the credential is designed to ship to browsers (Firebase /
                  Maps browser keys, Stripe publishable keys, ...). These are
                  reported as ``info`` so they do not pollute the real findings.
* ``validator`` - optional offline structural check (checksums, JWT decoding,
                  key body length). It may drop the match or adjust it.

The value to report is the regex group named ``v`` if present, else the whole
match.
"""

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Rule:
    id: str
    title: str
    pattern: "re.Pattern"
    keywords: tuple
    severity: str = "high"
    confidence: str = "high"
    category: str = "secret"
    public: bool = False
    validator: Optional[Callable] = None
    note: str = ""
    tags: tuple = field(default_factory=tuple)


# --------------------------------------------------------------------------- #
# Validators. Each returns None to drop the match, or a dict of overrides
# (severity / confidence / reasons / extra / title / public).
# --------------------------------------------------------------------------- #

_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b62_decode(s):
    n = 0
    for ch in s:
        idx = _B62.find(ch)
        if idx < 0:
            return None
        n = n * 62 + idx
    return n


def crc32_base62_ok(token, prefix_len):
    """GitHub / npm style tokens: last 6 chars are base62(crc32(body))."""
    body, check = token[prefix_len:-6], token[-6:]
    expected = _b62_decode(check)
    if expected is None:
        return False
    return binascii.crc32(body.encode("ascii", "ignore")) & 0xFFFFFFFF == expected


def v_checksum_token(prefix_len):
    def _v(value, ctx):
        if crc32_base62_ok(value, prefix_len):
            return {"confidence": "high", "reasons": ["checksum_valid"]}
        # Real tokens always pass. A failure is almost always a dummy, docs
        # example or truncated token - keep it for completeness at info.
        return {"confidence": "low", "severity": "info", "reasons": ["checksum_invalid"]}

    return _v


def b64url_json(segment):
    pad = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + pad)
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    return obj if isinstance(obj, dict) else None


_JWT_SAMPLE_SUBS = {"1234567890", "user123", "test", "example"}


def v_jwt(value, ctx):
    parts = value.split(".")
    if len(parts) != 3:
        return None
    header, payload = b64url_json(parts[0]), b64url_json(parts[1])
    if header is None or payload is None or "alg" not in header:
        return None
    # jwt.io / RFC sample tokens
    if str(payload.get("sub")) in _JWT_SAMPLE_SUBS and str(payload.get("name", "")).lower() in {
        "john doe",
        "jane doe",
        "",
    }:
        return None

    claims = {}
    for k in ("iss", "sub", "aud", "role", "scope", "exp", "iat"):
        if k in payload:
            claims[k] = payload[k]
    out = {"extra": {"jwt_alg": header.get("alg"), "jwt_claims": claims}, "reasons": ["jwt_decoded"]}

    role = str(payload.get("role", "")).lower()
    iss = str(payload.get("iss", "")).lower()
    if role == "service_role":
        out.update(severity="critical", title="Supabase service_role JWT (bypasses RLS)")
        return out
    if role == "anon" or ("supabase" in iss and role in {"", "anon"}):
        out.update(severity="info", public=True, title="Supabase anon JWT (public by design)")
        return out
    if str(header.get("alg", "")).lower() == "none":
        out["reasons"].append("alg_none")
    if str(payload.get("sub")) in {"123456", "12345", "1"} and not payload.get("iss"):
        out.update(severity="info", confidence="low")
        out["reasons"].append("placeholder_claims")
    exp = payload.get("exp")
    if isinstance(exp, str) and exp.isdigit():
        exp = int(exp)
    if isinstance(exp, (int, float)) and exp > 1e11:
        exp = exp / 1000  # milliseconds (JS Date.now()) instead of seconds
    if isinstance(exp, (int, float)) and exp < time.time():
        out.update(severity="info", confidence="medium")
        out["reasons"].append("expired")
    return out


_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/=]")


def v_private_key(value, ctx):
    body = ctx.get("match").group("body") if ctx.get("match") else ""
    body = body.replace("\\n", "\n").replace("\\r", "")
    # Drop PEM headers such as Proc-Type / DEK-Info
    body = "\n".join(line for line in body.splitlines() if ":" not in line)
    compact = re.sub(r"[\s\"'+,]", "", body)
    b64_chars = len(_PEM_BODY_RE.findall(compact))
    if b64_chars < 100 or b64_chars / max(len(compact), 1) < 0.95:
        # Library code that merely contains the BEGIN/END marker strings
        # (node-forge, jsrsasign, ...) - code between them, not a key body.
        return None
    if re.search(r"(?i)\.\.\.|x{8,}|<[a-z ]+>|your[ _-]?private", body):
        return None
    return {"reasons": [f"pem_body_chars={b64_chars}"]}


def v_basic_auth(value, ctx):
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    if ":" not in decoded or not decoded.isprintable():
        return None
    user, _, pw = decoded.partition(":")
    if not pw or pw.lower() in {"password", "pass", "secret", "changeme"} and user.lower() in {"user", "username"}:
        return None
    return {"extra": {"decoded": decoded}, "reasons": ["basic_auth_decoded"]}


_CONN_CTX = re.compile(r"(?i)data source\s*=|server\s*=|initial catalog\s*=|provider\s*=|user id\s*=|uid\s*=|database\s*=|host\s*=|dsn\s*=")
_CONN_PLACEHOLDER = re.compile(r"(?i)^(?:\*+|x+|\{.*\}|\$\(.*\)|\[.*\]|<.*>|%.*%|password|pass|pwd|your.*|changeme|secret|null|none)$")


def v_connection_string(value, ctx):
    m = ctx["match"]
    text = ctx["text"]
    window = text[max(0, m.start() - 300) : m.end() + 300]
    v = value.strip()
    if not _CONN_CTX.search(window) or _CONN_PLACEHOLDER.match(v) or len(v) < 3:
        return None
    return {"reasons": ["connection_string_context"]}


def v_aws_key_id(value, ctx):
    # AKIA... keys are base32 (A-Z, 2-7) after the 4-char prefix.
    if not re.fullmatch(r"[A-Z2-7]{16}", value[4:]):
        return None
    return {}


# --------------------------------------------------------------------------- #
# Rule table
# --------------------------------------------------------------------------- #

B = r"(?<![A-Za-z0-9_-])"  # left boundary that also respects - and _
E = r"(?![A-Za-z0-9_-])"  # right boundary


def R(pattern, flags=0):
    return re.compile(pattern, flags)


RULES = [
    # ----------------------------------------------------------------- cloud
    Rule(
        "aws_access_key_id",
        "AWS access key ID",
        R(r"\b(?P<v>(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"),
        ("akia", "asia", "abia", "acca"),
        severity="high",
        validator=v_aws_key_id,
        note="Pair with a secret access key to authenticate. ASIA = temporary STS key.",
    ),
    Rule(
        "aws_secret_access_key",
        "AWS secret access key",
        R(
            r"(?i)(?:aws_?secret_?(?:access_?)?key|secret_?access_?key|secretAccessKey)[\"']?\s*(?:[:=]|=>)\s*[\"']?"
            r"(?P<v>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"
        ),
        ("secret",),
        severity="critical",
    ),
    Rule(
        "gcp_service_account",
        "GCP service account key (JSON)",
        R(r"\"type\"\s*:\s*\"service_account\"[^}]{0,600}?\"private_key_id\"\s*:\s*\"(?P<v>[a-f0-9]{40})\""),
        ("service_account",),
        severity="critical",
    ),
    Rule(
        "google_oauth_client_secret",
        "Google OAuth client secret",
        R(B + r"(?P<v>GOCSPX-[A-Za-z0-9_-]{28})" + E),
        ("gocspx-",),
        severity="high",
    ),
    Rule(
        "google_oauth_access_token",
        "Google OAuth access token",
        R(B + r"(?P<v>ya29\.[0-9A-Za-z_-]{30,})" + E),
        ("ya29.",),
        severity="high",
    ),
    Rule(
        "google_api_key",
        "Google API key (browser key)",
        R(B + r"(?P<v>AIza[0-9A-Za-z_-]{35})" + E),
        ("aiza",),
        severity="info",
        public=True,
        note="Browser keys are public by design. Check API restrictions: unrestricted Maps/Places keys allow billing abuse.",
    ),
    Rule(
        "azure_storage_account_key",
        "Azure storage account key",
        R(r"(?i)AccountKey=(?P<v>[A-Za-z0-9+/]{86}==)"),
        ("accountkey",),
        severity="critical",
    ),
    Rule(
        "azure_sas_url",
        "Azure SAS token URL",
        R(
            r"(?P<v>https://[\w.-]+\.(?:blob|file|queue|table|dfs)\.core\.windows\.net/[^\s\"'<>]*?"
            r"[?&]sig=[A-Za-z0-9%/+=]{30,}[^\s\"'<>]*)"
        ),
        ("sig=",),
        severity="high",
    ),
    Rule(
        "digitalocean_token",
        "DigitalOcean token",
        R(r"\b(?P<v>do[por]_v1_[a-f0-9]{64})\b"),
        ("_v1_",),
        severity="critical",
    ),
    Rule(
        "databricks_token",
        "Databricks token",
        R(r"\b(?P<v>dapi[a-f0-9]{32}(?:-\d)?)\b"),
        ("dapi",),
        severity="high",
    ),
    # ----------------------------------------------------------------- source control / CI
    Rule(
        "github_token",
        "GitHub token",
        R(r"\b(?P<v>gh[pousr]_[A-Za-z0-9]{36})\b"),
        ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
        severity="critical",
        validator=v_checksum_token(4),
    ),
    Rule(
        "github_fine_grained_pat",
        "GitHub fine-grained PAT",
        R(r"\b(?P<v>github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b"),
        ("github_pat_",),
        severity="critical",
    ),
    Rule(
        "gitlab_token",
        "GitLab token",
        R(r"\b(?P<v>gl(?:pat|rt|ptt|dt|oas)-[A-Za-z0-9_-]{20,64})" + E),
        ("glpat-", "glrt-", "glptt-", "gldt-", "gloas-"),
        severity="critical",
    ),
    Rule(
        "npm_token",
        "npm access token",
        R(r"\b(?P<v>npm_[A-Za-z0-9]{36})\b"),
        ("npm_",),
        severity="critical",
        validator=v_checksum_token(4),
    ),
    Rule(
        "pypi_token",
        "PyPI upload token",
        R(r"\b(?P<v>pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})"),
        ("pypi-",),
        severity="critical",
    ),
    Rule(
        "vault_token",
        "HashiCorp Vault token",
        R(r"\b(?P<v>hv[sb]\.[A-Za-z0-9_-]{90,})"),
        ("hvs.", "hvb."),
        severity="critical",
    ),
    Rule(
        "terraform_cloud_token",
        "Terraform Cloud token",
        R(r"\b(?P<v>[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70})"),
        (".atlasv1.",),
        severity="critical",
    ),
    Rule(
        "doppler_token",
        "Doppler token",
        R(r"\b(?P<v>dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44})\b"),
        ("dp.",),
        severity="critical",
    ),
    Rule(
        "postman_api_key",
        "Postman API key",
        R(r"\b(?P<v>PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b"),
        ("pmak-",),
        severity="high",
    ),
    Rule(
        "atlassian_api_token",
        "Atlassian API token",
        R(r"\b(?P<v>ATATT3[A-Za-z0-9_\-=]{180,})"),
        ("atatt3",),
        severity="high",
    ),
    Rule(
        "linear_api_key",
        "Linear API key",
        R(r"\b(?P<v>lin_api_[A-Za-z0-9]{40})\b"),
        ("lin_api_",),
        severity="high",
    ),
    # ----------------------------------------------------------------- comms
    Rule(
        "slack_token",
        "Slack token",
        R(r"\b(?P<v>xox[baprs]-[0-9]{6,}-[0-9A-Za-z-]{10,})" + E),
        ("xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"),
        severity="critical",
    ),
    Rule(
        "slack_webhook",
        "Slack incoming webhook",
        R(r"(?P<v>https://hooks\.slack\.com/(?:services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}|workflows/[A-Za-z0-9/]{20,}|triggers/[A-Za-z0-9/]{20,}))"),
        ("hooks.slack.com",),
        severity="high",
    ),
    Rule(
        "discord_webhook",
        "Discord webhook",
        R(r"(?P<v>https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,70})"),
        ("/api/webhooks/",),
        severity="high",
    ),
    Rule(
        "teams_webhook",
        "Microsoft Teams webhook",
        R(r"(?P<v>https://[\w-]+\.webhook\.office\.com/webhookb2/[\w@/-]{80,})"),
        ("webhook.office.com",),
        severity="high",
    ),
    Rule(
        "telegram_bot_token",
        "Telegram bot token",
        R(r"(?<![\d:])(?P<v>\d{8,10}:AA[A-Za-z0-9_-]{33})" + E),
        (":aa",),
        severity="high",
    ),
    Rule(
        "twilio_api_key",
        "Twilio API key SID",
        R(r"\b(?P<v>SK[0-9a-f]{32})\b"),
        ("sk",),
        severity="high",
        confidence="medium",
    ),
    Rule(
        "sendgrid_api_key",
        "SendGrid API key",
        R(r"\b(?P<v>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})" + E),
        ("sg.",),
        severity="critical",
    ),
    Rule(
        "mailgun_api_key",
        "Mailgun API key",
        R(r"\b(?P<v>key-[0-9a-f]{32})\b"),
        ("key-",),
        severity="high",
    ),
    Rule(
        "mailchimp_api_key",
        "Mailchimp API key",
        R(r"\b(?P<v>[0-9a-f]{32}-us\d{1,2})\b"),
        ("-us",),
        severity="high",
    ),
    Rule(
        "brevo_api_key",
        "Brevo / Sendinblue API key",
        R(r"\b(?P<v>xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16})\b"),
        ("xkeysib-",),
        severity="high",
    ),
    # ----------------------------------------------------------------- payments / commerce
    Rule(
        "stripe_secret_key",
        "Stripe live secret key",
        R(r"\b(?P<v>(?:sk|rk)_live_[0-9A-Za-z]{24,247})\b"),
        ("sk_live_", "rk_live_"),
        severity="critical",
    ),
    Rule(
        "stripe_test_secret_key",
        "Stripe test secret key",
        R(r"\b(?P<v>(?:sk|rk)_test_[0-9A-Za-z]{24,247})\b"),
        ("sk_test_", "rk_test_"),
        severity="low",
        note="Test-mode key: no real money, but exposes test data and account config.",
    ),
    Rule(
        "stripe_webhook_secret",
        "Stripe webhook signing secret",
        R(r"\b(?P<v>whsec_[A-Za-z0-9]{32,})\b"),
        ("whsec_",),
        severity="high",
    ),
    Rule(
        "stripe_publishable_key",
        "Stripe publishable key",
        R(r"\b(?P<v>pk_(?:live|test)_[0-9A-Za-z]{24,247})\b"),
        ("pk_live_", "pk_test_"),
        severity="info",
        public=True,
    ),
    Rule(
        "square_token",
        "Square access token / secret",
        R(r"\b(?P<v>sq0(?:atp|csp)-[0-9A-Za-z_-]{22,43})" + E),
        ("sq0atp-", "sq0csp-"),
        severity="critical",
    ),
    Rule(
        "braintree_token",
        "Braintree access token",
        R(r"(?P<v>access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})"),
        ("access_token$production$",),
        severity="critical",
    ),
    Rule(
        "shopify_token",
        "Shopify token",
        R(r"\b(?P<v>shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32})\b"),
        ("shpat_", "shpss_", "shpca_", "shppa_"),
        severity="critical",
    ),
    # ----------------------------------------------------------------- AI providers
    Rule(
        "openai_api_key",
        "OpenAI API key",
        R(
            r"\b(?P<v>sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,200}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"
            + E
        ),
        ("sk-proj-", "sk-svcacct-", "sk-admin-", "t3blbkfj"),
        severity="critical",
    ),
    Rule(
        "anthropic_api_key",
        "Anthropic API key",
        R(r"\b(?P<v>sk-ant-(?:api03|admin01|oat01)-[A-Za-z0-9_-]{80,120})" + E),
        ("sk-ant-",),
        severity="critical",
    ),
    Rule(
        "openrouter_api_key",
        "OpenRouter API key",
        R(r"\b(?P<v>sk-or-v1-[a-f0-9]{64})\b"),
        ("sk-or-v1-",),
        severity="critical",
    ),
    Rule(
        "groq_api_key",
        "Groq API key",
        R(r"\b(?P<v>gsk_[A-Za-z0-9]{52})\b"),
        ("gsk_",),
        severity="critical",
    ),
    Rule(
        "xai_api_key",
        "xAI API key",
        R(r"\b(?P<v>xai-[A-Za-z0-9]{80})\b"),
        ("xai-",),
        severity="critical",
    ),
    Rule(
        "huggingface_token",
        "Hugging Face token",
        R(r"\b(?P<v>hf_[A-Za-z0-9]{34})\b"),
        ("hf_",),
        severity="high",
    ),
    # ----------------------------------------------------------------- observability / SaaS
    Rule(
        "datadog_client_token",
        "Datadog RUM client token",
        R(r"\b(?P<v>pub[0-9a-f]{32})\b"),
        ("pub",),
        severity="info",
        public=True,
        note="Browser RUM/log-intake token, public by design. It can only submit telemetry.",
    ),
    Rule(
        "datadog_api_key",
        "Datadog API / application key",
        R(
            r"(?i)(?:dd|datadog)[\w.-]{0,12}(?P<kind>api|app(?:lication)?)[_-]?key[\"'`]?\s*(?:[:=]|=>)\s*[\"'`]?"
            r"(?P<v>[0-9a-f]{32}|[0-9a-f]{40})(?![0-9a-f])"
        ),
        ("datadog", "dd_", "dd-", "ddapi", "ddapp"),
        severity="critical",
    ),
    Rule(
        "sentry_dsn",
        "Sentry DSN",
        R(r"(?P<v>https://[0-9a-f]{32}@(?:o\d+\.)?ingest(?:\.[a-z]{2})?\.sentry\.io/\d+)"),
        ("ingest",),
        severity="info",
        public=True,
        note="Public by design. Reveals the org/project ID only.",
    ),
    Rule(
        "firebase_database_url",
        "Firebase Realtime Database URL",
        R(r"(?P<v>https://[a-z0-9-]+(?:-default-rtdb)?\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app))"),
        ("firebaseio.com", "firebasedatabase.app"),
        severity="info",
        category="cloud",
        note="Firebase database referenced by the site.",
    ),
    Rule(
        "cloud_bucket_url",
        "Cloud storage bucket",
        R(
            r"(?P<v>https?://(?:[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"
            r"|storage\.googleapis\.com/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]|[a-z0-9]{3,24}\.blob\.core\.windows\.net/[a-z0-9-]{3,63}"
            r"|[a-z0-9-]+\.firebasestorage\.app|firebasestorage\.googleapis\.com/v0/b/[a-z0-9._-]+))"
        ),
        ("amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "firebasestorage"),
        severity="info",
        category="cloud",
        note="Cloud storage referenced by the site.",
    ),
    Rule(
        "newrelic_user_key",
        "New Relic user API key",
        R(r"\b(?P<v>NRAK-[A-Z0-9]{27})\b"),
        ("nrak-",),
        severity="high",
    ),
    Rule(
        "dynatrace_token",
        "Dynatrace token",
        R(r"\b(?P<v>dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64})\b"),
        ("dt0c01.",),
        severity="high",
    ),
    Rule(
        "grafana_token",
        "Grafana token",
        R(r"\b(?P<v>glc_[A-Za-z0-9+/]{32,400}={0,2}|glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})"),
        ("glc_", "glsa_"),
        severity="high",
    ),
    Rule(
        "sentry_auth_token",
        "Sentry auth token",
        R(r"\b(?P<v>sntrys_eyJ[A-Za-z0-9+/=_-]{60,}|sntryu_[a-f0-9]{64})"),
        ("sntrys_", "sntryu_"),
        severity="high",
    ),
    Rule(
        "supabase_secret",
        "Supabase secret / management key",
        R(r"\b(?P<v>sb_secret_[A-Za-z0-9_-]{20,}|sbp_[a-f0-9]{40})"),
        ("sb_secret_", "sbp_"),
        severity="critical",
    ),
    Rule(
        "mapbox_secret_token",
        "Mapbox secret token",
        R(r"\b(?P<v>sk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})"),
        ("sk.eyj",),
        severity="high",
    ),
    Rule(
        "mapbox_public_token",
        "Mapbox public token",
        R(r"\b(?P<v>pk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})"),
        ("pk.eyj",),
        severity="info",
        public=True,
    ),
    Rule(
        "facebook_access_token",
        "Facebook access token",
        R(r"\b(?P<v>EAA[A-Za-z0-9]{90,})\b"),
        ("eaa",),
        severity="high",
        confidence="medium",
    ),
    Rule(
        "twitter_bearer_token",
        "Twitter/X bearer token",
        R(r"\b(?P<v>AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,})"),
        ("aaaaaaaaaaaaaaaaaaaaa",),
        severity="high",
    ),
    # ----------------------------------------------------------------- keyed (vendor name + key)
    Rule(
        "algolia_admin_key",
        "Algolia admin/write key",
        R(r"(?i)algolia[\w.-]{0,20}(?:admin|write)[\w.-]{0,10}key[\"']?\s*[:=]\s*[\"'](?P<v>[a-f0-9]{32})[\"']"),
        ("algolia",),
        severity="high",
    ),
    Rule(
        "heroku_api_key",
        "Heroku API key",
        R(
            r"(?i)(?:heroku[\w.-]{0,20}(?:api_?key|token)[\"']?\s*[:=]\s*[\"'](?P<v>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"'])"
        ),
        ("heroku",),
        severity="high",
    ),
    # ----------------------------------------------------------------- structural
    Rule(
        "private_key",
        "Private key",
        R(
            r"(?P<v>-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)"
            r"(?P<body>[\s\S]{0,12000}?)-----END",
        ),
        ("private key",),
        severity="critical",
        validator=v_private_key,
    ),
    Rule(
        "putty_private_key",
        "PuTTY private key",
        R(r"(?P<v>PuTTY-User-Key-File-\d: [\w-]+)[\s\S]{0,4000}?Private-Lines: \d+\s*(?:\\r)?(?:\\n|\n)[A-Za-z0-9+/=]{40,}"),
        ("putty-user-key-file",),
        severity="critical",
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        R(r"(?<![A-Za-z0-9_.-])(?P<v>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})" + E),
        ("eyj",),
        severity="medium",
        category="token",
        validator=v_jwt,
    ),
    Rule(
        "connection_string_password",
        "Password in connection string",
        R(r"(?i)(?:^|[;\"'\s])(?:password|pwd)\s*=\s*(?P<v>[^;\"'\r\n<>]{3,128})"),
        ("password", "pwd"),
        severity="critical",
        category="credential",
        validator=v_connection_string,
    ),
    Rule(
        "basic_auth_header",
        "Hardcoded HTTP Basic credentials",
        R(r"(?i)[\"']?authorization[\"']?\s*[:=]\s*[\"'`]Basic\s+(?P<v>[A-Za-z0-9+/]{8,}={0,2})[\"'`]"),
        ("basic",),
        severity="high",
        category="credential",
        validator=v_basic_auth,
    ),
    Rule(
        "bearer_header",
        "Hardcoded bearer token",
        R(r"(?i)[\"']?authorization[\"']?\s*[:=]\s*[\"'`]Bearer\s+(?P<v>[A-Za-z0-9._~+/-]{20,}=*)[\"'`]"),
        ("bearer",),
        severity="high",
        confidence="medium",
        category="token",
    ),
]

RULES_BY_ID = {r.id: r for r in RULES}
