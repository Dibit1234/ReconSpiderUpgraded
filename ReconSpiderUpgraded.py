import argparse
import json
import math
import re
import shutil
import sys
import time
from html import unescape
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlunparse

import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.downloadermiddlewares.offsite import OffsiteMiddleware

APP_NAME = "ReconSpiderUpgraded"
APP_VERSION = "3.0"


class CustomOffsiteMiddleware(OffsiteMiddleware):
    def should_follow(self, request, spider):
        if not self.host_regex:
            return True
        host = urlparse(request.url).netloc.split(":")[0]
        return bool(self.host_regex.search(host))


class WebReconSpider(scrapy.Spider):
    name = "ReconSpiderUpgraded"

    EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    IPV4_CANDIDATE_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

    # High-confidence provider token patterns
    API_PATTERNS = {
        "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b"),
        "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "stripe_key": re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        "github_pat": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
        "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b"),
        "gitlab_pat": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b"),
        "slack_token": re.compile(r"\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b"),
        "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"),
        "twilio_api_key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        "sendgrid_api_key": re.compile(r"\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "shopify_access_token": re.compile(r"\bshpat_[A-Fa-f0-9]{32}\b"),
        "digitalocean_pat": re.compile(r"\bdop_v1_[A-Za-z0-9]{40,}\b"),
        "mapbox_token": re.compile(r"\b(?:pk|sk)\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    }

    API_CONTEXT_RE = re.compile(
        r"(?ix)"
        r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|bearer)"
        r"\s*[:=]\s*"
        r"[\"']?([A-Za-z0-9_\-./+=]{16,})[\"']?"
    )

    USERNAME_CONTEXT_RE = re.compile(
        r"(?ix)"
        r"(?:username|user|login|account|userid|user_id)"
        r"\s*[:=]\s*"
        r"[\"']?([A-Za-z0-9._@\-]{3,64})[\"']?"
    )

    PASSWORD_ASSIGNMENT_RE = re.compile(
        r"(?ix)"
        r"(?:password|passwd|pwd|passphrase|db_pass|db_password|secret)"
        r"\s*[:=]\s*"
        r"[\"']([^\"'\n\r]{4,128})[\"']"
    )
    STRUCTURED_KV_RE = re.compile(
        r"(?ix)"
        r"(?:^|[,{;\s])"
        r"[\"']?([a-zA-Z0-9_.-]{2,64})[\"']?"
        r"\s*[:=]\s*"
        r"[\"']([^\"'\n\r]{1,256})[\"']"
    )
    JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
    PRIVATE_KEY_BLOCK_RE = re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE
    )
    GENERIC_SECRET_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_./+=-]{20,256}\b")

    USERNAME_KEYS = {"username", "user", "login", "account", "userid", "user_id", "email", "owner"}
    PASSWORD_KEYS = {"password", "passwd", "pwd", "passphrase", "credential", "db_password", "db_pass"}
    TOKEN_KEYS = {
        "api_key",
        "apikey",
        "api-token",
        "token",
        "access_token",
        "auth_token",
        "secret",
        "secret_key",
        "client_secret",
        "bearer",
    }
    PLACEHOLDER_VALUES = {
        "null",
        "none",
        "undefined",
        "example",
        "sample",
        "test",
        "changeme",
        "change_me",
        "your_api_key",
        "your_token",
        "your_password",
        "xxxxx",
        "xxxxxxxx",
        "********",
        "**********",
    }
    CONTEXT_HINTS = {"auth", "password", "credential", "secret", "token", "apikey", "api_key", "login", "bearer"}

    PASSWORD_PLACEHOLDERS = {
        "password",
        "passwd",
        "example",
        "sample",
        "test",
        "changeme",
        "change_me",
        "your_password",
        "<password>",
        "********",
        "**********",
    }

    TRACKING_QUERY_KEYS = {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "gclid",
        "fbclid",
        "mc_cid",
        "mc_eid",
    }

    SKIP_PATH_PATTERNS = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"/logout/?$",
            r"/signout/?$",
            r"/wp-login\.php$",
            r"/wp-admin/",
            r"/cart/?$",
            r"/checkout/?$",
            r"/calendar/",
        ]
    ]

    def __init__(
        self,
        start_url,
        max_pages=1200,
        verbose=False,
        max_text_bytes=1500000,
        stream_findings=True,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.start_urls = [start_url]
        self.allowed_domains = [urlparse(start_url).netloc.split(":")[0]]

        self.max_pages = max(1, int(max_pages))
        self.max_text_bytes = max(4096, int(max_text_bytes))
        self.verbose = self._as_bool(verbose)
        self.stream_findings = self._as_bool(stream_findings)

        # Canonicalized URL dedupe
        self.visited_urls = set()
        self.visited_assets = set()

        self.results = {
            "emails": set(),
            "links": set(),
            "external_files": set(),
            "js_files": set(),
            "form_fields": set(),
            "images": set(),
            "videos": set(),
            "audio": set(),
            "comments": set(),
            "passwords": set(),
            "api_keys": set(),
            "usernames": set(),
            "ip_addresses": set(),
            "api_key_candidates": set(),
            "password_candidates": set(),
            "jwt_tokens": set(),
            "private_key_markers": set(),
        }

        # Rich findings for triage
        self.findings = {
            "emails": [],
            "ip_addresses": [],
            "api_keys": [],
            "api_key_candidates": [],
            "passwords": [],
            "password_candidates": [],
            "usernames": [],
            "jwt_tokens": [],
            "private_key_markers": [],
        }
        self.finding_dedupe = set()

        self.scan_stats = {
            "pages_scanned": 0,
            "text_pages_scanned": 0,
            "asset_responses_scanned": 0,
            "urls_normalized": 0,
            "urls_skipped_by_rules": 0,
            "asset_requests_scheduled": 0,
            "oversize_text_skipped": 0,
            "ip_matches": 0,
            "api_matches": 0,
            "password_matches": 0,
            "username_matches": 0,
            "structured_kv_hits": 0,
            "entropy_secret_hits": 0,
            "emails_found": 0,
            "links_found": 0,
            "external_files_found": 0,
            "js_files_found": 0,
            "form_fields_found": 0,
            "images_found": 0,
            "videos_found": 0,
            "audio_found": 0,
            "comments_found": 0,
            "passwords_found": 0,
            "password_candidates_found": 0,
            "api_keys_found": 0,
            "api_key_candidates_found": 0,
            "usernames_found": 0,
            "ip_addresses_found": 0,
            "jwt_tokens_found": 0,
            "private_key_markers_found": 0,
            "high_confidence_findings": 0,
            "medium_confidence_findings": 0,
            "low_confidence_findings": 0,
            "elapsed_seconds": 0.0,
            "pages_per_second": 0.0,
        }

        self.start_ts = time.time()
        self.spinner = "|/-\\"
        self._last_progress_emit = 0

        self.findings_stream_path = "findings.jsonl"
        self.findings_stream_handle = None
        self._stream_write_count = 0
        if self.stream_findings:
            self.findings_stream_handle = open(self.findings_stream_path, "w", encoding="utf-8")

        if not self.verbose:
            self.logger.setLevel("WARNING")

    @staticmethod
    def _as_bool(value):
        return str(value).lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _is_valid_ipv4(candidate):
        parts = candidate.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            if len(part) > 1 and part.startswith("0"):
                return False
            value = int(part)
            if value < 0 or value > 255:
                return False
        return True

    @staticmethod
    def _is_likely_version_string(candidate):
        parts = [int(p) for p in candidate.split(".")]
        small_parts = sum(1 for p in parts if p <= 30)
        return small_parts >= 3

    @staticmethod
    def _password_complexity_score(value):
        has_lower = any(c.islower() for c in value)
        has_upper = any(c.isupper() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_symbol = any(not c.isalnum() for c in value)
        return sum([has_lower, has_upper, has_digit, has_symbol])

    @staticmethod
    def _shannon_entropy(value):
        if not value:
            return 0.0
        freq = {}
        for char in value:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        length = float(len(value))
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _is_placeholder(self, value):
        lowered = value.strip().lower()
        if lowered in self.PLACEHOLDER_VALUES:
            return True
        if lowered.startswith("${") or lowered.startswith("<"):
            return True
        if lowered.startswith("http://") or lowered.startswith("https://"):
            return True
        return False

    def _api_candidate_score(self, value):
        classes = sum(
            [
                any(c.islower() for c in value),
                any(c.isupper() for c in value),
                any(c.isdigit() for c in value),
                any(c in "-_./+=" for c in value),
            ]
        )
        entropy = self._shannon_entropy(value)
        score = 0
        if len(value) >= 20:
            score += 1
        if classes >= 3:
            score += 1
        if entropy >= 3.6:
            score += 1
        return score, entropy

    def _password_score(self, value, key_hint="", has_auth_context=False):
        score = 0
        reasons = []
        if len(value) >= 8:
            score += 1
            reasons.append("len>=8")
        if len(value) >= 12:
            score += 1
            reasons.append("len>=12")
        complexity = self._password_complexity_score(value)
        if complexity >= 3:
            score += 1
            reasons.append("complexity>=3")
        if any(k in key_hint for k in self.PASSWORD_KEYS):
            score += 1
            reasons.append("password_key")
        if has_auth_context:
            score += 1
            reasons.append("auth_context")
        entropy = self._shannon_entropy(value)
        if entropy >= 3.4:
            score += 1
            reasons.append("entropy_high")
        return score, reasons

    @staticmethod
    def _render_progress_bar(percent, width=24):
        filled = int(width * percent)
        return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"

    @staticmethod
    def _format_pair(primary, candidates):
        if candidates <= 0:
            return str(primary)
        return f"{primary}+{candidates}"

    @staticmethod
    def _snip_context(text, value, radius=48):
        idx = text.find(value)
        if idx < 0:
            return ""
        left = max(0, idx - radius)
        right = min(len(text), idx + len(value) + radius)
        snippet = text[left:right].replace("\n", " ").replace("\r", " ")
        return snippet[:220]

    def _normalize_url(self, raw_url):
        parsed = urlparse(raw_url)
        scheme = (parsed.scheme or "http").lower()
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return raw_url

        port = parsed.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = hostname
        elif port:
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        params = []
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            if k.lower() in self.TRACKING_QUERY_KEYS:
                continue
            params.append((k, v))
        params.sort(key=lambda item: (item[0], item[1]))
        query = urlencode(params, doseq=True)

        normalized = urlunparse((scheme, netloc, parsed.path or "/", "", query, ""))
        self.scan_stats["urls_normalized"] += 1
        return normalized

    def _should_skip_url(self, normalized_url):
        parsed = urlparse(normalized_url)
        path = parsed.path or "/"
        query = (parsed.query or "").lower()

        if "replytocom=" in query:
            return True
        if "sessionid=" in query or "phpsessid=" in query:
            return True

        for pattern in self.SKIP_PATH_PATTERNS:
            if pattern.search(path):
                return True
        return False

    def _record_finding(self, kind, value, confidence, url, source_type, context="", reasons=None):
        if not value:
            return
        dedupe_key = (kind, value, url)
        if dedupe_key in self.finding_dedupe:
            return
        self.finding_dedupe.add(dedupe_key)

        finding = {
            "value": value,
            "confidence": confidence,
            "url": url,
            "source": source_type,
        }
        if context:
            finding["context"] = context
        if reasons:
            finding["reasons"] = reasons
        self.findings[kind].append(finding)

        if confidence == "high":
            self.scan_stats["high_confidence_findings"] += 1
        elif confidence == "medium":
            self.scan_stats["medium_confidence_findings"] += 1
        else:
            self.scan_stats["low_confidence_findings"] += 1

        if self.findings_stream_handle:
            stream_row = dict(finding)
            stream_row["kind"] = kind
            self.findings_stream_handle.write(json.dumps(stream_row, ensure_ascii=False) + "\n")
            self._stream_write_count += 1
            if self._stream_write_count % 25 == 0:
                self.findings_stream_handle.flush()

    def _print_progress(self):
        pages = self.scan_stats["pages_scanned"]
        elapsed = max(time.time() - self.start_ts, 0.001)
        pct = min(pages / self.max_pages, 1.0)
        spin = self.spinner[pages % len(self.spinner)]

        found_total = (
            len(self.results["emails"])
            + len(self.results["ip_addresses"])
            + len(self.results["api_keys"])
            + len(self.results["api_key_candidates"])
            + len(self.results["passwords"])
            + len(self.results["password_candidates"])
            + len(self.results["usernames"])
        )

        if not sys.stdout.isatty():
            if pages - self._last_progress_emit < 50 and pages != self.max_pages:
                return
            self._last_progress_emit = pages
            print(
                f"progress {pct * 100:6.2f}% pages={pages}/{self.max_pages} "
                f"text={self.scan_stats['text_pages_scanned']} found={found_total}"
            )
            return

        term_width = max(shutil.get_terminal_size((120, 20)).columns, 60)
        bar_width = max(12, min(28, term_width // 5))
        bar = self._render_progress_bar(pct, width=bar_width)

        line = (
            f"{spin} {bar} {pct * 100:6.2f}% "
            f"pages={pages}/{self.max_pages} text={self.scan_stats['text_pages_scanned']} "
            f"found={found_total} ips={len(self.results['ip_addresses'])} "
            f"api={self._format_pair(len(self.results['api_keys']), len(self.results['api_key_candidates']))} "
            f"pass={self._format_pair(len(self.results['passwords']), len(self.results['password_candidates']))} "
            f"users={len(self.results['usernames'])} rate={pages / elapsed:5.1f}/s"
        )
        clipped = line[: term_width - 1]
        sys.stdout.write("\r\033[2K" + clipped)
        sys.stdout.flush()

    def _record_private_ips_first(self, ips):
        private = []
        public = []
        for ip in ips:
            if ip.startswith("10."):
                private.append(ip)
                continue
            if ip.startswith("192.168."):
                private.append(ip)
                continue
            if ip.startswith("172."):
                second = int(ip.split(".")[1])
                if 16 <= second <= 31:
                    private.append(ip)
                    continue
            public.append(ip)
        return sorted(set(private)) + sorted(set(public))

    def _extract_ipv4(self, text, source_url, source_type):
        for candidate in self.IPV4_CANDIDATE_RE.findall(text):
            if not self._is_valid_ipv4(candidate):
                continue
            if self._is_likely_version_string(candidate):
                continue
            self.results["ip_addresses"].add(candidate)
            self.scan_stats["ip_matches"] += 1
            self._record_finding(
                "ip_addresses",
                candidate,
                "high",
                source_url,
                source_type,
                self._snip_context(text, candidate),
            )

    def _extract_api_keys(self, text, source_url, source_type):
        for pattern in self.API_PATTERNS.values():
            for match in pattern.findall(text):
                self.results["api_keys"].add(match)
                self.scan_stats["api_matches"] += 1
                self._record_finding(
                    "api_keys",
                    match,
                    "high",
                    source_url,
                    source_type,
                    self._snip_context(text, match),
                    reasons=["provider_signature"],
                )

        for match in self.API_CONTEXT_RE.findall(text):
            candidate = match.strip()
            if len(candidate) < 16 or self._is_placeholder(candidate):
                continue
            score, entropy = self._api_candidate_score(candidate)
            if candidate.isalpha() or score < 2:
                continue
            if score >= 3:
                self.results["api_keys"].add(candidate)
                self.scan_stats["api_matches"] += 1
                self._record_finding(
                    "api_keys",
                    candidate,
                    "high",
                    source_url,
                    source_type,
                    self._snip_context(text, candidate),
                    reasons=[f"context_assignment", f"entropy={entropy:.2f}"],
                )
            else:
                self.results["api_key_candidates"].add(candidate)
                self._record_finding(
                    "api_key_candidates",
                    candidate,
                    "medium",
                    source_url,
                    source_type,
                    self._snip_context(text, candidate),
                    reasons=[f"context_assignment", f"entropy={entropy:.2f}"],
                )

    def _extract_usernames(self, text, source_url, source_type):
        for username in self.USERNAME_CONTEXT_RE.findall(text):
            cleaned = username.strip()
            if cleaned.lower() in {"admin", "root", "user", "username", "login", "test"}:
                continue
            if self._is_placeholder(cleaned):
                continue
            self.results["usernames"].add(cleaned)
            self.scan_stats["username_matches"] += 1
            self._record_finding(
                "usernames",
                cleaned,
                "medium",
                source_url,
                source_type,
                self._snip_context(text, cleaned),
                reasons=["username_context"],
            )

    def _extract_passwords(self, text, source_url, source_type):
        surrounding_context = text.lower()
        has_auth_context = any(
            k in surrounding_context for k in self.CONTEXT_HINTS
        )

        for value in self.PASSWORD_ASSIGNMENT_RE.findall(text):
            candidate = unescape(value.strip())
            if not candidate:
                continue
            if candidate.lower() in self.PASSWORD_PLACEHOLDERS:
                continue
            if self._is_placeholder(candidate):
                continue

            score, reasons = self._password_score(candidate, key_hint="password", has_auth_context=has_auth_context)

            context = self._snip_context(text, candidate)
            if score >= 4:
                self.results["passwords"].add(candidate)
                self.scan_stats["password_matches"] += 1
                self._record_finding("passwords", candidate, "high", source_url, source_type, context, reasons)
            else:
                self.results["password_candidates"].add(candidate)
                self._record_finding(
                    "password_candidates",
                    candidate,
                    "low" if score < 3 else "medium",
                    source_url,
                    source_type,
                    context,
                    reasons,
                )

    def _classify_structured_kv(self, key, value, source_url, source_type, raw_text):
        key_l = key.lower().strip()
        value = unescape(value.strip())
        if not value or self._is_placeholder(value):
            return

        self.scan_stats["structured_kv_hits"] += 1
        context = self._snip_context(raw_text, value)

        if any(k in key_l for k in self.PASSWORD_KEYS):
            score, reasons = self._password_score(value, key_hint=key_l, has_auth_context=True)
            if score >= 4:
                self.results["passwords"].add(value)
                self.scan_stats["password_matches"] += 1
                self._record_finding("passwords", value, "high", source_url, source_type, context, reasons)
            else:
                self.results["password_candidates"].add(value)
                self._record_finding("password_candidates", value, "medium", source_url, source_type, context, reasons)
            return

        if any(k in key_l for k in self.TOKEN_KEYS):
            score, entropy = self._api_candidate_score(value)
            reasons = [f"token_key={key_l}", f"entropy={entropy:.2f}"]
            if score >= 3:
                self.results["api_keys"].add(value)
                self.scan_stats["api_matches"] += 1
                self._record_finding("api_keys", value, "high", source_url, source_type, context, reasons)
            elif score >= 2:
                self.results["api_key_candidates"].add(value)
                self._record_finding("api_key_candidates", value, "medium", source_url, source_type, context, reasons)
            return

        if any(k in key_l for k in self.USERNAME_KEYS):
            if len(value) <= 128 and not self._is_placeholder(value):
                self.results["usernames"].add(value)
                self.scan_stats["username_matches"] += 1
                self._record_finding(
                    "usernames",
                    value,
                    "medium",
                    source_url,
                    source_type,
                    context,
                    reasons=[f"username_key={key_l}"],
                )

    def _extract_structured_assignments(self, text, source_url, source_type):
        for key, value in self.STRUCTURED_KV_RE.findall(text):
            self._classify_structured_kv(key, value, source_url, source_type, text)

    def _extract_entropy_secrets(self, text, source_url, source_type):
        for token in self.GENERIC_SECRET_TOKEN_RE.findall(text):
            if len(token) < 20 or len(token) > 180:
                continue
            if token.isdigit() or self._is_placeholder(token):
                continue
            entropy = self._shannon_entropy(token)
            classes = sum(
                [
                    any(c.islower() for c in token),
                    any(c.isupper() for c in token),
                    any(c.isdigit() for c in token),
                    any(c in "-_./+=" for c in token),
                ]
            )
            if entropy < 4.0 or classes < 3:
                continue
            self.scan_stats["entropy_secret_hits"] += 1
            self.results["api_key_candidates"].add(token)
            self._record_finding(
                "api_key_candidates",
                token,
                "low",
                source_url,
                source_type,
                self._snip_context(text, token),
                reasons=[f"entropy={entropy:.2f}", "generic_secret_token"],
            )

    def _extract_jwt_and_private_keys(self, text, source_url, source_type):
        for token in self.JWT_RE.findall(text):
            self.results["jwt_tokens"].add(token)
            self.results["api_keys"].add(token)
            self.scan_stats["api_matches"] += 1
            self._record_finding(
                "jwt_tokens",
                token,
                "high",
                source_url,
                source_type,
                self._snip_context(text, token),
                reasons=["jwt_signature"],
            )
            self._record_finding(
                "api_keys",
                token,
                "high",
                source_url,
                source_type,
                self._snip_context(text, token),
                reasons=["jwt_signature"],
            )
        for marker in self.PRIVATE_KEY_BLOCK_RE.findall(text):
            self.results["private_key_markers"].add(marker)
            self._record_finding(
                "private_key_markers",
                marker,
                "high",
                source_url,
                source_type,
                self._snip_context(text, marker),
                reasons=["private_key_block"],
            )

    def _extract_sensitive_data(self, text, source_url, source_type):
        for email in self.EMAIL_RE.findall(text):
            self.results["emails"].add(email)
            self._record_finding(
                "emails",
                email,
                "medium",
                source_url,
                source_type,
                self._snip_context(text, email),
                reasons=["email_pattern"],
            )

        self._extract_ipv4(text, source_url, source_type)
        self._extract_api_keys(text, source_url, source_type)
        self._extract_usernames(text, source_url, source_type)
        self._extract_passwords(text, source_url, source_type)
        self._extract_structured_assignments(text, source_url, source_type)
        self._extract_entropy_secrets(text, source_url, source_type)
        self._extract_jwt_and_private_keys(text, source_url, source_type)

    def _extract_querystring_credentials(self, url):
        params = parse_qs(urlparse(url).query)
        for key, values in params.items():
            k = key.lower()
            for value in values:
                candidate = value.strip()
                if not candidate or self._is_placeholder(candidate):
                    continue
                if any(t in k for t in ["pass", "pwd", "secret", "credential"]):
                    score, reasons = self._password_score(candidate, key_hint=k, has_auth_context=True)
                    if score >= 4:
                        self.results["passwords"].add(candidate)
                        self.scan_stats["password_matches"] += 1
                        self._record_finding("passwords", candidate, "high", url, "query", reasons=reasons)
                    else:
                        self.results["password_candidates"].add(candidate)
                        self._record_finding("password_candidates", candidate, "medium", url, "query", reasons=reasons)
                if any(t in k for t in ["api", "token", "key", "auth", "bearer"]):
                    score, entropy = self._api_candidate_score(candidate)
                    reasons = [f"query_key={k}", f"entropy={entropy:.2f}"]
                    if score >= 3:
                        self.results["api_keys"].add(candidate)
                        self.scan_stats["api_matches"] += 1
                        self._record_finding("api_keys", candidate, "high", url, "query", reasons=reasons)
                    elif score >= 2:
                        self.results["api_key_candidates"].add(candidate)
                        self._record_finding("api_key_candidates", candidate, "medium", url, "query", reasons=reasons)
                if any(t in k for t in ["user", "login", "account", "email"]):
                    if len(candidate) <= 128:
                        self.results["usernames"].add(candidate)
                        self.scan_stats["username_matches"] += 1
                        self._record_finding(
                            "usernames",
                            candidate,
                            "medium",
                            url,
                            "query",
                            reasons=[f"query_key={k}"],
                        )

    def _schedule_asset_request(self, absolute_url, response, source_type):
        normalized = self._normalize_url(absolute_url)
        if self._should_skip_url(normalized):
            self.scan_stats["urls_skipped_by_rules"] += 1
            return None
        if normalized in self.visited_assets:
            return None
        if urlparse(normalized).netloc != urlparse(response.url).netloc:
            return None

        self.visited_assets.add(normalized)
        self.scan_stats["asset_requests_scheduled"] += 1
        return response.follow(normalized, callback=self.parse_asset, cb_kwargs={"source_type": source_type})

    def parse_asset(self, response, source_type="asset"):
        self.scan_stats["asset_responses_scanned"] += 1
        content_type = response.headers.get("Content-Type", b"").decode("utf-8", errors="ignore").lower()

        # Large assets are skipped for performance.
        if len(response.body) > self.max_text_bytes:
            self.scan_stats["oversize_text_skipped"] += 1
            return

        looks_text = any(t in content_type for t in ["javascript", "ecmascript", "json", "css", "text"])
        if not looks_text:
            return

        body_text = response.text if hasattr(response, "text") else response.body.decode("utf-8", errors="ignore")
        self._extract_sensitive_data(body_text, response.url, source_type)
        self._print_progress()

    def parse(self, response):
        self.scan_stats["pages_scanned"] += 1
        current_url = self._normalize_url(response.url)
        self.visited_urls.add(current_url)

        content_type = response.headers.get("Content-Type", b"").decode("utf-8", errors="ignore").lower()
        is_text = content_type.startswith("text") or "json" in content_type or "javascript" in content_type

        if is_text:
            self.scan_stats["text_pages_scanned"] += 1

            if len(response.body) > self.max_text_bytes:
                self.scan_stats["oversize_text_skipped"] += 1
            else:
                self._extract_sensitive_data(response.text, response.url, "html")

                comments = response.xpath("//comment()").getall()
                self.results["comments"].update(comments)
                for comment in comments:
                    self._extract_sensitive_data(comment, response.url, "comment")

                inline_scripts = response.css("script::text").getall()
                for script in inline_scripts:
                    self._extract_sensitive_data(script, response.url, "inline_js")

                links = response.css("a::attr(href)").getall()
                for link in links:
                    if link.startswith("mailto:"):
                        continue

                    absolute = response.urljoin(link)
                    normalized = self._normalize_url(absolute)
                    if self._should_skip_url(normalized):
                        self.scan_stats["urls_skipped_by_rules"] += 1
                        continue

                    self._extract_querystring_credentials(normalized)

                    if urlparse(normalized).netloc == urlparse(response.url).netloc:
                        if normalized not in self.visited_urls:
                            self.visited_urls.add(normalized)
                            yield response.follow(normalized, callback=self.parse)

                    self.results["links"].add(normalized)

                external_files = response.css("link::attr(href), a::attr(href)").re(r".*\.(?:css|pdf|docx?|xlsx?)$")
                for ext_file in external_files:
                    absolute_ext = self._normalize_url(response.urljoin(ext_file))
                    self.results["external_files"].add(absolute_ext)

                css_files = response.css("link[rel*=stylesheet]::attr(href)").getall()
                for css_href in css_files:
                    req = self._schedule_asset_request(response.urljoin(css_href), response, "css")
                    if req:
                        yield req

                js_files = response.css("script::attr(src)").getall()
                for js_file in js_files:
                    absolute_js = self._normalize_url(response.urljoin(js_file))
                    self.results["js_files"].add(absolute_js)
                    req = self._schedule_asset_request(absolute_js, response, "js")
                    if req:
                        yield req

                form_fields = response.css("input::attr(name), textarea::attr(name), select::attr(name)").getall()
                self.results["form_fields"].update(form_fields)

                images = response.css("img::attr(src)").getall()
                for img in images:
                    self.results["images"].add(self._normalize_url(response.urljoin(img)))

                videos = response.css("video::attr(src), source::attr(src)").getall()
                for video in videos:
                    self.results["videos"].add(self._normalize_url(response.urljoin(video)))

                audio = response.css("audio::attr(src), source::attr(src)").getall()
                for aud in audio:
                    self.results["audio"].add(self._normalize_url(response.urljoin(aud)))
        else:
            self.results["external_files"].add(response.url)

        if self.verbose:
            self.logger.info(
                "Processed %s | text=%s | ips=%d api=%d pass=%d users=%d",
                response.url,
                is_text,
                len(self.results["ip_addresses"]),
                len(self.results["api_keys"]) + len(self.results["api_key_candidates"]),
                len(self.results["passwords"]) + len(self.results["password_candidates"]),
                len(self.results["usernames"]),
            )

        self._print_progress()

    def closed(self, reason):
        elapsed = max(time.time() - self.start_ts, 0.001)

        normalized = {}
        for key, values in self.results.items():
            if key == "ip_addresses":
                normalized[key] = self._record_private_ips_first(values)
            else:
                normalized[key] = sorted(values)

        # Bucket counts
        self.scan_stats["emails_found"] = len(self.results["emails"])
        self.scan_stats["links_found"] = len(self.results["links"])
        self.scan_stats["external_files_found"] = len(self.results["external_files"])
        self.scan_stats["js_files_found"] = len(self.results["js_files"])
        self.scan_stats["form_fields_found"] = len(self.results["form_fields"])
        self.scan_stats["images_found"] = len(self.results["images"])
        self.scan_stats["videos_found"] = len(self.results["videos"])
        self.scan_stats["audio_found"] = len(self.results["audio"])
        self.scan_stats["comments_found"] = len(self.results["comments"])
        self.scan_stats["passwords_found"] = len(self.results["passwords"])
        self.scan_stats["password_candidates_found"] = len(self.results["password_candidates"])
        self.scan_stats["api_keys_found"] = len(self.results["api_keys"])
        self.scan_stats["api_key_candidates_found"] = len(self.results["api_key_candidates"])
        self.scan_stats["usernames_found"] = len(self.results["usernames"])
        self.scan_stats["ip_addresses_found"] = len(self.results["ip_addresses"])
        self.scan_stats["jwt_tokens_found"] = len(self.results["jwt_tokens"])
        self.scan_stats["private_key_markers_found"] = len(self.results["private_key_markers"])

        self.scan_stats["elapsed_seconds"] = round(elapsed, 3)
        self.scan_stats["pages_per_second"] = round(self.scan_stats["pages_scanned"] / elapsed, 3)

        normalized["findings"] = self.findings
        normalized["scan_stats"] = self.scan_stats
        normalized["scan_reason"] = reason
        normalized["target"] = self.start_urls[0]
        normalized["max_pages"] = self.max_pages
        normalized["max_text_bytes"] = self.max_text_bytes

        with open("results.json", "w", encoding="utf-8") as handle:
            json.dump(normalized, handle, indent=4)

        if self.findings_stream_handle:
            self.findings_stream_handle.flush()
            self.findings_stream_handle.close()

        sys.stdout.write("\n\nScan complete. Results saved to results.json\n")
        if self.stream_findings:
            sys.stdout.write(f"Streaming findings: {self.findings_stream_path}\n")
        sys.stdout.write(
            "Summary: pages={pages} text={text} emails={emails} ips={ips} api={api} "
            "pass={pwd} users={users} jwt={jwt} pkey={pkey} assets={assets}\n".format(
                pages=self.scan_stats["pages_scanned"],
                text=self.scan_stats["text_pages_scanned"],
                emails=self.scan_stats["emails_found"],
                ips=self.scan_stats["ip_addresses_found"],
                api=self._format_pair(
                    self.scan_stats["api_keys_found"],
                    self.scan_stats["api_key_candidates_found"],
                ),
                pwd=self._format_pair(
                    self.scan_stats["passwords_found"],
                    self.scan_stats["password_candidates_found"],
                ),
                users=self.scan_stats["usernames_found"],
                jwt=self.scan_stats["jwt_tokens_found"],
                pkey=self.scan_stats["private_key_markers_found"],
                assets=self.scan_stats["asset_responses_scanned"],
            )
        )
        sys.stdout.flush()


def run_crawler(start_url, max_pages=1200, verbose=False, max_text_bytes=1500000, stream_findings=True):
    verbose = WebReconSpider._as_bool(verbose)
    stream_findings = WebReconSpider._as_bool(stream_findings)

    settings = {
        "DOWNLOADER_MIDDLEWARES": {
            "__main__.CustomOffsiteMiddleware": 500,
        },
        "CLOSESPIDER_PAGECOUNT": max(1, int(max_pages)),
        "LOG_LEVEL": "INFO" if verbose else "WARNING",
        "LOGSTATS_INTERVAL": 0,
        "DOWNLOAD_TIMEOUT": 20,
        "RETRY_TIMES": 2,
        "CONCURRENT_REQUESTS": 24,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 16,
        "AUTOTHROTTLE_ENABLED": True,
        "AUTOTHROTTLE_START_DELAY": 0.25,
        "AUTOTHROTTLE_MAX_DELAY": 5.0,
        "AUTOTHROTTLE_TARGET_CONCURRENCY": 6.0,
    }

    if not verbose:
        settings["LOG_ENABLED"] = False

    process = CrawlerProcess(settings=settings)
    process.crawl(
        WebReconSpider,
        start_url=start_url,
        max_pages=max_pages,
        verbose=verbose,
        max_text_bytes=max_text_bytes,
        stream_findings=stream_findings,
    )
    print_banner(start_url, max_pages, verbose, max_text_bytes, stream_findings)
    process.start()


def print_banner(start_url, max_pages, verbose, max_text_bytes, stream_findings):
    if not sys.stdout.isatty():
        return
    banner = r"""
 ____  _____ ____ ___  _   _   ____  ____  ___ ____  _____ ____   _   _ ____  ____    _  _____ _____ ____
|  _ \| ____/ ___/ _ \| \ | | / ___||  _ \|_ _|  _ \| ____|  _ \ | | | |  _ \|  _ \  / \|_   _| ____|  _ \
| |_) |  _|| |  | | | |  \| | \___ \| |_) || || | | |  _| | | | || | | | |_) | | | |/ _ \ | | |  _| | | | |
|  _ <| |__| |__| |_| | |\  |  ___) |  __/ | || |_| | |___| |_| || |_| |  __/| |_| / ___ \| | | |___| |_| |
|_| \_\_____\____\___/|_| \_| |____/|_|   |___|____/|_____|____/  \___/|_|   |____/_/   \_\_| |_____|____/
"""
    print(banner)
    print(f"{APP_NAME} v{APP_VERSION} | Target: {start_url}")
    print(f"Max pages: {max_pages} | Max text bytes: {max_text_bytes} | Verbose: {verbose}")
    print(f"Stream findings.jsonl: {stream_findings}")
    print("Features: normalized dedupe, asset scanning, confidence scoring, live progress")
    print("Press Ctrl+C to stop early.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ReconSpiderUpgraded")
    parser.add_argument("start_url", help="The starting URL for the web crawler")
    parser.add_argument(
        "--max-pages",
        type=int,
        default=1200,
        help="Max pages to scan (used for progress percentage and auto-stop)",
    )
    parser.add_argument(
        "--max-text-bytes",
        type=int,
        default=1500000,
        help="Skip scanning response bodies larger than this many bytes",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed Scrapy logs and per-page processing logs",
    )
    parser.add_argument(
        "--no-stream-findings",
        action="store_true",
        help="Disable incremental findings.jsonl output",
    )
    args = parser.parse_args()

    run_crawler(
        args.start_url,
        max_pages=args.max_pages,
        verbose=args.verbose,
        max_text_bytes=args.max_text_bytes,
        stream_findings=not args.no_stream_findings,
    )
