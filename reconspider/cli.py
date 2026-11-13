"""Command line entry point and multi-target runner."""

import argparse
import json
import os
import random
import re
import signal
import sys
import time
from types import SimpleNamespace
from urllib.parse import urlparse

from . import APP_NAME, APP_VERSION
from .output import color, print_findings_table, target_result, write_summary, write_target

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
UA_POOL = [
    DEFAULT_UA,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
]


class RequestDecorator:
    """Downloader middleware: UA, extra headers, cookies, proxy."""

    def __init__(self, settings):
        self.ua = settings.get("RS_USER_AGENT") or DEFAULT_UA
        self.random_ua = settings.getbool("RS_RANDOM_UA")
        self.headers = settings.getdict("RS_HEADERS")
        self.cookie = settings.get("RS_COOKIE") or ""
        self.proxy = settings.get("RS_PROXY") or ""

    @classmethod
    def from_crawler(cls, crawler):
        return cls(crawler.settings)

    def process_request(self, request, spider=None):
        request.headers["User-Agent"] = random.choice(UA_POOL) if self.random_ua else self.ua
        request.headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        request.headers.setdefault("Accept-Language", "en-US,en;q=0.9")
        for k, v in self.headers.items():
            request.headers[k] = v
        if self.cookie:
            request.headers["Cookie"] = self.cookie
        if self.proxy:
            request.meta["proxy"] = self.proxy
        return None


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #


def normalize_target(raw):
    """Return (url, scheme_assumed) or None."""
    t = raw.strip()
    if not t or t.startswith("#"):
        return None
    t = t.split()[0].rstrip(",;")
    assumed = not re.match(r"^https?://", t, re.I)
    if assumed:
        if "://" in t:
            return None  # ftp:// etc.
        t = "https://" + t
    p = urlparse(t)
    try:
        p.port
    except ValueError:
        return None
    if not p.hostname:
        return None
    return (t if p.path else t + "/"), assumed


def load_targets(args, merge=True):
    raw = list(args.targets or [])
    for path in args.list or []:
        fh = sys.stdin if path == "-" else open(path, encoding="utf-8")
        with fh:
            raw.extend(fh.read().splitlines())
    if "-" in raw:
        raw.remove("-")
        raw.extend(sys.stdin.read().splitlines())
    """Return [(primary_url, scheme_assumed, [extra seed urls])].

    URLs on the same host (ignoring www.) and port become ONE target with
    several seed pages, so a list of 30 landing pages on one site is crawled
    once and each finding is reported once.
    """
    groups, order = {}, []
    for r in raw:
        nt = normalize_target(r)
        if not nt:
            if r.strip() and not r.strip().startswith("#"):
                print(f"[!] skipping invalid target {r.strip()!r}", file=sys.stderr)
            continue
        t, assumed = nt
        p = urlparse(t)
        host = (p.hostname or "").lower()
        bare = host[4:] if host.startswith("www.") else host
        key = (bare, p.port) if merge else (bare, p.port, p.path.rstrip("/") or "/", p.query)
        g = groups.get(key)
        if g is None:
            groups[key] = g = {"primary": t, "assumed": assumed, "seeds": [], "seen": {p.path.rstrip("/") + "?" + p.query}}
            order.append(key)
            continue
        sig = p.path.rstrip("/") + "?" + p.query
        if sig in g["seen"]:
            continue
        g["seen"].add(sig)
        g["seeds"].append(t)
    return [(groups[k]["primary"], groups[k]["assumed"], groups[k]["seeds"]) for k in order]


# --------------------------------------------------------------------------- #
# Args
# --------------------------------------------------------------------------- #


def build_parser():
    p = argparse.ArgumentParser(
        prog="ReconSpiderUpgraded",
        description="Crawl one or more web targets and report client-side secrets, credentials, tokens, internal IPs and emails.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("targets", nargs="*", help="Target URLs or hosts (https:// assumed). Use - to read from stdin.")
    p.add_argument("-l", "--list", action="append", metavar="FILE", help="File with one target per line (# comments allowed). Repeatable. '-' = stdin.")
    p.add_argument("-o", "--output", default="", help="Output directory (default: recon-<timestamp>)")

    g = p.add_argument_group("scope and budgets (per target)")
    g.add_argument("--max-pages", type=int, default=300, help="Max HTML pages per target")
    g.add_argument("--max-assets", type=int, default=400, help="Max JS/JSON/sourcemap requests per target")
    g.add_argument("--max-depth", type=int, default=4, help="Max link depth from the start page")
    g.add_argument("--max-time", type=int, default=300, help="Hard time limit per target in seconds (0 = none)")
    g.add_argument("--max-per-template", type=int, default=8, help="Max pages per URL template (/blog/{slug}, /item/{n}) - stops spider traps")
    g.add_argument("--include-subdomains", action="store_true", help="Also crawl other subdomains of the target's domain that are linked or referenced in JS")
    g.add_argument("--max-subdomains", type=int, default=15, help="With --include-subdomains: max extra subdomains seeded per target")
    g.add_argument("--no-merge-hosts", action="store_true", help="Crawl each listed URL as its own target even when several share a host")
    g.add_argument("--no-seed", dest="seed", action="store_false", help="Don't seed the crawl from robots.txt and sitemap.xml")
    g.add_argument("--max-text-bytes", type=int, default=3_000_000, help="Max HTML page size to download")
    g.add_argument("--max-asset-bytes", type=int, default=8_000_000, help="Max JS/JSON size to download")
    g.add_argument("--max-map-bytes", type=int, default=25_000_000, help="Max sourcemap size to download")

    g = p.add_argument_group("discovery extras")
    g.add_argument("--probe", action="store_true", help="Request commonly exposed files and APIs (/.env, /.git, OpenAPI/Swagger, GraphQL, Spring actuator, WP users, config endpoints) with soft-404 detection")
    g.add_argument("--probe-sourcemaps", action="store_true", help="Request <script>.map for first-party JS even when not referenced")
    g.add_argument("--include-vendor", action="store_true", help="Also scan node_modules/vendor sources inside sourcemaps")

    g = p.add_argument_group("detection")
    g.add_argument("--entropy", action="store_true", help="Also report unnamed high-entropy string literals in JS (noisier, low confidence)")
    g.add_argument("--no-signature-api-keys", dest="signatures", action="store_false", help="Disable provider signature rules")
    g.add_argument("--signature-api-keys", dest="signatures", action="store_true", help=argparse.SUPPRESS)
    g.add_argument("--ignore", action="append", default=[], metavar="REGEX", help="Suppress findings whose value or URL matches REGEX. Repeatable.")
    g.add_argument("--ignore-file", metavar="FILE", help="File of suppression regexes, one per line")
    g.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"], default="low", help="Lowest severity printed to the terminal (all are written to files)")
    g.add_argument("--redact", action="store_true", help="Mask secret values in output files")

    g = p.add_argument_group("HTTP")
    g.add_argument("-c", "--concurrency", type=int, default=16, help="Concurrent requests per target")
    g.add_argument("-p", "--parallel", type=int, default=3, help="Targets crawled at the same time")
    g.add_argument("--delay", type=float, default=0.0, help="Delay between requests to the same target (seconds)")
    g.add_argument("--polite", action="store_true", help="Enable AutoThrottle (slower, gentler on fragile targets)")
    g.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout")
    g.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'", help="Extra request header (e.g. for authenticated crawling). Repeatable.")
    g.add_argument("--cookie", default="", help="Cookie header value for authenticated crawling")
    g.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080 for Burp")
    g.add_argument("--user-agent", default="", help="Custom User-Agent")
    g.add_argument("--random-user-agent", action="store_true", help="Rotate common browser User-Agents")

    g = p.add_argument_group("output")
    g.add_argument("--no-stream-findings", action="store_true", help="Don't write findings.jsonl while crawling")
    g.add_argument("--include-urls", action="store_true", help="Include crawled URLs and form field names in results.json")
    g.add_argument("--include-comments", action="store_true", help="Include HTML comments in results.json")
    g.add_argument("--include-external", action="store_true", help=argparse.SUPPRESS)
    g.add_argument("-q", "--quiet", action="store_true", help="No progress line")
    g.add_argument("--verbose", action="store_true", help="Scrapy logging")

    g = p.add_argument_group("optional LLM triage (post-crawl, low/medium generic findings only)")
    g.add_argument("-llm", "--llm", default="", help="OpenAI-compatible endpoint or host:port (Ollama /api/generate also supported)")
    g.add_argument("--llm-model", default="")
    g.add_argument("--llm-timeout", type=float, default=6.0)
    g.add_argument("--llm-max-checks", type=int, default=0, help="0 = unlimited")
    g.add_argument("--llm-validate-all", action="store_true", help="Also check high-confidence and provider findings")
    g.add_argument("--no-llm-relaxed", action="store_true", help=argparse.SUPPRESS)
    g.add_argument("--test", "--llm-debug", dest="llm_debug", action="store_true", help="Print LLM prompts/answers")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    return p


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.llm and not args.llm_model:
        parser.error("--llm-model is required when --llm is provided")
    targets = load_targets(args, merge=not args.no_merge_hosts)
    if not targets:
        parser.error("no targets given (positional, -l FILE, or - for stdin)")

    headers = {}
    for h in args.header:
        if ":" not in h:
            parser.error(f"bad header {h!r}, expected 'Name: value'")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    ignore = list(args.ignore)
    if args.ignore_file:
        with open(args.ignore_file, encoding="utf-8") as fh:
            ignore += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    for rx in ignore:
        try:
            re.compile(rx)
        except re.error as exc:
            parser.error(f"bad --ignore regex {rx!r}: {exc}")
    # Never report the credentials we were given ourselves.
    suppress = [v for v in headers.values()] + [c.split("=", 1)[-1] for c in args.cookie.split(";") if "=" in c]
    suppress += [v.split()[-1] for v in headers.values() if " " in v]

    out_dir = args.output or time.strftime("recon-%Y%m%d-%H%M%S")
    os.makedirs(out_dir, exist_ok=True)

    opts = SimpleNamespace(
        max_pages=max(1, args.max_pages), max_assets=max(0, args.max_assets), max_depth=max(0, args.max_depth),
        max_per_template=max(1, args.max_per_template), include_subdomains=args.include_subdomains, seed=args.seed,
        max_text_bytes=args.max_text_bytes, max_asset_bytes=args.max_asset_bytes, max_map_bytes=args.max_map_bytes,
        probe=args.probe, probe_sourcemaps=args.probe_sourcemaps, include_vendor=args.include_vendor,
        max_subdomains=max(0, args.max_subdomains),
        entropy=args.entropy, signatures=args.signatures, ignore_patterns=ignore, suppress_values=suppress,
        redact=args.redact, include_urls=args.include_urls, include_comments=args.include_comments,
    )
    return run(targets, opts, args, headers, out_dir)


def run(targets, opts, args, headers, out_dir):
    from scrapy.utils.reactor import install_reactor

    install_reactor("twisted.internet.asyncioreactor.AsyncioSelectorReactor")
    from scrapy.crawler import CrawlerProcess

    from .crawl import TargetSpider

    tty = sys.stdout.isatty() and not args.quiet
    settings = {
        "DOWNLOADER_MIDDLEWARES": {"reconspider.cli.RequestDecorator": 390},
        "RS_USER_AGENT": args.user_agent,
        "RS_RANDOM_UA": args.random_user_agent,
        "RS_HEADERS": headers,
        "RS_COOKIE": args.cookie,
        "RS_PROXY": args.proxy,
        "USER_AGENT": args.user_agent or DEFAULT_UA,
        "ROBOTSTXT_OBEY": False,
        "COOKIES_ENABLED": True,
        "CONCURRENT_REQUESTS": max(1, args.concurrency) * max(1, args.parallel),
        "CONCURRENT_REQUESTS_PER_DOMAIN": max(1, args.concurrency),
        "DOWNLOAD_DELAY": args.delay,
        "RANDOMIZE_DOWNLOAD_DELAY": True,
        "AUTOTHROTTLE_ENABLED": args.polite,
        "AUTOTHROTTLE_START_DELAY": 0.5,
        "AUTOTHROTTLE_TARGET_CONCURRENCY": 4.0,
        "DOWNLOAD_TIMEOUT": args.timeout,
        "RETRY_TIMES": 1,
        "REDIRECT_MAX_TIMES": 5,
        "DOWNLOAD_MAXSIZE": max(args.max_text_bytes, args.max_asset_bytes, args.max_map_bytes),
        "DOWNLOAD_WARNSIZE": 0,
        "DOWNLOAD_FAIL_ON_DATALOSS": False,
        "DEPTH_LIMIT": 0,
        "DEPTH_PRIORITY": 0,
        "CLOSESPIDER_TIMEOUT": max(0, args.max_time),
        "TELNETCONSOLE_ENABLED": False,
        "LOGSTATS_INTERVAL": 0,
        "DNSCACHE_ENABLED": True,
        "REACTOR_THREADPOOL_MAXSIZE": 20,
        "LOG_ENABLED": args.verbose,
        "LOG_LEVEL": "INFO" if args.verbose else "ERROR",
        "REQUEST_FINGERPRINTER_IMPLEMENTATION": "2.7",
    }
    settings["LOG_INSTALL_ROOT_HANDLER"] = args.verbose
    settings["TWISTED_REACTOR"] = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
    if not args.verbose:
        import logging
        import warnings

        warnings.filterwarnings("ignore", module="scrapy")
        logging.getLogger("scrapy").setLevel(logging.ERROR)
        logging.getLogger("twisted").setLevel(logging.ERROR)
        logging.getLogger("py.warnings").setLevel(logging.ERROR)

    started = time.time()
    stream = None if args.no_stream_findings else open(os.path.join(out_dir, "findings.jsonl"), "w", encoding="utf-8")
    from .output import prepare

    streamed = set()

    def sink(spider, finding):
        key = (finding["rule"], finding["value"])
        if key in streamed:
            return  # same finding already written for another target
        streamed.add(key)
        if stream:
            row = prepare([finding], opts.redact)[0]
            row = {k: v for k, v in row.items() if k not in {"occurrences", "locations"}}
            row["target"] = spider.target
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
            stream.flush()

    process = CrawlerProcess(settings)
    from twisted.internet import defer, reactor, task

    sem = defer.DeferredSemaphore(max(1, args.parallel))
    state = {"stopping": False, "active": [], "done": 0, "results": []}

    if tty:
        print(color(f"{APP_NAME} v{APP_VERSION}", "bold"), f"| {len(targets)} target(s) | parallel={args.parallel} c={args.concurrency} "
              f"| per-target: pages≤{opts.max_pages} assets≤{opts.max_assets} depth≤{opts.max_depth} time≤{args.max_time}s | out={out_dir}")

    def finish_target(result, crawler):
        from twisted.python.failure import Failure

        if isinstance(result, Failure):
            print(f"\n[!] crawl error: {result.getErrorMessage()}", file=sys.stderr)
            if args.verbose:
                print(result.getTraceback(), file=sys.stderr)
        spider = getattr(crawler, "spider", None)
        if spider in state["active"]:
            state["active"].remove(spider)
        state["done"] += 1
        if spider is None:
            return
        reason = (crawler.stats.get_value("finish_reason") if crawler.stats else None) or "finished"
        res = target_result(spider, opts, reason)
        write_target(out_dir, res)
        state["results"].append(res)
        s = res["summary"]["by_severity"]
        line = (f"[{state['done']}/{len(targets)}] {spider.target}  pages={spider.stats['pages_fetched']} assets={spider.stats['assets_fetched']} "
                f"{res['stats']['elapsed_seconds']}s  crit={s['critical']} high={s['high']} med={s['medium']} low={s['low']} info={s['info']}"
                + (f"  (redirected off-site to {spider.redirected_to})" if spider.redirected_to else "")
                + (f"  UNREACHABLE: {spider.start_error}" if not spider.start_ok and spider.start_error else "")
                + (f"  [{reason}]" if reason not in {"finished"} else ""))
        if tty:
            sys.stdout.write("\r\033[2K")
        print(line)
        sys.stdout.flush()

    def crawl_one(target):
        if state["stopping"]:
            return defer.succeed(None)
        url, assumed, seeds = target
        crawler = process.create_crawler(TargetSpider)
        d = process.crawl(crawler, target=url, opts=opts, sink=sink, scheme_assumed=assumed, extra_seeds=seeds)
        # spider exists once crawl() has started
        reactor.callLater(0, lambda: state["active"].append(crawler.spider) if getattr(crawler, "spider", None) else None)
        d.addBoth(finish_target, crawler)
        return d

    def progress():
        if not tty:
            return
        act = [s for s in state["active"] if s is not None]
        parts = [f"{urlparse(s.target).hostname}:{s.stats['pages_fetched']}p/{s.stats['assets_fetched']}a/{len(s.findings)}f" for s in act[:4]]
        line = f"  {state['done']}/{len(targets)} done | {int(time.time() - started)}s | " + "  ".join(parts)
        sys.stdout.write("\r\033[2K" + line[: os.get_terminal_size().columns - 1])
        sys.stdout.flush()

    ticker = task.LoopingCall(progress)

    def all_done(_):
        if ticker.running:
            ticker.stop()
        reactor.callWhenRunning(lambda: reactor.running and reactor.stop())

    def launch():
        deferreds = [sem.run(crawl_one, t) for t in targets]
        defer.DeferredList(deferreds, consumeErrors=True).addBoth(all_done)

    reactor.callWhenRunning(launch)

    def on_sigint(signum, frame):
        if not state["stopping"]:
            state["stopping"] = True
            sys.stdout.write("\nCtrl+C: stopping crawls and writing results (press again to abort)...\n")
            sys.stdout.flush()
            reactor.callFromThread(lambda: [c.stop() for c in list(process.crawlers)])
        else:
            reactor.callFromThread(reactor.stop)

    prev = signal.signal(signal.SIGINT, on_sigint)
    try:
        if tty:
            reactor.callWhenRunning(ticker.start, 0.5, False)
        process.start(stop_after_crawl=False, install_signal_handlers=False)
    finally:
        signal.signal(signal.SIGINT, prev)
        if stream:
            stream.close()

    results = state["results"]
    if args.llm and results:
        from .llm import triage

        print(f"LLM triage via {args.llm} ({args.llm_model}) ...")
        for res in results:
            kept, st = triage(res["findings"], args.llm, args.llm_model, args.llm_timeout, args.llm_max_checks, args.llm_validate_all, args.llm_debug)
            res["findings"] = kept
            res["llm"] = st
            from .output import counts

            by_sev, by_cat = counts(kept)
            res["summary"] = {"by_severity": by_sev, "by_category": by_cat, "total": len(kept)}
            write_target(out_dir, res)
            print(f"  {res['target']}: checked={st['checked']} kept={st['yes']} dropped={st['no']} errors={st['errors']}")

    from .domains import inventory, lookalike_findings

    extra = lookalike_findings(results)
    inv = inventory(results)
    summary = write_summary(out_dir, results, started, opts, extra_findings=extra, inventory=inv)
    if inv["shared_bundles"]:
        top = inv["shared_bundles"][0]
        print(f"Shared build: {top[0]} served by {len(top[1])} hosts (see report.md)")
    if inv["subdomains"]:
        print(f"Discovered {len(inv['subdomains'])} other host(s) on target domains (summary.json -> inventory.subdomains)")
    print()
    print(color("Findings", "bold"), f"(≥{args.min_severity}; everything is in {out_dir}/summary.json and report.md)")
    print_findings_table(summary["findings"], min_sev=args.min_severity)
    sev = summary["by_severity"]
    print(f"\nTotal: crit={sev['critical']} high={sev['high']} med={sev['medium']} low={sev['low']} info={sev['info']} "
          f"| {len(results)}/{len(targets)} targets | {summary['elapsed_seconds']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
