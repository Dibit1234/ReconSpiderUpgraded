# ReconSpiderUpgraded

A fast, bounded web crawler that finds secrets and information disclosure in client-visible content: HTML, inline scripts, same-site JS bundles, JSON, sourcemaps and response headers. It takes one target or a list of targets.

It reports:

- **Provider secrets:** about 60 signatures with structural validation, including AWS, GCP, Azure, GitHub (CRC32 checksum verified), GitLab, Slack, Stripe, SendGrid, Twilio, OpenAI, Anthropic, Telegram, Shopify, Vault, Datadog API/app keys, npm and PyPI.
- **Credentials:** hardcoded passwords, URL credentials (`mongodb+srv://user:pass@`, `https://user:pass@`), Basic auth headers (decoded) and pre-filled password inputs.
- **Tokens and keys:** JWTs (decoded and classified, e.g. Supabase `service_role` vs `anon`, expired) and private keys (body validated).
- **Disclosure:** internal IPs (including from response headers), target-domain and obfuscated emails, API endpoints, and exposed files and APIs (`--probe`).
- **Lookalike domains:** a domain in site content that is one typo away from one the site normally uses, e.g. a contact email at `realifecover.com.au` on sites that use `reallifecover.com.au`. Mail or visitors sent to the typo go elsewhere.
- **Mock code in production bundles:** test-only mock API code (MSW, Mirage, axios-mock-adapter) shipped to the browser is flagged once per file. The fake tokens and IDs inside it are downgraded, not reported as secrets.

Public-by-design keys are reported as `info`, so they don't drown out real findings. Examples are Firebase/Maps browser keys, Stripe publishable keys, Supabase anon keys, Datadog RUM client tokens (`pub…`) and Sentry DSNs. Referenced cloud storage (S3, GCS, Azure Blob, Firebase) is listed as info for you to review.

## Install

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

```bash
python ReconSpiderUpgraded.py https://example.com
```

```bash
python ReconSpiderUpgraded.py -l targets.txt -p 4
```

```bash
cat hosts.txt | python ReconSpiderUpgraded.py - --probe
```

```bash
python ReconSpiderUpgraded.py https://app.example.com -H "Authorization: Bearer eyJ..." --cookie "session=abc" --proxy http://127.0.0.1:8080
```

Target lists accept full URLs or bare `host[:port]`, one per line, with `#` comments. URLs on the same host (ignoring `www.`) are merged into one target with several start pages, so a list of 30 landing pages on one site is crawled once and each finding is reported once (`--no-merge-hosts` turns this off). Duplicates and invalid entries are dropped. For bare hosts, https is tried first and http is used as a fallback. Unreachable targets are reported and don't stall the run.

### Key options

| Option | Default | Purpose |
|---|---|---|
| `-p, --parallel` | 3 | Targets crawled at once |
| `-c, --concurrency` | 16 | Concurrent requests per target |
| `--max-pages` | 300 | HTML pages per target |
| `--max-assets` | 400 | JS/JSON/sourcemap requests per target |
| `--max-depth` | 4 | Link depth from the start page |
| `--max-time` | 300 | Hard time limit per target (s), `0` = none |
| `--max-per-template` | 8 | Pages per URL template (`/blog/{slug}`, `/item/{n}`); stops spider traps |
| `--include-subdomains` | off | Also crawl other subdomains of the target's domain that are linked or referenced in JS |
| `--max-subdomains` | 15 | Cap on extra subdomains crawled per target |
| `--probe` | off | ~90 GET checks with content validation and soft-404 detection: `.env` variants, `.git`/`.svn`/`.DS_Store`, config backups, OpenAPI/Swagger, GraphQL (incl. introspection), Spring actuator, WordPress user listing, ELMAH/trace, phpinfo, permissive crossdomain policies, and config-style API endpoints found in JS |
| `--probe-sourcemaps` | off | Request `<script>.map` even when not referenced |
| `--entropy` | off | Also report unnamed high-entropy JS strings (noisier) |
| `--ignore REGEX` / `--ignore-file` | | Suppress known-benign values or URLs |
| `--redact` | off | Mask secret values in output files |
| `--delay`, `--polite` | | Slow down for fragile targets |
| `-H`, `--cookie`, `--proxy` | | Authenticated crawling / route through Burp. Your own header and cookie values are never reported. |
| `--min-severity` | low | Lowest severity printed in the terminal (files always contain everything) |

Run `--help` for the full list. The optional local-LLM triage (`--llm`, `--llm-model`) still exists. It now runs after the crawl, only on low and medium confidence generic findings, and keeps a finding if the LLM call errors.

## How discovery works

The crawl starts from the given page and expands breadth-first, so the site's sections are covered before deep pagination. It also:

- Seeds from `robots.txt` (Disallow/Allow paths) and sitemaps (`sitemap.xml`, `sitemap_index.xml`, `wp-sitemap.xml`, indexes and `.gz`).
- Reads build manifests that list every JS chunk: CRA `asset-manifest.json`, Vite `.vite/manifest.json`, and Next.js `_buildManifest.js` (found via `__NEXT_DATA__.buildId`), which also lists page routes that may not be linked anywhere.
- Rebuilds lazy-loaded webpack chunk URLs from the runtime's chunk map (`"static/js/"+e+"."+{345:"9f8e7d6c"}[e]+".chunk.js"`). These chunks never appear as literal paths.
- Follows `a`, `area`, `iframe`, `form action`, `link`, meta-refresh, `data-*-url`/`data-href` attributes and JS navigation (`location.href = '/x'`, `router.push`, `window.open`).
- Follows `<script src>` and `modulepreload` scripts, JS/JSON paths referenced inside JS, and same-site page URLs found in JS.
- Records every subdomain and external host the site references (`discovered_hosts`, `external_hosts` in results).
- Follows `sourceMappingURL` and `SourceMap` headers, including inline `data:` maps, and scans the original sources with `node_modules` skipped.
- Skips state-changing links (`/logout`, `/delete`...), binary and media files, and stylesheets.

## Speed, deduplication and bounding

- **Request dedupe:** URLs are canonicalised (scheme/host case, default ports, tracking params, param order, trailing slash, `http`/`https` and `www.` variants). Assets also ignore cache-busters, so `app.js?v=1` and `app.js?v=2` count as one fetch.
- **Content dedupe:** identical bodies are scanned once (SHA-1). Inline scripts are hashed individually. HTML is deduped per line, so repeated header, footer and nav markup is only scanned on the first page.
- **Trap control:** per-URL-template caps (IDs, dates and slugs like `oak-chair-123` collapse to one pattern, and a folder with more than 25 distinct children is treated as one variable), repeated-segment and URL-length limits, and depth limits.
- **Hard budgets per target:** pages, assets, download size and wall-clock time.
- **Cross-target dedupe:** a finding seen on several targets is written once to `findings.jsonl` and listed once in `summary.json` with every target it appeared on.
- **Bulk lists collapse:** a file with dozens of IPs (blocklists, allowlists) becomes one finding with a count and sample.
- **Fast scanning:** keyword prefilters skip rules whose vendor prefix is absent, and generic and email detection is anchor-first instead of full-text backtracking regexes.

## Output

Each run writes to `-o DIR` (default `recon-<timestamp>/`):

- `summary.json`: all targets and all findings (merged across targets), sorted by severity, plus an `inventory` of discovered subdomains and shared bundles.
- `report.md`: a per-target table, findings grouped by severity, discovered hosts, and identical hashed JS bundles served by several targets (one codebase behind several brands, so one bug likely affects all of them).
- `findings.jsonl`: streamed while crawling.
- `<target>/results.json`: findings, plus the following:
  - each finding with `rule`, `severity`, `confidence`, `value`, `url`, `source`, `context`, `reasons`, `occurrences` and `locations`;
  - discovered API endpoints and JS files;
  - crawl stats;
  - `filtered_candidates`, which records why candidates were rejected (useful for tuning).

> **Breaking change from v3:** results are now written to an output directory, with a flat findings list per target, instead of `results.json` and `findings.jsonl` in the working directory.

## Accuracy

`tests/fixture_site.py` is a labelled site with 37 planted findings and 33 decoys that commonly fool scanners, including the real-world false-positive shapes behind v4.1 (Datadog RUM tokens, `http://mailto:` links, MSW mock bundles, header-only JWTs, IP lists). It also contains spider traps, a soft-404 catch-all, a lazy webpack chunk, a Next.js route only listed in the build manifest, a sitemap-index-only page and links hidden in `data-*`/`onclick`. `tests/bench.py` scores a run against it. Separately, about 56 MB of popular npm libraries were scanned, where every finding is a false positive.

| | v3 | v4.1 |
|---|---|---|
| Fixture recall (v4 set of 26) | 9/26* | 26/26 |
| Fixture recall (full v4.1 set) | n/a | 37/37 (41/41 with `--probe`) |
| Fixture false positives / decoys reported | 58 / 14 | 0 / 0 |
| Library-code false positives (1,808 files) | 298 | 3** |
| Scan throughput | 1.5 MB/s | 3.4 MB/s |
| Large e-commerce site, 1,200-page budget | 48 s (skipped the 2 MB bundle) | 4 s: finishes at 210 pages covering every section, 7,376 repeat product/pagination pages skipped |

\* With its crash patched. Unpatched, v3 stopped after the first page, because of a missing `_looks_like_text_phrase` method.
\*\* Real hardcoded test credentials in amazon-cognito's `__tests__` folder.

```bash
python -m pytest -q
```

```bash
python tests/bench.py --old path/to/previous/ReconSpiderUpgraded.py
```

No crawler sees server-side secrets, and pages rendered purely by JS may need a browser. Treat findings as leads to validate.

## Legal and ethical use

Only scan systems you own or are explicitly authorised to test.
