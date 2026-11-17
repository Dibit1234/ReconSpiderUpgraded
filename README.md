# ReconSpiderUpgraded

A fast, bounded web crawler that finds secrets and information disclosure in client-visible content: HTML, inline scripts, same-site JS bundles, JSON, sourcemaps and response headers. It takes one target or a list of targets.

It reports:

- **Provider secrets:** about 60 signatures with structural validation, including AWS, GCP, Azure, GitHub (CRC32 checksum verified), GitLab, Slack, Stripe, SendGrid, Twilio, OpenAI, Anthropic, Telegram, Shopify, Vault, Datadog API/app keys, npm and PyPI.
- **Credentials:** hardcoded passwords, URL credentials (`mongodb+srv://user:pass@`, `https://user:pass@`), Basic auth headers (decoded) and pre-filled password inputs.
- **Tokens and keys:** JWTs (decoded and classified, e.g. Supabase `service_role` vs `anon`, expired) and private keys (body validated).
- **Disclosure:** internal IPs (including from response headers), target-domain and obfuscated emails, API endpoints, and exposed files and APIs (`--probe`).
- **Lookalike domains:** a domain in site content that is one typo away from one the site normally uses, e.g. a contact email at `realifecover.com.au` on sites that use `reallifecover.com.au`. Mail or visitors sent to the typo go elsewhere.
- **Downloaded files (`--files`, `--files-images`):** credentials and keys inside PDFs, Office/OpenDocument files, CSVs and ZIPs; account names, internal shares and hosts, people, GPS positions, devices and software versions from metadata. See [File analysis](#file-analysis---files).
- **Mock code in production bundles:** test-only mock API code (MSW, Mirage, axios-mock-adapter) shipped to the browser is flagged once per file. The fake tokens and IDs inside it are downgraded, not reported as secrets.

Public-by-design keys are reported as `info`, so they don't drown out real findings. Examples are Firebase/Maps browser keys, Stripe publishable keys, Supabase anon keys, Datadog RUM client tokens (`pub…`) and Sentry DSNs. Referenced cloud storage (S3, GCS, Azure Blob, Firebase) is listed as info for you to review.

## Install

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

ExifTool is optional but recommended for `--files-images` (`sudo apt install libimage-exiftool-perl`; Kali usually ships it). Without it, built-in parsers and Pillow (if installed) cover common EXIF, including GPS.

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
| `--files` | off | Download linked documents (PDF, Office, OpenDocument, RTF, CSV, ZIP, SVG) and analyse them offline |
| `--files-images` | off | Also download images (JPEG, PNG, TIFF, HEIC, WebP) for EXIF/XMP metadata |
| `--max-files` / `--max-images` | 100 / 150 | Per-target download caps |
| `--max-file-bytes` | 30 MB | Largest file downloaded |
| `--files-any-host` | off | Also download files hosted on other domains (CDNs). Off keeps downloads in scope |
| `--exiftool PATH` / `--no-exiftool` | PATH | ExifTool binary; versions before 12.38 are refused |
| `--delete-files` | off | Delete downloaded files after analysis |
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

## File analysis (`--files`)

With `--files`, linked documents are downloaded and parsed offline after the crawl. They are found via links, sitemaps, JS and JSON references. `--files-images` adds images found in `<img>`, `srcset` and `og:image`. Findings appear next to the web findings, pointing at the file URL, and `report.md` gets a "From downloaded files" section.

### What is extracted

| Format | Text | Metadata and structure |
|---|---|---|
| PDF | All pages (pypdf), including glyph-per-character exports | Author, Creator/Producer, XMP, link annotations, attachments, JavaScript flag |
| DOCX/XLSX/PPTX/VSDX (and macro variants) | Body, headers/footers, comments, tracked changes, speaker notes; spreadsheet rows as `Header: value` | Author, last modified by, company, template; external links (attached template, linked workbooks, hyperlinks); data connections (connection strings); comment/revision authors; hidden sheets; VBA macros |
| ODT/ODS/ODP | Body and tables (header-aware) | Creator, generator, printer name, Basic macros |
| DOC/XLS/PPT (legacy) | `.xls` rows via xlrd; `.doc`/`.ppt` text recovered as printable runs, with binary junk filtered out | ExifTool (author, company, template...), VBA flag |
| RTF, CSV, TXT, SVG | Plain text; CSV as `Header: value` | RTF `\info`, Inkscape export paths, SVG creator |
| ZIP | Text-like members (`.env`, configs, keys, scripts) and nested Office/PDF files, read in memory | Member list |
| JPEG/PNG/TIFF/WebP/HEIC | PNG text chunks | GPS, people, devices and serials, host computer, software |

Extracted text goes through the same detector as web content. It adds document-style credential patterns: `Password: Winter2026!`, "the admin password is …", `Password=` in connection strings, and table columns such as `Username | Password`.

### What metadata is kept

A survey of 395 real files in about 120 formats found that ExifTool returns about 44 values per file, nearly all of them noise: colour profiles, exposure settings, dimensions, and the downloaded copy's own local name, size and dates. Only these are kept:

| Kept | Reported as |
|---|---|
| Usernames in paths (`C:\Users\jsmith\…`, `/home/x/`), UNC shares (`\\fs01\finance`), internal hostnames/IPs, `HostComputer` | `low` findings |
| GPS position (photos) | `medium` finding with a map link |
| Data connections (server), macros, PDF JavaScript | `low` findings |
| People (author, last modified by, commenters, revision authors, photographer) | inventory |
| Companies, software and versions, devices and serial numbers | inventory |
| Titles, descriptions, comments, custom properties | scanned for secrets, not reported on their own |

People are separated from tools (`cairo 1.16`, `LibreOffice 24.2` go to the software list) and placeholders are dropped (`Microsoft Office User`, `Administrator`, `Artist`, `unknown`…).

### Safety model

Downloaded files are hostile input. ReconSpider never executes or opens them with another application, and doesn't run LibreOffice or any viewer on them:

- **What is downloaded:** only allow-listed document and image extensions are requested. `.exe` and scripts are never requested. Before anything is saved, the response is checked by magic bytes. Executables, scripts, unknown binaries and HTML (soft-404s and login pages served for a file URL) are discarded.
- **How it is stored:** files go to `<out>/<target>/files/` under a hash-based name with a `.quarantine` suffix and `0600` permissions. Nothing from the server goes into the filename, and nothing opens on a double-click.
- **How it is parsed:** in a separate Python process (`reconspider/extract.py`) with CPU (45 s), memory (2.5 GB), wall-clock (60 s) limits, a 0-byte file-size limit (it cannot write files) and an empty working directory. A parser hang or decompression bomb kills only that child.
- **Parsers:** pure Python (stdlib, plus optional pypdf, xlrd and Pillow). XML with entity declarations is refused (XXE, "billion laughs"). Archives are read in memory with size and compression-ratio caps and never extracted, so `../../` member names are harmless.
- **ExifTool:** run read-only. Versions before 12.38 are refused (CVE-2021-22204 code execution via malicious DjVu, CVE-2022-23935).

### Results

The planted corpus (`tests/file_corpus.py`) has 22 files. They include real LibreOffice conversions to PDF, ODT/ODS/ODP, DOC/XLS/PPT and RTF, decoy files and 7 hostile files:

| | Result |
|---|---|
| Planted findings | 26/26 |
| Decoy files / placeholder people | 0 findings / none |
| Raw bytes scanned directly vs extraction | 4 findings in 3 files vs 79 in 20 files |
| Hostile files (zip bomb, 1.2 GB PDF stream bomb, XXE, billion laughs, executable renamed `.pdf`, soft-404 `.pdf`, corrupt PDF) | all refused or parsed safely in 0.4 s; parent unaffected |
| Sandbox: 6 GB allocation / CPU spin / infinite sleep / write attempt | killed / killed / killed / 0 bytes written |

On 395 real-world files (ExifTool's multi-format samples plus system documents and images), metadata went from 12,327 values to 1,660 kept (13.5%). There were 7 findings at low or above, all true: 6 GPS positions and 1 Windows account name from a `.lnk` path. Raw binary scanning of the same files produced 1 junk value (an "IP" inside a binary), and only with `--entropy` enabled. Garbled binary is not where the false positives come from. Text hidden in compressed streams is what raw scanning misses.

Limitations:
- Scanned PDFs need OCR, which is not done.
- Encrypted documents are flagged, not opened.
- Legacy `.doc`/`.ppt` text recovery is heuristic.
- Documents behind authentication need `-H`/`--cookie`.

```bash
python tests/file_corpus.py /tmp/corpus && python tests/file_eval.py /tmp/corpus --real /path/to/files
```

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
