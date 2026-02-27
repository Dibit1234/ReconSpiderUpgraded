# ReconSpiderUpgraded

`ReconSpiderUpgraded` is a Scrapy-based reconnaissance crawler focused on surfacing potentially sensitive data in client-visible content.

It scans HTML pages, inline scripts, comments, query strings, and same-domain JS/CSS assets for:

- Emails
- IP addresses
- Usernames
- Password indicators
- API keys / tokens
- JWT tokens
- Private key markers

## Features

- URL normalization and deduplication
- Same-domain crawling with offsite protection
- Low-noise terminal mode with live progress
- Optional verbose logs (`--verbose`)
- Confidence-scored findings (`high`, `medium`, `low`)
- Explanatory finding reasons (why a match was flagged)
- Streaming findings to `findings.jsonl` during crawl
- Final structured output in `results.json`

## Requirements

- Python 3.9+
- Packages in `requirements.txt`

## Install

```bash
python -m venv .venv
. .venv/bin/activate  # Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

```bash
python ReconSpiderUpgraded.py https://example.com
```

Common options:

```bash
python ReconSpiderUpgraded.py https://example.com --max-pages 2000 --max-text-bytes 2000000
python ReconSpiderUpgraded.py https://example.com --verbose
python ReconSpiderUpgraded.py https://example.com --no-stream-findings
```

## Output

- `results.json`: aggregated results, findings with confidence and reasons, scan stats.
- `findings.jsonl`: incremental per-finding stream (unless disabled).

## Notes on Accuracy

No crawler can guarantee perfect detection. This tool improves recall/precision using layered pattern detection and scoring, but:

- Server-side secrets are not visible to crawlers.
- JS-rendered content may require browser automation.
- Obfuscation/minification can reduce signal quality.

Use findings for triage and follow-up validation.

## Legal and Ethical Use

Only scan systems you own or are explicitly authorized to test.

