"""Optional post-crawl LLM triage for low/medium-confidence generic findings.

Runs after crawling (never blocks the crawl), on deduplicated findings only,
in a small thread pool. Fail-open: errors keep the finding.
Supports OpenAI-compatible /v1/chat/completions and Ollama /api/generate.
"""

import json
import re
from concurrent.futures import ThreadPoolExecutor
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

from .detect import GENERIC_RULES


def build_url(value):
    raw = (value or "").strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    p = urlparse(raw)
    if p.path and p.path != "/":
        return raw
    return raw.rstrip("/") + "/v1/chat/completions"


def _ask(url, model, prompt, timeout):
    if "/api/generate" in url:
        payload = {"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0, "num_predict": 3}}
    else:
        payload = {
            "model": model,
            "temperature": 0,
            "max_tokens": 3,
            "messages": [{"role": "system", "content": "Answer with exactly one word: yes or no."}, {"role": "user", "content": prompt}],
        }
    req = urlrequest.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", "ignore"))
    if "/api/generate" in url:
        answer = str(data.get("response", ""))
    else:
        choices = data.get("choices") or [{}]
        answer = str((choices[0].get("message") or {}).get("content", ""))
    tok = re.search(r"[a-z]+", answer.lower())
    if not tok:
        return None, answer
    if tok.group(0).startswith("yes"):
        return True, answer
    if tok.group(0).startswith("no"):
        return False, answer
    return None, answer


def _prompt(f):
    kind = {"credential": "a real hardcoded password/credential", "username": "a real account username"}.get(f["category"], "a real secret/API key/token (not a placeholder, hash, id or label)")
    return f"value: {f['value'][:200]} | context: {f.get('context', '')[:200]} | Is the value {kind}? Answer yes or no."


def triage(findings, endpoint, model, timeout=6.0, max_checks=0, validate_all=False, debug=False, workers=4):
    """Return (kept_findings, stats). Annotates checked findings with 'llm'."""
    url = build_url(endpoint)
    todo = [
        f
        for f in findings
        if f["severity"] != "info"
        and (validate_all or (f["rule"] in GENERIC_RULES or f["rule"] == "username") and f["confidence"] != "high")
    ]
    if max_checks > 0:
        todo = todo[:max_checks]
    stats = {"checked": 0, "yes": 0, "no": 0, "errors": 0}
    verdicts = {}

    def run(f):
        try:
            v, raw = _ask(url, model, _prompt(f), timeout)
        except (urlerror.URLError, OSError, ValueError, TimeoutError) as exc:
            v, raw = None, f"error: {exc}"
        if debug:
            print(f"[LLM] {f['rule']} {f['value'][:60]!r} -> {raw.strip()[:40]!r}")
        return id(f), v

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fid, v in pool.map(run, todo):
            verdicts[fid] = v
            stats["checked"] += 1
            stats["yes" if v else "no" if v is False else "errors"] += 1

    kept = []
    for f in findings:
        v = verdicts.get(id(f), "unchecked")
        if v is False:
            continue
        if v != "unchecked":
            f["llm"] = "yes" if v else "error"
        kept.append(f)
    return kept, stats
