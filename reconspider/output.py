"""Result writers: per-target JSON, combined summary JSON, Markdown report."""

import json
import os
import re
import sys
import time

from .rules import SEVERITIES, SEVERITY_RANK

CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def slug(target):
    s = re.sub(r"^https?://", "", target).rstrip("/")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:120] or "target"


def redact(value):
    if not isinstance(value, str) or len(value) <= 12:
        return "****" if isinstance(value, str) else value
    return f"{value[:4]}…{value[-4:]}"


def sort_key(f):
    return (SEVERITY_RANK.get(f["severity"], 9), CONF_RANK.get(f["confidence"], 9), f["rule"], f["value"])


def prepare(findings, do_redact=False):
    out = []
    for f in sorted(findings, key=sort_key):
        f = dict(f)
        if do_redact and f["category"] not in {"email", "ip", "exposure"}:
            raw = f["value"]
            f["value"] = redact(raw)
            if f.get("context"):
                f["context"] = f["context"].replace(raw, f["value"])
            if "extra" in f:
                f["extra"] = {k: (redact(v) if k in {"password", "decoded"} else v) for k, v in f["extra"].items()}
        out.append(f)
    return out


def counts(findings):
    by_sev = {s: 0 for s in SEVERITIES}
    by_cat = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    return by_sev, by_cat


def target_result(spider, opts, reason):
    findings = list(spider.findings.values())
    by_sev, by_cat = counts(findings)
    st = dict(spider.stats)
    st["elapsed_seconds"] = round(time.time() - spider.start_ts, 2)
    st["scan_seconds"] = round(st["scan_seconds"], 2)
    res = {
        "target": spider.target,
        "close_reason": reason,
        "start_error": None if spider.start_ok else spider.start_error,
        "redirected_offsite_to": spider.redirected_to,
        "summary": {"by_severity": by_sev, "by_category": by_cat, "total": len(findings)},
        "stats": st,
        "filtered_candidates": dict(spider.det.rejections.most_common(40)),
        "findings": prepare(findings, opts.redact),
        "endpoints": sorted(spider.endpoints),
        "js_files": sorted(spider.js_files),
    }
    if opts.include_urls:
        res["crawled_urls"] = spider.crawled_urls
        res["form_fields"] = sorted(spider.form_fields)
    if opts.include_comments:
        res["comments"] = sorted(spider.comments)
    return res


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, path)


def write_target(out_dir, result):
    d = os.path.join(out_dir, slug(result["target"]))
    os.makedirs(d, exist_ok=True)
    write_json(os.path.join(d, "results.json"), result)
    return d


def write_summary(out_dir, results, started, opts):
    all_f = [dict(f, target=r["target"]) for r in results for f in r["findings"]]
    by_sev, by_cat = counts(all_f)
    summary = {
        "started": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(started)),
        "elapsed_seconds": round(time.time() - started, 2),
        "targets": [
            {
                "target": r["target"],
                "total": r["summary"]["total"],
                "by_severity": r["summary"]["by_severity"],
                "pages": r["stats"]["pages_fetched"],
                "assets": r["stats"]["assets_fetched"],
                "elapsed_seconds": r["stats"]["elapsed_seconds"],
                "close_reason": r["close_reason"],
                "start_error": r.get("start_error"),
                "redirected_offsite_to": r["redirected_offsite_to"],
                "results": os.path.join(slug(r["target"]), "results.json"),
            }
            for r in results
        ],
        "by_severity": by_sev,
        "by_category": by_cat,
        "findings": sorted(all_f, key=sort_key),
    }
    write_json(os.path.join(out_dir, "summary.json"), summary)
    write_markdown(os.path.join(out_dir, "report.md"), summary)
    return summary


def _md_escape(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def write_markdown(path, summary):
    lines = ["# ReconSpider report", "", f"Started {summary['started']} · {summary['elapsed_seconds']}s · {len(summary['targets'])} target(s)", ""]
    lines += ["| Target | Pages | Assets | Crit | High | Med | Low | Info | Time (s) |", "|---|---|---|---|---|---|---|---|---|"]
    for t in summary["targets"]:
        s = t["by_severity"]
        lines.append(f"| {_md_escape(t['target'])} | {t['pages']} | {t['assets']} | {s['critical']} | {s['high']} | {s['medium']} | {s['low']} | {s['info']} | {t['elapsed_seconds']} |")
    for sev in SEVERITIES:
        items = [f for f in summary["findings"] if f["severity"] == sev]
        if not items:
            continue
        lines += ["", f"## {sev.capitalize()} ({len(items)})", "", "| Finding | Value | Confidence | Where | Target |", "|---|---|---|---|---|"]
        for f in items[:500]:
            lines.append(
                f"| {_md_escape(f['title'])} | `{_md_escape(f['value'][:90])}` | {f['confidence']} | {_md_escape(f['url'][:100])} | {_md_escape(f['target'])} |"
            )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- #
# Terminal
# --------------------------------------------------------------------------- #

ANSI = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m", "reset": "\033[0m", "green": "\033[32m", "dim": "\033[2m", "bold": "\033[1m"}


def color(text, key, enabled=None):
    enabled = sys.stdout.isatty() if enabled is None else enabled
    return f"{ANSI[key]}{text}{ANSI['reset']}" if enabled else text


def print_findings_table(findings, min_sev="low", limit=60):
    shown = [f for f in sorted(findings, key=sort_key) if SEVERITY_RANK[f["severity"]] <= SEVERITY_RANK[min_sev]]
    if not shown:
        print("No findings at or above", min_sev)
        return
    for f in shown[:limit]:
        sev = color(f"{f['severity'].upper():8}", f["severity"])
        val = f["value"] if len(f["value"]) <= 70 else f["value"][:67] + "..."
        where = f.get("url", "")
        where = where if len(where) <= 60 else "…" + where[-59:]
        print(f"  {sev} {f['title'][:38]:38} {val:70} {color(f['confidence'], 'dim'):6}  {where}")
    if len(shown) > limit:
        print(f"  ... {len(shown) - limit} more in summary.json / report.md")
