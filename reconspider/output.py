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
        "start_urls": [spider.target] + list(spider.extra_seeds),
        "endpoints": sorted(spider.endpoints),
        "js_files": sorted(spider.js_files),
        "files": getattr(spider, "file_records", []),
        "file_inventory": getattr(spider, "file_inventory", {}),
        "discovered_hosts": sorted(spider.discovered_hosts),
        "external_hosts": {h: sorted(k) for h, k in sorted(spider.external_refs.items())},
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


def merge_across_targets(results, extra=None):
    """One row per (rule, value) across all targets, with every target listed."""
    merged = {}
    for r in results:
        for f in r["findings"]:
            key = (f["rule"], f["value"])
            cur = merged.get(key)
            if cur is None:
                cur = dict(f, target=r["target"], targets=[r["target"]])
                cur["locations"] = list(f.get("locations") or [f["url"]])
                merged[key] = cur
                continue
            if r["target"] not in cur["targets"]:
                cur["targets"].append(r["target"])
            cur["occurrences"] = cur.get("occurrences", 1) + f.get("occurrences", 1)
            for loc in f.get("locations") or [f["url"]]:
                if loc not in cur["locations"] and len(cur["locations"]) < 5:
                    cur["locations"].append(loc)
            # keep the strongest classification seen
            if SEVERITY_RANK.get(f["severity"], 9) < SEVERITY_RANK.get(cur["severity"], 9):
                cur.update(severity=f["severity"], confidence=f["confidence"], title=f["title"])
    for f in extra or []:
        merged.setdefault((f["rule"], f["value"]), f)
    return list(merged.values())


def write_summary(out_dir, results, started, opts, extra_findings=None, inventory=None):
    all_f = merge_across_targets(results, extra_findings)
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
    if inventory:
        summary["inventory"] = inventory
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
            tg = f.get("targets") or [f.get("target", "")]
            tgt = tg[0] + (f" (+{len(tg) - 1} more)" if len(tg) > 1 else "")
            lines.append(
                f"| {_md_escape(f['title'])} | `{_md_escape(f['value'][:90])}` | {f['confidence']} | {_md_escape(f['url'][:100])} | {_md_escape(tgt)} |"
            )
    inv = summary.get("inventory") or {}
    docs = inv.get("documents") or {}
    if docs:
        lines += ["", f"## From downloaded files ({inv.get('files_analyzed', 0)} analyzed)", ""]
        labels = (("usernames", "Account names (from file paths)"), ("internal_hosts", "Internal hosts and shares"), ("people", "People (authors, editors, commenters)"),
                  ("companies", "Companies"), ("software", "Software and versions"), ("devices", "Devices"), ("flags", "File flags"))
        for key, label in labels:
            items = docs.get(key) or {}
            if not items:
                continue
            shown = ", ".join(f"{_md_escape(v)} ({i['count']})" for v, i in list(items.items())[:40])
            lines.append(f"- **{label}:** {shown}" + (f" … +{len(items) - 40} more" if len(items) > 40 else ""))
    if inv.get("subdomains"):
        lines += ["", f"## Discovered hosts on target domains ({len(inv['subdomains'])})", ""]
        lines += [f"- {h}" for h in inv["subdomains"][:300]]
    if inv.get("shared_bundles"):
        lines += ["", "## Identical JS bundles served by several targets", "", "Same build on several hosts: a vulnerability in one likely affects all of them.", ""]
        for name, hosts in inv["shared_bundles"][:50]:
            lines.append(f"- `{name}`: {', '.join(hosts[:12])}")
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
