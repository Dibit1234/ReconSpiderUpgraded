"""Evaluate file analysis on the labelled corpus (tests/file_corpus.py).

    python tests/file_eval.py CORPUS_DIR [--exiftool PATH] [--real DIR]

Reports, per file: kind, extracted chars, metadata kept vs total, findings
>= low. Then recall against truth.json, decoy checks, converted-format
coverage, raw-bytes vs extracted comparison, and the hostile-file results.
With --real, also runs the analyzer over a directory of real-world files
and prints every finding >= low for manual review.
"""

import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from reconspider.detect import Detector  # noqa: E402
from reconspider.files import FileAnalyzer  # noqa: E402

SHOWN = {"critical", "high", "medium", "low"}


def files_in(d):
    out = []
    for fn in sorted(os.listdir(d)):
        p = os.path.join(d, fn)
        if os.path.isfile(p) and fn != "truth.json":
            data = open(p, "rb").read()
            import hashlib

            out.append({"url": f"https://acme.com/docs/{fn}", "path": p, "bytes": len(data), "sha1": hashlib.sha1(data).hexdigest()})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--exiftool", default="")
    ap.add_argument("--real", default="")
    a = ap.parse_args()
    truth = json.load(open(os.path.join(a.corpus, "truth.json")))
    fa = FileAnalyzer("acme.com", exiftool=a.exiftool)
    print("exiftool:", fa.exif_status)

    files = files_in(a.corpus)
    t0 = time.time()
    findings, records, inv = fa.analyze(files)
    print(f"analyzed {len(files)} files in {time.time() - t0:.1f}s\n")
    by_file = {}
    for f in findings:
        by_file.setdefault(f["url"].rsplit("/", 1)[-1], []).append(f)
    print(f"{'file':14} {'kind':6} {'text':>6} {'meta kept/total':>16} {'exif tags':>9}  findings>=low")
    for r in records:
        fn = r["url"].rsplit("/", 1)[-1]
        shown = [f for f in by_file.get(fn, []) if f["severity"] in SHOWN]
        print(f"{fn:14} {str(r['kind']):6} {r['text_chars']:>6} {r['metadata_values_kept']:>7}/{r['metadata_values_total']:<8} {r['exiftool_tags']:>9}  "
              + ", ".join(sorted({f'{x["rule"]}' for x in shown})) + (f"  ERR {r['errors'][:1]}" if r["errors"] else ""))

    # recall
    print("\n== recall vs truth ==")
    hit = 0
    for e in truth["expect"]:
        ok = any(f["rule"] == e["rule"] and e["value"].lower() in str(f["value"]).lower() and f["severity"] in SHOWN for f in by_file.get(e["file"], []))
        hit += ok
        if not ok:
            print("  MISSED", e)
    print(f"  {hit}/{len(truth['expect'])} expected findings")
    people = set(inv["people"])
    missing_people = [p for p in truth["people"] if p not in people]
    print(f"  people inventory: {len(people)} found; expected missing: {missing_people or 'none'}")
    print(f"  people found: {sorted(people)}")
    print(f"  software: {list(inv['software'])[:12]}")
    print(f"  usernames: {list(inv['usernames'])} | internal hosts: {list(inv['internal_hosts'])}")
    print(f"  devices: {list(inv['devices'])} | companies: {list(inv['companies'])}")

    print("\n== decoys (must have no findings >= low) ==")
    for d in truth["decoy_files"]:
        bad = [(f["rule"], f["value"]) for f in by_file.get(d, []) if f["severity"] in SHOWN]
        print(f"  {d}: {bad or 'clean'}")
    junk_people = [p for p in people if p.lower() in {"microsoft office user", "administrator", "artist", "unknown", "copyright"}]
    print(f"  placeholder people leaked: {junk_people or 'none'}")
    own = [f for f in findings if "claude" in str(f["value"]).lower() or "/tmp/" in str(f["value"])]
    print(f"  local download path leaked into findings: {[(f['rule'], f['value']) for f in own] or 'none'}")

    # converted formats: which planted secrets survive conversion + extraction
    print("\n== converted formats (secret recovered?) ==")
    S = truth["secrets"]
    checks = {"report": ["vpn_pw", "aws_id", "comment_pw"], "budget": ["payroll_pw", "gh", "sql_pw"], "deck": ["demo_pw"]}
    for fn in sorted(by_file.keys() | {r["url"].rsplit("/", 1)[-1] for r in records}):
        stem, _, ext = fn.partition(".")
        if stem not in checks:
            continue
        vals = " ".join(str(f["value"]) for f in by_file.get(fn, []) if f["severity"] in SHOWN)
        res = {k: ("yes" if S[k] in vals else "no") for k in checks[stem]}
        rec = next(r for r in records if r["url"].endswith("/" + fn))
        authors = [v for k, v in rec["metadata"].items() if k.rsplit(":", 1)[-1].lower() in ("author", "creator", "lastmodifiedby")]
        print(f"  {fn:12} {res}  authors={authors[:3]}")

    # raw bytes vs extracted
    print("\n== raw bytes scanning vs extraction (same detector) ==")
    det = Detector("acme.com")
    for fdesc in files:
        fn = os.path.basename(fdesc["path"])
        raw = open(fdesc["path"], "rb").read().decode("utf-8", "ignore")
        raw_f = [f for f in det.scan(raw, fdesc["url"], "document") if f["severity"] in SHOWN]
        ext_f = [f for f in by_file.get(fn, []) if f["severity"] in SHOWN]
        print(f"  {fn:14} raw={len(raw_f):3}  extracted={len(ext_f):3}" + (f"   raw-only: {[(f['rule'], f['value'][:30]) for f in raw_f if f['value'] not in {x['value'] for x in ext_f}][:3]}" if raw_f else ""))

    # hostile
    print("\n== hostile files ==")
    hfiles = files_in(os.path.join(a.corpus, "hostile"))
    t0 = time.time()
    hf, hrec, _ = fa.analyze(hfiles)
    for r in hrec:
        print(f"  {r['url'].rsplit('/', 1)[-1]:14} kind={r['kind']!s:12} text={r['text_chars']:<6} flags={r['flags']} errors={[e[:60] for e in r['errors']][:2]}")
    print(f"  parent process survived; {len(hf)} findings; {time.time() - t0:.1f}s")
    print("  traversal member written to disk:", os.path.exists("/etc/cron.d/evil") and open("/etc/cron.d/evil").read().strip() == "* * * * * root id")

    if a.real:
        print("\n== real-world corpus ==")
        rfiles = files_in(a.real)
        t0 = time.time()
        rf, rrec, rinv = fa.analyze(rfiles)
        tot = sum(r["metadata_values_total"] for r in rrec)
        kept = sum(r["metadata_values_kept"] for r in rrec)
        print(f"  {len(rfiles)} files in {time.time() - t0:.1f}s; metadata values {tot} -> kept {kept} ({100 * kept / max(tot, 1):.1f}%)")
        shown = [f for f in rf if f["severity"] in SHOWN]
        print(f"  findings >= low: {len(shown)}; info: {len(rf) - len(shown)}")
        for f in shown:
            print(f"    [{f['severity']}] {f['rule']:24} {str(f['value'])[:50]:50} {f['url'].rsplit('/', 1)[-1][:40]}")
        print(f"  people ({len(rinv['people'])}): {list(rinv['people'])[:40]}")
        print(f"  software ({len(rinv['software'])}): {list(rinv['software'])[:25]}")
        print(f"  usernames: {list(rinv['usernames'])} | hosts: {list(rinv['internal_hosts'])[:20]}")
        print(f"  devices ({len(rinv['devices'])}): {list(rinv['devices'])[:10]} | flags: {dict((k, v['count']) for k, v in rinv['flags'].items())}")
        errs = [r for r in rrec if r["errors"]]
        print(f"  files with extractor errors: {len(errs)}: {[(r['url'].rsplit('/', 1)[-1], r['errors'][0][:40]) for r in errs[:8]]}")


if __name__ == "__main__":
    main()
