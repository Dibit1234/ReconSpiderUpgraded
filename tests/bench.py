"""Precision/recall + speed benchmark against the labelled fixture site.

    python tests/bench.py                      # new version only
    python tests/bench.py --old path/to/old.py # also run a previous version for comparison
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import fixture_site as fx  # noqa: E402

SHOWN = {"critical", "high", "medium", "low"}


def start_server(port):
    srv = fx.serve(port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def match(expected, value):
    return expected in value or (len(value) >= 8 and value in expected)


def score(values_shown, values_all, expected):
    hits = {k: any(match(v, x) for x in values_all) for k, v in expected.items()}
    fps = []
    for v in values_shown:
        if any(match(e, v) for e in expected.values()) or v in fx.PUBLIC or any(p in v for p in fx.PUBLIC):
            continue
        fps.append(v)
    decoys = [d for d in fx.DECOY_VALUES if any(d == v or (d in v and len(v) < len(d) + 12) for v in values_shown)]
    return hits, fps, decoys


def run_old(script, port, workdir):
    t0 = time.time()
    fx.Handler.count = 0
    subprocess.run([sys.executable, script, f"http://127.0.0.1:{port}/", "--no-stream-findings"], cwd=workdir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
    elapsed = time.time() - t0
    with open(os.path.join(workdir, "results.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    values = [f["value"] for items in data.get("findings", {}).values() for f in items]
    return values, values, elapsed, fx.Handler.count, data.get("scan_stats", {}).get("pages_scanned")


def run_new(port, workdir, extra=()):
    t0 = time.time()
    fx.Handler.count = 0
    out = os.path.join(workdir, "out")
    subprocess.run([sys.executable, os.path.join(ROOT, "ReconSpiderUpgraded.py"), f"http://127.0.0.1:{port}/", "-o", out, "-q", *extra], stdout=subprocess.DEVNULL, timeout=1800, check=True)
    elapsed = time.time() - t0
    with open(os.path.join(out, "summary.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    shown = [f["value"] for f in data["findings"] if f["severity"] in SHOWN]
    # extra decoded values (basic auth decoded, url-cred passwords) count for recall
    allv = [f["value"] for f in data["findings"]] + [str(v) for f in data["findings"] for v in (f.get("extra") or {}).values()]
    pages = sum(t["pages"] for t in data["targets"])
    return shown, allv, elapsed, fx.Handler.count, pages, data


def report(name, hits, fps, decoys, elapsed, requests, pages):
    tp = sum(hits.values())
    print(f"\n=== {name} ===")
    print(f"recall: {tp}/{len(hits)}   false positives (shown): {len(fps)}   decoys hit: {len(decoys)}/{len(fx.DECOY_VALUES)}")
    print(f"time: {elapsed:.1f}s   requests to server: {requests}   pages: {pages}")
    missed = [k for k, v in hits.items() if not v]
    if missed:
        print("missed:", ", ".join(missed))
    if decoys:
        print("decoys reported:", decoys)
    for v in fps[:25]:
        print("  FP:", v[:110])
    if len(fps) > 25:
        print(f"  ... {len(fps) - 25} more")
    return tp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", help="path to a previous ReconSpiderUpgraded.py")
    ap.add_argument("--port", type=int, default=8811)
    args = ap.parse_args()
    start_server(args.port)

    if args.old:
        with tempfile.TemporaryDirectory() as wd:
            vals, allv, el, req, pages = run_old(os.path.abspath(args.old), args.port, wd)
            report("OLD", *score(vals, allv, fx.TRUE_POSITIVES), el, req, pages)

    with tempfile.TemporaryDirectory() as wd:
        shown, allv, el, req, pages, _ = run_new(args.port, wd)
        report("NEW (defaults)", *score(shown, allv, fx.TRUE_POSITIVES), el, req, pages)

    with tempfile.TemporaryDirectory() as wd:
        exp = dict(fx.TRUE_POSITIVES, **fx.PROBE_TRUE_POSITIVES)
        shown, allv, el, req, pages, data = run_new(args.port, wd, ["--probe"])
        report("NEW (--probe)", *score(shown, allv, exp), el, req, pages)
        rules = {f["rule"] for f in data["findings"] if f["severity"] != "info"}
        need = {"lookalike_domain", "mock_api_handlers", "graphql_introspection", "exposed_file", "datadog_api_key"}
        print("required rules missing:", sorted(need - rules) or "none")
        print("bulk IP list collapsed:", any(f["rule"] == "public_ip_list" for f in data["findings"]),
              "| single public_ip rows:", sum(f["rule"] == "public_ip" for f in data["findings"]))
        inv = data.get("inventory", {})
        print("inventory:", {k: len(v) for k, v in inv.items()})


if __name__ == "__main__":
    main()
