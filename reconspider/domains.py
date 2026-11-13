"""Post-crawl, passive analysis across all targets (no extra requests).

* Lookalike domains: a domain used in site content (email, link, script)
  that is one typo away from a domain the site normally uses, e.g.
  service@realifecover.com.au on a site that otherwise uses
  reallifecover.com.au. Mail or links to the typo go somewhere else.
* Inventory: subdomains seen, and identical hashed JS bundles shared by
  several hosts (one codebase behind many brands).
"""

import re
from collections import defaultdict

from .detect import registrable_domain

HASHED_BUNDLE_RE = re.compile(r"[-.][A-Za-z0-9_]{6,}(?:\.chunk)?\.m?js$")


def _split(domain):
    """'reallifecover.com.au' -> ('reallifecover', 'com.au')."""
    reg = registrable_domain(domain)
    label, _, suffix = reg.partition(".")
    return label, suffix


def _one_edit(a, b):
    """True if a and b differ by one insert/delete/substitute/transpose."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1 :]


def domain_usage(results):
    """registrable domain -> {"count": n, "kinds": set, "where": [urls], "targets": set}"""
    use = defaultdict(lambda: {"count": 0, "kinds": set(), "where": [], "targets": set()})

    def add(domain, kind, where, target):
        d = registrable_domain(domain)
        if not d or "." not in d:
            return
        u = use[d]
        u["count"] += 1
        u["kinds"].add(kind)
        u["targets"].add(target)
        if where and where not in u["where"] and len(u["where"]) < 5:
            u["where"].append(where)

    for r in results:
        t = r["target"]
        for host in [re.sub(r"^https?://", "", t).split("/")[0].split(":")[0]] + r.get("discovered_hosts", []):
            add(host, "target", "", t)
        for f in r["findings"]:
            if f["rule"] == "email":
                for loc in f.get("locations") or [f["url"]]:
                    add(f["value"].partition("@")[2], "email", loc, t)
        for host, kinds in (r.get("external_hosts") or {}).items():
            for k in kinds:
                add(host, k, "", t)
    return use


def lookalike_findings(results):
    use = domain_usage(results)
    by_suffix = defaultdict(list)
    for d in use:
        label, suffix = _split(d)
        if len(label) >= 5:
            by_suffix[suffix].append(label)
    out = []
    for suffix, labels in by_suffix.items():
        labels = sorted(set(labels))
        for i, a in enumerate(labels):
            for b in labels[i + 1 :]:
                if not _one_edit(a, b):
                    continue
                da, db = f"{a}.{suffix}", f"{b}.{suffix}"
                ua, ub = use[da], use[db]
                # The rarer one is the suspect; the other must be clearly established.
                sus, legit = (da, db) if (ua["count"], "target" in ua["kinds"]) < (ub["count"], "target" in ub["kinds"]) else (db, da)
                us, ul = use[sus], use[legit]
                # Suspect must be rare relative to the established domain, which
                # is a target itself or used clearly more often.
                if "target" in us["kinds"] or not ("target" in ul["kinds"] or ul["count"] >= max(2, 2 * us["count"])):
                    continue
                kinds = sorted(us["kinds"])
                sev = "medium" if us["kinds"] & {"email", "script", "form"} else "low"
                out.append({
                    "rule": "lookalike_domain",
                    "title": f"Possible typo of {legit} in site content",
                    "category": "exposure",
                    "severity": sev,
                    "confidence": "medium",
                    "value": sus,
                    "url": (us["where"] or [""])[0],
                    "source": "analysis",
                    "context": f"{sus} used {us['count']}x ({', '.join(kinds)}); {legit} used {ul['count']}x",
                    "reasons": ["one_edit_from_established_domain"],
                    "extra": {"likely_intended": legit, "used_as": kinds, "seen_on": us["where"], "targets": sorted(us["targets"])},
                    "note": "If the typo domain is unregistered or owned by someone else, mail or visitors sent to it are lost or intercepted. Check its registration (whois) and DNS.",
                    "target": sorted(us["targets"])[0],
                    "targets": sorted(us["targets"]),
                })
    return out


def inventory(results):
    target_hosts = {re.sub(r"^https?://", "", r["target"]).split("/")[0].split(":")[0].lower() for r in results}
    subs = set()
    for r in results:
        subs.update(h for h in r.get("discovered_hosts", []) if h not in target_hosts)
    bundles = defaultdict(set)
    for r in results:
        host = re.sub(r"^https?://", "", r["target"]).split("/")[0]
        for js in r.get("js_files", []):
            name = js.split("?", 1)[0].rsplit("/", 1)[-1]
            if HASHED_BUNDLE_RE.search(name):
                bundles[name].add(host)
    shared = sorted(((n, sorted(h)) for n, h in bundles.items() if len(h) >= 2), key=lambda x: (-len(x[1]), x[0]))
    return {"subdomains": sorted(subs), "shared_bundles": shared}
