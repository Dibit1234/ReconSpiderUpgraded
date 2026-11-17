"""Downloaded-file analysis (parent side).

Pipeline per file:
  1. reconspider/extract.py in a separate, resource-limited Python process
     (no file writes, CPU/memory/time caps) -> text, metadata, links, flags.
  2. ExifTool (if installed and >= 12.38), one batch call, read-only.
  3. Filtering: an allow-list of metadata that matters to an assessment.
     Everything else is dropped (ICC profiles, exposure, dimensions, the
     local file's own name/size/dates...). Every remaining value and link is
     also searched for user paths, UNC shares, internal hosts and emails.
  4. Extracted text goes through the normal secret Detector with
     source="document".

See README "File analysis" for the rationale and test results.
"""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from .detect import Detector, registrable_domain

EXTRACT_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extract.py")
EXIFTOOL_MIN = (12, 38)  # CVE-2021-22204 (DjVu RCE, fixed 12.24), CVE-2022-23935 (fixed 12.38)

# --------------------------------------------------------------------------- #
# What is worth keeping
# --------------------------------------------------------------------------- #

PERSON_TAGS = {
    "author", "creator", "artist", "lastmodifiedby", "ownername", "by-line", "writer-editor", "captionwriter",
    "manager", "cameraownername", "printedby", "xmp:creator", "initial-creator",
}
COMPANY_TAGS = {"company", "organization", "organisation"}
SOFTWARE_TAGS = {
    "producer", "creatortool", "software", "application", "appversion", "generator", "writername", "readername",
    "processingsoftware", "historysoftwareagent", "xmp:creatortool", "xmp:producer", "encoder", "encodedby",
}
SERIAL_TAGS = {"serialnumber", "cameraserialnumber", "lensserialnumber", "internalserialnumber", "bodyserialnumber"}
DEVICE_TAGS = {"make", "model"}
TEXT_TAGS = {
    "title", "subject", "description", "imagedescription", "usercomment", "comment", "keywords", "caption-abstract",
    "headline", "instructions", "specialinstructions", "notes", "category", "hyperlinkbase", "template", "printername",
    "sheets", "docname", "export-filename", "absref",
}
GPS_TAGS = {"gpslatitude", "gpslongitude", "gpsposition"}
HOST_TAGS = {"hostcomputer", "computername", "machinename", "workstation", "computer"}
DROP_GROUPS = {"file", "system", "exiftool", "composite-file"}

PLACEHOLDER_PEOPLE = {
    "", "user", "users", "admin", "administrator", "owner", "author", "artist", "unknown", "none", "n/a", "na", "default",
    "windows user", "microsoft office user", "office user", "microsoft account", "test", "guest", "me", "name", "your name",
    "creator", "an author", "photographer", "copyright", "title", "-", "?", "staff", "pc", "home", "valued customer",
    "registered user", "customer", "authorname", "first last", "john doe", "jane doe", "someone", "anonymous",
    "user name", "username", "byline", "by-line", "manager", "writer", "writers", "editor", "caption writer", "who knows",
    "guess who", "me too", "i wrote it", "i'm the author", "self", "company", "organization", "my company", "your company",
}
ROLE_PREFIX_RE = re.compile(r"(?i)^(?:author|creator|manager|artist|by|written by|prepared by|owner)\s*:\s*")
TOOL_RE = re.compile(
    r"(?i)\d+\.\d+|\b(?:writer|word|excel|powerpoint|acrobat|distiller|pdf|ghostscript|cairo|tex|latex|libreoffice|openoffice|"
    r"microsoft|adobe|photoshop|illustrator|indesign|quartz|mac ?os|windows|chrom(?:e|ium)|skia|wkhtml|itext|pdfsharp|reportlab|"
    r"prince|canva|pscript|aspose|crystal|jasper|fop|fpdf|tcpdf|mpdf|dompdf|xerox|canon|ricoh|konica|scan(?:ner)?|printer|"
    r"ilovepdf|smallpdf|nitro|foxit|keynote|google|inkscape|gimp|figma|sketch|affinity|corel|visio|onenote|publisher|wps|"
    r"kingsoft|ios|android|camera|picasa|lightroom|exiftool|xmp|toolkit|library|engine|converter|generator|version|build|"
    r"impress|calc|draw|math|pages|numbers|wordpad|notepad|textedit|quark|framemaker|pagemaker|zamzar|torrent)\b|\w/\d"
)

# --------------------------------------------------------------------------- #
# Patterns applied to every kept value and every link target
# --------------------------------------------------------------------------- #

WIN_USER_RE = re.compile(r"(?i)\b[a-z]:[\\/]+(?:users|documents and settings)[\\/]+([^\\/:*?\"<>|\r\n]{1,64})[\\/]")
NIX_USER_RE = re.compile(r"(?:^|[\s\"'=(file:/)])/(?:home|Users)/([A-Za-z0-9._-]{1,64})/")
UNC_RE = re.compile(r"(?:\\\\|file:/{2,5})([A-Za-z0-9][A-Za-z0-9._-]{1,62})[\\/]+([^\\/\s\"<>|]{1,80})")
GENERIC_USERS = {"public", "default", "all users", "default user", "administrator", "admin", "user", "users", "shared", "guest", "root", "runner", "build", "jenkins", "vsts", "vssadministrator"}
INTERNAL_TLDS = (".local", ".corp", ".internal", ".lan", ".intranet", ".ad", ".localdomain", ".int", ".priv", ".private", ".home.arpa")
URL_RE = re.compile(r"(?i)\b(?:https?|ftp|file)://[^\s\"'<>]{3,500}")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b")
BARE_INTERNAL_HOST_RE = re.compile(r"(?i)(?<![\w.@/-])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63})*\.(?:local|corp|internal|lan|intranet|localdomain|priv)(?![\w.-])")
CONN_SERVER_RE = re.compile(r"(?i)(?:data source|server|host|address|addr|network address)\s*=\s*([^;\"']{2,120})")


HOSTNAME_RE = re.compile(r"(?i)^(?=.{2,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
SERVERISH_RE = re.compile(r"(?i)srv|serv|fs|file|share|nas|dc\d|sql|db|app|web|print|prn|data|backup|store|corp|dept|finance|hr|it")


def _is_internal_host(host):
    host = (host or "").lower().strip("[]")
    if not host or not HOSTNAME_RE.match(host.split("%")[0]):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    return host.endswith(INTERNAL_TLDS) or ("." not in host and host not in {"localhost"} and len(host) > 2)


def _clean_person(v):
    v = re.sub(r"\s+", " ", str(v)).strip(" ;,\x00")
    v = re.sub(r";+$", "", v)
    return v


def classify_person(v):
    """('person'|'tool'|None, cleaned)"""
    v = ROLE_PREFIX_RE.sub("", _clean_person(v))
    if len(v) < 2 or len(v) > 80 or v.lower() in PLACEHOLDER_PEOPLE or v.isdigit():
        return None, v
    if re.fullmatch(r"(?i)(?:the |an? |another )?(?:author|artist|creator|owner|title|copyright|name|manager|user|person|photographer)\b.*", v) or re.search(r"[{}<>\[\]]|_type_", v) or re.search(r"(?i)\b(?:right|wrong)\d*of\d*-|^(?:right|wrong)-", v):
        return None, v  # test fixtures / template placeholders
    if TOOL_RE.search(v):
        return "tool", v
    if not re.search(r"[A-Za-z]", v):
        return None, v
    return "person", v


# --------------------------------------------------------------------------- #
# Sandboxed extraction + ExifTool
# --------------------------------------------------------------------------- #


def _limits():  # runs in the child before exec (POSIX only)
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (45, 50))
    resource.setrlimit(resource.RLIMIT_AS, (2_500_000_000, 2_500_000_000))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))  # may not write any file
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.setsid()


def _sandbox_kwargs(workdir):
    kw = {"cwd": workdir, "env": {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONIOENCODING": "utf-8"}, "stdin": subprocess.DEVNULL}
    if os.name == "posix":
        kw["preexec_fn"] = _limits
    return kw


def run_extract(path, workdir, timeout=60):
    try:
        p = subprocess.run([sys.executable, "-I", EXTRACT_PY, path], capture_output=True, timeout=timeout, **_sandbox_kwargs(workdir))
    except subprocess.TimeoutExpired:
        return {"kind": "unknown", "errors": ["extract_timeout"], "text": "", "meta": {}, "links": [], "people": [], "flags": ["extract_timeout"], "members": []}
    if p.returncode != 0 or not p.stdout:
        reason = "killed_by_limit" if p.returncode < 0 else f"exit_{p.returncode}"
        return {"kind": "unknown", "errors": [reason, p.stderr.decode("utf-8", "ignore")[-300:]], "text": "", "meta": {}, "links": [], "people": [], "flags": [reason], "members": []}
    try:
        return json.loads(p.stdout.decode("utf-8", "ignore"))
    except ValueError:
        return {"kind": "unknown", "errors": ["bad_json"], "text": "", "meta": {}, "links": [], "people": [], "flags": [], "members": []}


def find_exiftool(explicit=""):
    if explicit is False:
        return None, "exiftool disabled (--no-exiftool): built-in parsers only"
    exe = explicit or shutil.which("exiftool")
    if not exe:
        return None, "exiftool not found (metadata limited to built-in parsers)"
    try:
        out = subprocess.run([exe, "-ver"], capture_output=True, timeout=20, stdin=subprocess.DEVNULL).stdout.decode().strip()
        ver = tuple(int(x) for x in out.split(".")[:2])
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None, f"could not run {exe}"
    if ver < EXIFTOOL_MIN:
        return None, f"exiftool {out} is older than {EXIFTOOL_MIN[0]}.{EXIFTOOL_MIN[1]} (known code-execution bugs on malicious files): not used"
    return exe, f"exiftool {out}"


def run_exiftool(exe, paths, workdir, timeout=180):
    if not exe or not paths:
        return {}
    out = {}
    for i in range(0, len(paths), 50):
        batch = paths[i:i + 50]
        try:
            p = subprocess.run(
                [exe, "-j", "-G1", "-a", "-n", "-q", "-q", "-m", "-struct", "-charset", "filename=utf8", "-api", "LargeFileSupport=1", *batch],
                capture_output=True, timeout=timeout, **_sandbox_kwargs(workdir),
            )
            for row in json.loads(p.stdout.decode("utf-8", "ignore") or "[]"):
                out[row.get("SourceFile")] = row
        except (subprocess.TimeoutExpired, ValueError, OSError):
            continue
    return out


def _flatten(prefix, v, out):
    if isinstance(v, dict):
        for k, x in v.items():
            _flatten(f"{prefix}.{k}" if prefix else k, x, out)
    elif isinstance(v, list):
        for x in v[:50]:
            _flatten(prefix, x, out)
    else:
        out.append((prefix, v))


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


class FileAnalyzer:
    def __init__(self, target_host="", exiftool="", workers=4, detector_kwargs=None):
        self.exe, self.exif_status = find_exiftool(exiftool)
        self.workers = workers
        self.det = Detector(target_host=target_host, **(detector_kwargs or {}))
        self.target_site = registrable_domain(target_host) if target_host else ""

    def analyze(self, files):
        """files: [{"url", "path", "kind", "bytes", "sha1"}] -> (findings, records, inventory)"""
        findings, records = [], []
        inv = {"people": {}, "software": {}, "companies": {}, "usernames": {}, "internal_hosts": {}, "devices": {}, "flags": {}}
        if not files:
            return findings, records, inv
        with tempfile.TemporaryDirectory(prefix="rs-extract-") as work:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                extracted = list(pool.map(lambda f: run_extract(f["path"], work), files))
            exif = run_exiftool(self.exe, [f["path"] for f in files], work)
        for f, ex in zip(files, extracted):
            fnd, rec = self._one(f, ex, exif.get(f["path"]) or {}, inv)
            findings += fnd
            records.append(rec)
        inv = {k: dict(sorted(v.items(), key=lambda kv: -kv[1]["count"])) for k, v in inv.items()}
        return findings, records, inv

    # ------------------------------------------------------------------
    def _one(self, f, ex, exif_row, inv):
        url = f["url"]
        out = []
        self._file_seen = set()
        meta_pairs = []  # (tag, value, source)
        for k, v in (ex.get("meta") or {}).items():
            if k.startswith("EXIF-fallback:") and exif_row:
                continue  # exiftool read the same EXIF, more completely
            meta_pairs.append((k, v, "parser"))
        exif_total = 0
        for k, v in exif_row.items():
            group, _, tag = k.rpartition(":")
            exif_total += 1
            if group.lower() in DROP_GROUPS or k == "SourceFile":
                continue
            flat = []
            _flatten(tag, v, flat)
            for t, x in flat:
                meta_pairs.append((f"{group}:{t}" if group else t, x, "exiftool"))

        kept = {}
        lat = lon = None
        make = model = serial = None
        for key, val, _src in meta_pairs:
            if val in (None, "", [], {}):
                continue
            tag = key.rsplit(":", 1)[-1].lower().replace(" ", "")
            sval = str(val).strip()
            if not sval:
                continue
            base = tag.split(".")[-1]
            if base in PERSON_TAGS or key.lower().startswith("xmp-dc:creator"):
                kind, clean = classify_person(sval)
                if kind == "person":
                    kept[key] = clean
                    self._inv(inv["people"], clean, url, role=base)
                elif kind == "tool":
                    kept[key] = clean
                    self._inv(inv["software"], clean, url)
            elif base in COMPANY_TAGS:
                kind, clean = classify_person(sval)
                if kind:
                    kept[key] = clean
                    self._inv(inv["companies"], clean, url)
            elif base in SOFTWARE_TAGS or key.lower().startswith(("xmp-xmpmm:historysoftwareagent",)):
                if re.fullmatch(r"[\d.]+", sval):
                    continue  # AppVersion "16.0000" alone says nothing
                if not re.search(r"(?i)^(?:image::)?exiftool|^xmp core|^adobe xmp core", sval):
                    kept[key] = sval[:200]
                    self._inv(inv["software"], sval[:200], url)
            elif base in ("gpslatitude",):
                lat = _num(val)
            elif base in ("gpslongitude",):
                lon = _num(val)
            elif base in HOST_TAGS:
                h = sval.strip().lower()
                if re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,62}", h) and not TOOL_RE.search(sval):
                    kept[key] = sval
                    if self._inv(inv["internal_hosts"], h, url):
                        out.append(self._f("doc_internal_host", "Computer name in file metadata", "low", "high", h, url, f"{key}: {sval}", [f"from={key}"]))
            elif base in SERIAL_TAGS:
                if len(sval) >= 4 and not re.fullmatch(r"0+|[0 ]+|unknown|none", sval.lower()):
                    serial = sval
                    kept[key] = sval
            elif base in DEVICE_TAGS:
                if base == "make":
                    make = sval
                else:
                    model = sval
            elif base in TEXT_TAGS or key.startswith(("Custom:", "PNG:", "SVG:")):
                kept[key] = sval[:500]
            # every value: user paths, shares, internal hosts, emails
            self._patterns(sval, key, url, out, inv)

        # links (hyperlinks, templates, linked workbooks, data connections)
        for link in ex.get("links") or []:
            tgt = link.get("target", "")
            self._patterns(tgt, f"link:{link.get('type')}", url, out, inv, is_link=True)
            if link.get("type") in ("data_connection", "data_source") and CONN_SERVER_RE.search(tgt):
                m = CONN_SERVER_RE.search(tgt)
                out.append(self._f("doc_data_connection", "Data connection in document", "low", "high", m.group(1).strip(), url,
                                   tgt[:200], ["external_data_connection"], extra={"connection": tgt[:500]}))
        # people from comments / tracked changes
        for role, name in ex.get("people") or []:
            kind, clean = classify_person(name)
            if kind == "person":
                self._inv(inv["people"], clean, url, role=role)

        import math

        valid = lat is not None and lon is not None and math.isfinite(lat) and math.isfinite(lon) and abs(lat) <= 90 and abs(lon) <= 180
        if valid and not (abs(lat) < 0.0001 and abs(lon) < 0.0001):
            v = f"{lat:.5f},{lon:.5f}"
            out.append(self._f("doc_gps", "GPS location in file metadata", "medium", "high", v, url, f"https://www.openstreetmap.org/?mlat={lat:.5f}&mlon={lon:.5f}&zoom=16",
                               ["exif_gps"], extra={"latitude": lat, "longitude": lon, "device": " ".join(x for x in (make, model) if x) or None}))
        if make and model and model.lower().startswith(make.lower().split()[0]):
            make = None  # "Canon" + "Canon EOS R6"
        if serial:
            dev = " ".join(x for x in (make, model) if x) or "device"
            self._inv(inv["devices"], f"{dev} #{serial}", url)
        elif make or model:
            self._inv(inv["devices"], " ".join(x for x in (make, model) if x), url)

        flags = ex.get("flags") or []
        for fl, (rule, title, sev) in FLAG_FINDINGS.items():
            if fl in flags:
                out.append(self._f(rule, title, sev, "high", url, url, "", [fl]))
        for fl in flags:
            self._inv(inv["flags"], fl, url)

        # text -> secret detector, plus paths/shares/hosts written in the body
        text = ex.get("text") or ""
        self._patterns(text[:2_000_000], "text", url, out, inv, is_link=True)
        scan_text = text
        # metadata free text and data connections are also scanned
        extra_text = "\n".join(f"{k}: {v}" for k, v in kept.items() if k.rsplit(":", 1)[-1].lower() in TEXT_TAGS or k.startswith(("Custom:", "PNG:")))
        extra_text += "\n" + "\n".join(l.get("target", "") for l in ex.get("links") or [] if l.get("type") in ("data_connection", "data_source"))
        if scan_text or extra_text.strip():
            for x in self.det.scan(scan_text + "\n" + extra_text, url, "document"):
                x.setdefault("extra", {})["file_kind"] = ex.get("kind")
                out.append(x)

        rec = {
            "url": url, "saved_as": f["path"], "kind": ex.get("kind"), "bytes": f.get("bytes"), "sha1": f.get("sha1"),
            "text_chars": len(text), "metadata": kept, "flags": flags, "links": [l.get("target") for l in (ex.get("links") or [])][:50],
            "members": (ex.get("members") or [])[:50], "errors": ex.get("errors") or [],
            "metadata_values_total": len(meta_pairs), "metadata_values_kept": len(kept), "exiftool_tags": exif_total,
        }
        return out, rec

    def _patterns(self, s, key, url, out, inv, is_link=False):
        if not s or len(s) < 4:
            return
        for m in WIN_USER_RE.finditer(s):
            self._username(m.group(1), m.group(0), key, url, out, inv)
        for m in NIX_USER_RE.finditer(s):
            self._username(m.group(1), m.group(0), key, url, out, inv)
        for m in UNC_RE.finditer(s):
            host, share = m.group(1), m.group(2)
            if host.lower() in {"localhost", "127.0.0.1"} or re.fullmatch(r"[a-z]:?", host.lower()) or not HOSTNAME_RE.match(host):
                continue
            sep = s[m.end(1):m.start(2)]
            if sep == "\\" and share[:1] in "ntr" and not re.search(r"[\d.-]", host) and not SERVERISH_RE.search(host) and not host.isupper():
                continue  # "\\backslash\\nnewline": escaped text, not a share
            hv = f"\\\\{host}\\{share}"
            if self._inv(inv["internal_hosts"], host.lower(), url):
                out.append(self._f("doc_internal_share", "Internal file share in document", "low", "high", hv, url, s[:200], [f"from={key}"], extra={"host": host}))
        for m in BARE_INTERNAL_HOST_RE.finditer(s):
            host = m.group(0).lower()
            if self._inv(inv["internal_hosts"], host, url):
                out.append(self._f("doc_internal_host", "Internal hostname in document", "low", "high", host, url, s[max(0, m.start() - 60):m.end() + 60], [f"from={key}"]))
        for m in URL_RE.finditer(s):
            try:
                p = urlparse(m.group(0))
                host = (p.hostname or "").lower()
            except ValueError:
                continue
            if p.scheme == "file" or not host:
                continue
            if _is_internal_host(host) and self._inv(inv["internal_hosts"], host, url):
                out.append(self._f("doc_internal_host", "Internal hostname in document", "low", "high", host, url, m.group(0)[:200], [f"from={key}"]))
        if not is_link:
            for m in EMAIL_RE.finditer(s):
                e = m.group(0).lower()
                out.append(self._f("email", "Email address", "info", "high", e, url, s[:200], [f"metadata:{key}"], category="email",
                                   extra={"on_target_domain": registrable_domain(e.split('@')[1]) == self.target_site}))

    def _username(self, user, path, key, url, out, inv):
        user = user.strip()
        if not user or user.lower() in GENERIC_USERS or user.startswith(("$", "%", "{")) or len(user) < 2:
            return
        if self._inv(inv["usernames"], user, url):
            out.append(self._f("doc_username", "Account name in document path", "low", "high", user, url, path[:200], [f"from={key}"], extra={"path": path[:300]}))

    def _inv(self, bucket, value, url, role=None):
        """Add to an inventory bucket. Returns True the first time a value is
        seen in the current file (the crawler dedupes across files and keeps
        every location)."""
        key = (id(bucket), value)
        first_in_file = key not in self._file_seen
        self._file_seen.add(key)
        cur = bucket.get(value)
        if cur is None:
            bucket[value] = {"count": 1, "files": [url]} | ({"roles": [role]} if role else {})
            return first_in_file
        cur["count"] += 1
        if url not in cur["files"] and len(cur["files"]) < 5:
            cur["files"].append(url)
        if role and role not in cur.setdefault("roles", []):
            cur["roles"].append(role)
        return first_in_file

    @staticmethod
    def _f(rule, title, sev, conf, value, url, ctx, reasons, category="file", extra=None):
        f = {"rule": rule, "title": title, "category": category, "severity": sev, "confidence": conf, "value": value, "url": url,
             "source": "document", "context": ctx, "reasons": reasons}
        if extra:
            f["extra"] = extra
        return f


FLAG_FINDINGS = {
    "macros_vba": ("doc_macros", "Macro-enabled document (VBA)", "low"),
    "macros_basic": ("doc_macros", "Document contains Basic macros", "low"),
    "pdf_javascript": ("doc_pdf_javascript", "PDF contains JavaScript", "low"),
}


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
