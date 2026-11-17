"""File-analysis tests: extraction, metadata filtering, sandbox and safety.

Run: python -m pytest -q tests/test_files.py
Uses tests/file_corpus.py (built once per session). ExifTool is used when on
PATH or in $EXIFTOOL; LibreOffice conversions are skipped here for speed.
"""

import os
import shutil
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import file_corpus  # noqa: E402
from reconspider import extract  # noqa: E402
from reconspider import files as F  # noqa: E402

EXIFTOOL = os.environ.get("EXIFTOOL") or shutil.which("exiftool") or ""
SHOWN = {"critical", "high", "medium", "low"}


@pytest.fixture(scope="session")
def corpus(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("corpus"))
    os.environ["RS_CORPUS_NO_SOFFICE"] = "1"
    if EXIFTOOL:
        os.environ["EXIFTOOL"] = EXIFTOOL
    file_corpus.R.seed(4242)
    truth = file_corpus.build(d)
    return d, truth


def ex(path):
    """Run the real sandboxed extractor."""
    return F.run_extract(path, os.path.dirname(path))


@pytest.fixture(scope="session")
def analyzed(corpus):
    d, truth = corpus
    files = [{"url": f"https://acme.com/docs/{fn}", "path": os.path.join(d, fn)} for fn in sorted(os.listdir(d)) if os.path.isfile(os.path.join(d, fn)) and fn != "truth.json"]
    fa = F.FileAnalyzer("acme.com", exiftool=EXIFTOOL or False)
    findings, records, inv = fa.analyze(files)
    by_file = {}
    for f in findings:
        by_file.setdefault(f["url"].rsplit("/", 1)[-1], []).append(f)
    return by_file, records, inv, fa


# ---------------------------------------------------------------- sniffing
@pytest.mark.parametrize(
    "data,kind",
    [
        (b"MZ\x90\x00" + b"\x00" * 100, "executable:pe"), (b"\x7fELF\x02\x01", "executable:elf"), (b"#!/bin/sh\nrm -rf /", "executable:script"),
        (b"%PDF-1.7\n", "pdf"), (b"\xff\xd8\xff\xe0", "jpeg"), (b"\x89PNG\r\n\x1a\n", "png"), (b"{\\rtf1\\ansi", "rtf"),
        (b"<!doctype html><html>", "html"), (b"<svg xmlns='http://www.w3.org/2000/svg'/>", "svg"), (b"a,b\n1,2\n", "text"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 50, "ole"),
    ],
)
def test_sniff_by_content_not_name(data, kind):
    assert extract.sniff(data) == kind


def test_office_kinds(corpus):
    d, _ = corpus
    for fn, kind in (("report.docx", "docx"), ("budget.xlsx", "xlsx"), ("deck.pptx", "pptx"), ("macro.docm", "docx"), ("backup.zip", "zip")):
        assert extract.sniff(open(os.path.join(d, fn), "rb").read()) == kind


# ---------------------------------------------------------------- extraction content
def test_docx_extraction(corpus):
    d, truth = corpus
    r = ex(os.path.join(d, "report.docx"))
    assert f"Password: {truth['secrets']['vpn_pw']}" in r["text"]
    assert truth["secrets"]["comment_pw"] in r["text"]  # comments.xml
    assert r["meta"]["Author"] == "Jordan Smith" and r["meta"]["LastModifiedBy"] == "priya.raman" and r["meta"]["Company"] == "Acme Corp"
    targets = {l["target"] for l in r["links"]}
    assert any("jsmith" in t for t in targets) and any("acme-fs01" in t for t in targets)
    assert ("tracked_change_author", "Mark Chen") in [tuple(p) for p in r["people"]]
    assert ("comment_author", "Lisa Wong") in [tuple(p) for p in r["people"]]


def test_xlsx_rows_keep_headers(corpus):
    d, truth = corpus
    r = ex(os.path.join(d, "budget.xlsx"))
    assert f"Password: {truth['secrets']['payroll_pw']}" in r["text"]
    assert "hidden_sheets" in r["flags"]
    assert any(l["type"] == "data_connection" and "SQLPROD01" in l["target"] for l in r["links"])


def test_pptx_notes_and_rtf_svg_png(corpus):
    d, truth = corpus
    assert truth["secrets"]["demo_pw"] in ex(os.path.join(d, "deck.pptx"))["text"]
    svg = ex(os.path.join(d, "logo.svg"))
    assert "dwilliams" in svg["meta"]["SVG:export-filename"]
    png = ex(os.path.join(d, "logo.png"))
    assert png["meta"]["PNG:Author"] == "Dana Williams" and "acme-design" in png["meta"]["PNG:Comment"]


def test_zip_members_read_in_memory(corpus):
    d, truth = corpus
    r = ex(os.path.join(d, "backup.zip"))
    assert truth["secrets"]["zip_env_pw"] in r["text"] and "PRIVATE KEY" in r["text"]
    assert "../../etc/cron.d/evil" in r["members"]
    assert not os.path.exists("/etc/cron.d/evil") or "root id" not in open("/etc/cron.d/evil").read()


def test_pdf_glyph_per_line_rejoined():
    t = "\n".join("Jump host 10.42.7.15 (jump01.acme.corp)")
    assert extract._fix_glyph_lines(t) == "Jump host 10.42.7.15 (jump01.acme.corp)"
    assert extract._fix_glyph_lines("normal\ntext") == "normal\ntext"


def test_ole_strings_drop_binary_junk():
    r = extract.Result("ole")
    extract.extract_ole(b"\x00" * 64 + b"dddzzzHHH'''555cccdddppp" + b"\x00" * 8 + "Password: Hunter-22x".encode("utf-16-le") + b"\x00" * 8, r)
    text = "\n".join(r.text)
    assert "Password: Hunter-22x" in text and "dddzzz" not in text


# ---------------------------------------------------------------- recall / decoys
def test_recall_against_truth(corpus, analyzed):
    _, truth = corpus
    by_file, _, _, fa = analyzed
    missed = []
    for e in truth["expect"]:
        if e["rule"] == "doc_gps" and not fa.exe:
            continue
        if not any(f["rule"] == e["rule"] and e["value"].lower() in str(f["value"]).lower() and f["severity"] in SHOWN for f in by_file.get(e["file"], [])):
            missed.append(e)
    assert missed == []


def test_decoys_and_placeholders(corpus, analyzed):
    _, truth = corpus
    by_file, _, inv, _ = analyzed
    for d in truth["decoy_files"]:
        assert [f for f in by_file.get(d, []) if f["severity"] in SHOWN] == []
    assert not {"Microsoft Office User", "Administrator", "Artist", "unknown", "LW"} & set(inv["people"])
    assert {"Jordan Smith", "priya.raman", "Lisa Wong", "Mark Chen", "Tom Nguyen", "Dana Williams"} <= set(inv["people"])


def test_local_paths_never_reported(analyzed):
    by_file, records, _, _ = analyzed
    for fs in by_file.values():
        for f in fs:
            assert "/tmp" not in str(f["value"]) and "pytest" not in str(f["value"])
    for r in records:
        assert not any(k.lower().startswith(("file:", "system:")) for k in r["metadata"])


@pytest.mark.skipif(not EXIFTOOL, reason="exiftool not available")
def test_exif_noise_dropped(analyzed):
    _, records, inv, _ = analyzed
    photo = next(r for r in records if r["url"].endswith("photo.jpg"))
    plain = next(r for r in records if r["url"].endswith("plain.jpg"))
    assert photo["exiftool_tags"] > 30 and photo["metadata_values_kept"] <= 6
    assert plain["metadata_values_kept"] == 0  # Make/Model/Artist=Artist/Copyright=Copyright/resolution: all noise
    assert "Apple iPhone 15 Pro #F2LXK9Q1ABCD" in inv["devices"]


@pytest.mark.parametrize(
    "value,kind",
    [
        ("Jordan Smith", "person"), ("priya.raman", "person"), ("Microsoft Office User", None), ("Administrator", None), ("Artist", None),
        ("an author", None), ("Author: Jeff", "person"), ("LibreOffice 24.2", "tool"), ("Writer", None), ("Impress", "tool"), ("cairo 1.16.0 (https://cairographics.org)", "tool"),
        ("uTorrent/1840", "tool"), ("12345", None), ("", None), ("bad_list_type_A", None),
    ],
)
def test_person_vs_tool(value, kind):
    assert F.classify_person(value)[0] == kind


def test_path_and_share_patterns():
    fa = F.FileAnalyzer("acme.com", exiftool=False)
    out, inv = [], {k: {} for k in ("usernames", "internal_hosts")}
    fa._file_seen = set()
    fa._patterns("C:\\Users\\jsmith\\AppData\\x.dotm  /home/build/x  \\\\FS01\\Finance  \\\\backslash\\nnewline  http://(removed)/x  http://wiki.acme.local/a",
                 "t", "u", out, inv)
    vals = {(f["rule"], f["value"]) for f in out}
    assert ("doc_username", "jsmith") in vals and ("doc_internal_share", "\\\\FS01\\Finance") in vals and ("doc_internal_host", "wiki.acme.local") in vals
    assert not any("build" == v or "backslash" in v or "removed" in v for _, v in vals)


# ---------------------------------------------------------------- hostile input / sandbox
def test_hostile_files(corpus):
    d, _ = corpus
    h = os.path.join(d, "hostile")
    assert "unsafe:xml_entity_declaration" in ex(os.path.join(h, "xxe.docx"))["flags"]
    assert "unsafe:xml_entity_declaration" in ex(os.path.join(h, "laughs.svg"))["flags"]
    assert ex(os.path.join(h, "invoice.pdf"))["errors"] == ["refused_executable"]
    for name in ("bomb.zip", "bomb.pdf", "corrupt.pdf"):
        r = ex(os.path.join(h, name))
        assert len(r["text"]) < 1000


def test_plain_doctype_allowed():
    root = extract.safe_xml(b'<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg/>')
    assert root is not None
    with pytest.raises(extract.Unsafe):
        extract.safe_xml(b'<!DOCTYPE x [<!ELEMENT x ANY>]><x/>')


@pytest.mark.skipif(os.name != "posix", reason="rlimits are POSIX only")
@pytest.mark.parametrize("code,expect", [
    ("x = bytearray(6_000_000_000)\nprint('{}')", "exit_1"),
    ("import time\ntime.sleep(60)", "extract_timeout"),
])
def test_sandbox_limits(tmp_path, monkeypatch, code, expect):
    script = tmp_path / "child.py"
    script.write_text(code)
    monkeypatch.setattr(F, "EXTRACT_PY", str(script))
    r = F.run_extract("/dev/null", str(tmp_path), timeout=4)
    assert expect in r["flags"]


@pytest.mark.skipif(os.name != "posix", reason="rlimits are POSIX only")
def test_sandbox_cannot_write_files(tmp_path, monkeypatch):
    target = tmp_path / "out.txt"
    script = tmp_path / "child.py"
    script.write_text(f"open({str(target)!r}, 'w').write('x' * 100)\nprint('{{}}')")
    monkeypatch.setattr(F, "EXTRACT_PY", str(script))
    F.run_extract("/dev/null", str(tmp_path), timeout=10)
    assert not target.exists() or target.stat().st_size == 0


def test_old_exiftool_refused(tmp_path):
    for ver, ok in (("12.10", False), ("12.37", False), ("12.38", True), ("13.64", True)):
        fake = tmp_path / f"exiftool-{ver}"
        fake.write_text(f"#!/bin/sh\necho {ver}\n")
        fake.chmod(0o700)
        exe, msg = F.find_exiftool(str(fake))
        assert (exe is not None) == ok, msg


# ---------------------------------------------------------------- crawl-side download gate
def _spider(tmp_path, **over):
    from types import SimpleNamespace

    from reconspider.crawl import TargetSpider

    o = dict(include_subdomains=False, max_subdomains=15, entropy=False, signatures=True, ignore_patterns=[], suppress_values=[], max_assets=400,
             max_pages=300, max_depth=4, max_per_template=8, max_text_bytes=10**6, max_asset_bytes=10**6, max_map_bytes=10**6, probe=False, seed=True,
             probe_sourcemaps=False, include_vendor=False, files=True, files_images=True, max_files=100, max_images=150, max_file_bytes=10**7,
             files_any_host=False, files_root=str(tmp_path))
    o.update(over)
    return TargetSpider("https://acme.com/", SimpleNamespace(**o), sink=lambda s, f: None)


def _resp(url, body, ctype="application/pdf"):
    from scrapy.http import Request, Response

    return Response(url, status=200, body=body, headers={"Content-Type": ctype}, request=Request(url))


def test_download_gate_and_quarantine(tmp_path):
    sp = _spider(tmp_path)
    sp.parse_file(_resp("https://acme.com/a/invoice.pdf", b"MZ\x90\x00" + b"\x00" * 200))  # exe named .pdf
    sp.parse_file(_resp("https://acme.com/a/missing.pdf", b"<!doctype html><html>Not found</html>", "text/html"))  # soft 404
    sp.parse_file(_resp("https://acme.com/a/run.sh.pdf", b"#!/bin/sh\necho pwned\n"))
    sp.parse_file(_resp("https://acme.com/a/report.docx", b"PK\x03\x04" + b"\x00" * 100, "application/octet-stream"))
    sp.parse_file(_resp("https://acme.com/b/same.docx", b"PK\x03\x04" + b"\x00" * 100))  # same bytes, other URL
    assert sp.stats["files_rejected_type"] == 2 and sp.stats["files_rejected_html"] == 1 and sp.stats["files_saved"] == 1 and sp.stats["files_duplicate"] == 1
    saved = sp.downloads[0]
    assert saved["path"].endswith(".docx.quarantine") and "report" not in os.path.basename(saved["path"])
    assert oct(os.stat(saved["path"]).st_mode & 0o777) == "0o600"
    assert saved["urls"] == ["https://acme.com/a/report.docx", "https://acme.com/b/same.docx"]


def test_file_requests_scoped_and_capped(tmp_path):
    sp = _spider(tmp_path, max_files=2)
    assert sp.file_request("https://cdn.other.net/x.pdf", "doc") is None  # off-site without --files-any-host
    assert sp.file_request("https://acme.com/a.pdf", "doc") is not None
    assert sp.file_request("https://acme.com/a.pdf?v=2", "doc") is None  # cache-buster dedupe
    assert sp.file_request("https://acme.com/b.pdf", "doc") is not None
    assert sp.file_request("https://acme.com/c.pdf", "doc") is None  # cap
    assert sp.page_request("https://acme.com/setup.exe", None) is None  # executables never requested
    assert _spider(tmp_path, files_any_host=True).file_request("https://cdn.other.net/x.pdf", "doc") is not None


def test_gps_rejects_nan_and_out_of_range():
    fa = F.FileAnalyzer("acme.com", exiftool=False)
    inv = {k: {} for k in ("people", "software", "companies", "usernames", "internal_hosts", "devices", "flags")}
    for lat, lon, n in ((float("nan"), float("nan"), 0), (123.0, 10.0, 0), (0.0, 0.0, 0), (-33.8688, 151.2093, 1)):
        out, _ = fa._one({"url": "u", "path": "p"}, {"meta": {"EXIF-fallback:GPSLatitude": lat, "EXIF-fallback:GPSLongitude": lon}}, {}, inv)
        assert sum(f["rule"] == "doc_gps" for f in out) == n
