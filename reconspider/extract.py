"""Untrusted-file extractor. Runs in a separate, resource-limited process:

    python -I reconspider/extract.py FILE        -> JSON on stdout

Safety model
------------
* Nothing is ever executed or opened by another application. Every format
  is parsed by pure-Python code (stdlib, plus optional pypdf).
* The file type comes from magic bytes, never the URL or Content-Type.
  Executables and scripts are refused.
* XML parts are rejected if they declare a DOCTYPE/ENTITY (blocks XXE
  and "billion laughs"). OOXML/ODF parts never legitimately contain one.
* Archives are read in memory, member by member, with size and
  compression-ratio caps (zip bombs); members are never written to disk,
  so path traversal names ("../../x") are harmless.
* The parent process applies CPU, memory, file-size (0 = no writes) and
  wall-clock limits, so a parser hang or decompression bomb only kills
  this child.

Only stdlib imports at module level so the child starts fast and never
imports the crawler.
"""

import io
import json
import re
import sys
import zipfile
import zlib
from xml.etree import ElementTree as ET

MAX_TEXT = 2_000_000  # characters of extracted text returned
MAX_PART = 20_000_000  # bytes read from one archive member
MAX_TOTAL_UNZIPPED = 120_000_000
MAX_RATIO = 200  # compressed -> uncompressed ratio considered a bomb
MAX_MEMBERS = 2000
PDF_MAX_PAGES = 80

# --------------------------------------------------------------------------- #
# Type sniffing
# --------------------------------------------------------------------------- #

EXECUTABLE_MAGIC = (
    (b"MZ", "pe"), (b"\x7fELF", "elf"), (b"\xca\xfe\xba\xbe", "macho"), (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"), (b"\xce\xfa\xed\xfe", "macho"), (b"\xcf\xfa\xed\xfe", "macho"),
    (b"#!", "script"), (b"dex\n", "dex"),
)


def sniff(data):
    """Return a coarse kind from content alone."""
    head = data[:16]
    for magic, kind in EXECUTABLE_MAGIC:
        if head.startswith(magic):
            return "executable:" + kind
    if head.startswith(b"%PDF"):
        return "pdf"
    if b"%PDF-" in data[:1024]:
        return "pdf"  # junk before header is legal
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return _sniff_zip(data)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return "tiff"
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"heim", b"heis", b"avif"):
            return "heif"
        return "mp4"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith((b"Rar!", b"7z\xbc\xaf", b"\x1f\x8b", b"BZh")):
        return "archive"
    if b"\x00" in data[:4096] and not head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "binary"
    text = data[:4096].decode("utf-8", "ignore").lstrip("\ufeff \r\n\t").lower()
    if text.startswith(("<!doctype html", "<html", "<head", "<body")) or "<html" in text[:500]:
        return "html"
    if "<svg" in text[:2000]:
        return "svg"
    if text.startswith("<?xml") or text.startswith("<"):
        return "xml"
    return "text"


def _sniff_zip(data):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = set(z.namelist()[:MAX_MEMBERS])
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError):
        return "zip"
    if "mimetype" in names:
        try:
            mt = z.read("mimetype")[:100].decode("ascii", "ignore")
        except (KeyError, zipfile.BadZipFile, ValueError, OSError, NotImplementedError):
            mt = ""
        if "opendocument" in mt:
            return "odf"
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return "docx"
        if any(n.startswith("xl/") for n in names):
            return "xlsx"
        if any(n.startswith("ppt/") for n in names):
            return "pptx"
        if any(n.startswith("visio/") for n in names):
            return "vsdx"
    return "zip"


# --------------------------------------------------------------------------- #
# Safe helpers
# --------------------------------------------------------------------------- #


class Unsafe(Exception):
    pass


def safe_xml(raw):
    """Parse XML bytes, refusing DTDs/entities. Returns root or None."""
    if not raw:
        return None
    low = raw[:200000].lower()
    # A plain <!DOCTYPE svg PUBLIC ...> is harmless (ElementTree never fetches
    # external DTDs). Entity declarations or an internal subset are not.
    m = re.search(rb"<!doctype[^>\[]*(\[)?", low)
    if b"<!entity" in low or (m and m.group(1)):
        raise Unsafe("xml_entity_declaration")
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        return None


def local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


class SafeZip:
    """Bounded, in-memory zip reader. Never extracts to disk."""

    def __init__(self, data):
        self.z = zipfile.ZipFile(io.BytesIO(data))
        self.infos = self.z.infolist()[:MAX_MEMBERS]
        self.names = [i.filename for i in self.infos]
        self.total = 0
        self.flags = []
        if len(self.z.infolist()) > MAX_MEMBERS:
            self.flags.append("archive_truncated")

    def info(self, name):
        try:
            return self.z.getinfo(name)
        except KeyError:
            return None

    def read(self, name, cap=MAX_PART):
        i = self.info(name)
        if i is None:
            return b""
        if i.flag_bits & 0x1:
            self.flags.append("encrypted_member")
            return b""
        if i.file_size > cap:
            self.flags.append("member_too_large")
            return b""
        if i.compress_size and i.file_size / max(i.compress_size, 1) > MAX_RATIO and i.file_size > 1_000_000:
            raise Unsafe("zip_bomb_ratio")
        if self.total + i.file_size > MAX_TOTAL_UNZIPPED:
            raise Unsafe("zip_bomb_total")
        # Read through a bounded stream: never trust the declared size.
        with self.z.open(i) as fh:
            out = fh.read(cap + 1)
        if len(out) > cap:
            raise Unsafe("zip_member_overflow")
        self.total += len(out)
        return out


def xml_text(root, text_tags=("t",), para_tags=("p", "br", "tab", "row", "tr")):
    """Concatenate text nodes, inserting newlines at paragraph-ish tags."""
    if root is None:
        return ""
    parts = []
    for el in root.iter():
        name = local(el.tag)
        if name in para_tags:
            parts.append("\n")
        if name in text_tags and el.text:
            parts.append(el.text)
    return re.sub(r"[ \t]+\n", "\n", "".join(parts))


def attrs_named(root, names):
    out = []
    if root is None:
        return out
    for el in root.iter():
        for k, v in el.attrib.items():
            if local(k) in names and v:
                out.append(v)
    return out


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #


def _clean(v):
    """Drop lone surrogates / undecodable bits so output is valid UTF-8."""
    if not isinstance(v, str):
        v = str(v)
    return v.encode("utf-8", "replace").decode("utf-8")


class Result:
    def __init__(self, kind):
        self.kind = kind
        self.text = []
        self.meta = {}  # name -> value (raw, filtered later by the parent)
        self.links = []
        self.people = []  # (role, value)
        self.flags = []
        self.members = []
        self.errors = []

    def add_text(self, s):
        if s and sum(len(t) for t in self.text) < MAX_TEXT:
            self.text.append(s)

    def to_json(self):
        text = _clean("\n".join(self.text)[:MAX_TEXT])
        self.meta = {_clean(k): _clean(v) for k, v in self.meta.items()}
        self.links = [{k: _clean(v) for k, v in x.items()} for x in self.links]
        self.people = [(a, _clean(b)) for a, b in self.people]
        self.members = [_clean(x) for x in self.members]
        return {
            "kind": self.kind, "text": text, "meta": self.meta, "links": self.links[:2000],
            "people": self.people[:500], "flags": sorted(set(self.flags)), "members": self.members[:500], "errors": self.errors[:20],
        }


# --------------------------------------------------------------------------- #
# OOXML (docx / xlsx / pptx / vsdx)
# --------------------------------------------------------------------------- #

CORE_MAP = {"creator": "Author", "lastModifiedBy": "LastModifiedBy", "title": "Title", "subject": "Subject", "description": "Description",
            "keywords": "Keywords", "category": "Category", "created": "CreateDate", "modified": "ModifyDate", "lastPrinted": "LastPrinted", "revision": "Revision"}
APP_MAP = {"Application": "Application", "AppVersion": "AppVersion", "Company": "Company", "Manager": "Manager", "Template": "Template",
           "HyperlinkBase": "HyperlinkBase", "TotalTime": "TotalEditTime", "DocSecurity": "DocSecurity"}


def ooxml_props(z, r):
    core = safe_xml(z.read("docProps/core.xml"))
    if core is not None:
        for el in core.iter():
            n = local(el.tag)
            if n in CORE_MAP and (el.text or "").strip():
                r.meta[CORE_MAP[n]] = el.text.strip()
    app = safe_xml(z.read("docProps/app.xml"))
    if app is not None:
        for el in app.iter():
            n = local(el.tag)
            if n in APP_MAP and (el.text or "").strip():
                r.meta[APP_MAP[n]] = el.text.strip()
    custom = safe_xml(z.read("docProps/custom.xml"))
    if custom is not None:
        for prop in custom.iter():
            if local(prop.tag) == "property":
                name = prop.attrib.get("name", "")
                val = "".join(x.text or "" for x in prop.iter() if x is not prop)
                if name and val.strip():
                    r.meta["Custom:" + name[:60]] = val.strip()[:500]


def ooxml_rels(z, r):
    """External relationship targets: hyperlinks, templates, linked files."""
    for name in z.names:
        if not name.endswith(".rels"):
            continue
        root = safe_xml(z.read(name, cap=5_000_000))
        if root is None:
            continue
        for el in root.iter():
            if local(el.tag) != "Relationship":
                continue
            target = el.attrib.get("Target", "")
            mode = el.attrib.get("TargetMode", "")
            rtype = el.attrib.get("Type", "").rsplit("/", 1)[-1]
            if mode == "External" and target:
                r.links.append({"type": rtype, "target": target[:1000], "part": name})


def ooxml_common(z, r):
    ooxml_props(z, r)
    ooxml_rels(z, r)
    names = z.names
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        r.flags.append("macros_vba")
    if any("/embeddings/" in n for n in names):
        r.flags.append("embedded_objects")
        r.members += [n for n in names if "/embeddings/" in n][:50]
    # people.xml / comments authors
    for n in names:
        low = n.lower()
        if low.endswith(("people.xml", "persons/person.xml")) or "comments" in low or "threadedcomments" in low:
            root = safe_xml(z.read(n, cap=10_000_000))
            for a in attrs_named(root, {"author", "displayName", "userId"}):
                r.people.append(("comment_author", a))
            if root is not None and "comments" in low:
                r.add_text(xml_text(root, text_tags=("t",)))
        if low.endswith("connections.xml"):
            root = safe_xml(z.read(n, cap=5_000_000))
            for c in attrs_named(root, {"connection", "command", "sourceFile", "url", "odcFile"}):
                r.links.append({"type": "data_connection", "target": c[:2000], "part": n})
                r.add_text(c)


def extract_docx(z, r):
    ooxml_common(z, r)
    for n in z.names:
        if re.match(r"word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$", n):
            root = safe_xml(z.read(n))
            r.add_text(xml_text(root, text_tags=("t", "delText", "instrText")))
            # tracked changes authors
            for el in (root.iter() if root is not None else []):
                if local(el.tag) in ("ins", "del", "moveFrom", "moveTo"):
                    a = next((v for k, v in el.attrib.items() if local(k) == "author"), None)
                    if a:
                        r.people.append(("tracked_change_author", a))
        if n == "word/settings.xml":
            root = safe_xml(z.read(n))
            for el in (root.iter() if root is not None else []):
                if local(el.tag) == "attachedTemplate":
                    r.flags.append("attached_template")


def _col(ref):
    m = re.match(r"([A-Z]+)(\d+)", ref or "")
    if not m:
        return None, None
    c = 0
    for ch in m.group(1):
        c = c * 26 + ord(ch) - 64
    return c, int(m.group(2))


def extract_xlsx(z, r):
    ooxml_common(z, r)
    shared = []
    ss = safe_xml(z.read("xl/sharedStrings.xml"))
    if ss is not None:
        for si in ss.iter():
            if local(si.tag) == "si":
                shared.append("".join(t.text or "" for t in si.iter() if local(t.tag) == "t"))
    wb = safe_xml(z.read("xl/workbook.xml"))
    sheet_names = []
    for el in (wb.iter() if wb is not None else []):
        if local(el.tag) == "sheet":
            sheet_names.append((el.attrib.get("name", ""), el.attrib.get("state", "visible")))
            if el.attrib.get("state") in ("hidden", "veryHidden"):
                r.flags.append("hidden_sheets")
        if local(el.tag) == "definedName" and el.text and ("!" in el.text or "\\" in el.text):
            r.add_text(el.text)
    r.meta["Sheets"] = ", ".join(f"{n} ({s})" if s != "visible" else n for n, s in sheet_names)[:500]
    for n in sorted(x for x in z.names if re.match(r"xl/worksheets/sheet\d+\.xml$", x)):
        root = safe_xml(z.read(n))
        if root is None:
            continue
        rows = {}
        cells = 0
        for c in root.iter():
            if local(c.tag) != "c":
                continue
            cells += 1
            if cells > 200_000:
                r.flags.append("sheet_truncated")
                break
            col, row = _col(c.attrib.get("r"))
            t = c.attrib.get("t")
            val = None
            for ch in c:
                if local(ch.tag) == "v" and ch.text is not None:
                    val = ch.text
                    if t == "s":
                        try:
                            val = shared[int(val)]
                        except (ValueError, IndexError):
                            val = None
                elif local(ch.tag) == "is":
                    val = "".join(x.text or "" for x in ch.iter() if local(x.tag) == "t")
                elif local(ch.tag) == "f" and ch.text and ("[" in ch.text or "\\" in ch.text or "http" in ch.text):
                    r.add_text(ch.text)  # external workbook references in formulas
            if val is not None and row is not None:
                rows.setdefault(row, {})[col] = val
        # Emit "Header: value" lines so the credential detector sees structure
        header = rows.get(min(rows)) if rows else {}
        lines = ["\t".join(header.get(c, "") for c in sorted(header))] if header else []
        for rn in sorted(rows)[1:]:
            row = rows[rn]
            for col, val in sorted(row.items()):
                h = header.get(col)
                lines.append(f"{h}: {val}" if h and len(str(h)) < 40 else str(val))
        r.add_text("\n".join(lines))
    # pivot/query caches can embed source connection strings
    for n in z.names:
        if "pivotCacheDefinition" in n or n.startswith("xl/queryTables/"):
            root = safe_xml(z.read(n, cap=5_000_000))
            for a in attrs_named(root, {"connection", "sourceFile", "url"}):
                r.links.append({"type": "data_source", "target": a[:2000], "part": n})


def extract_pptx(z, r):
    ooxml_common(z, r)
    for n in sorted(z.names):
        if re.match(r"ppt/(slides/slide|notesSlides/notesSlide)\d+\.xml$", n):
            r.add_text(xml_text(safe_xml(z.read(n)), text_tags=("t",)))


def extract_vsdx(z, r):
    ooxml_common(z, r)
    for n in z.names:
        if re.match(r"visio/pages/page\d+\.xml$", n):
            r.add_text(xml_text(safe_xml(z.read(n)), text_tags=("Text",), para_tags=("Shape",)))


# --------------------------------------------------------------------------- #
# ODF (odt / ods / odp)
# --------------------------------------------------------------------------- #

ODF_META = {"initial-creator": "Author", "creator": "LastModifiedBy", "generator": "Generator", "title": "Title", "subject": "Subject",
            "description": "Description", "keyword": "Keywords", "creation-date": "CreateDate", "date": "ModifyDate", "printed-by": "PrintedBy"}


def extract_odf(z, r):
    meta = safe_xml(z.read("meta.xml"))
    for el in (meta.iter() if meta is not None else []):
        n = local(el.tag)
        if n in ODF_META and (el.text or "").strip():
            r.meta[ODF_META[n]] = el.text.strip()
        if n == "user-defined" and (el.text or "").strip():
            name = next((v for k, v in el.attrib.items() if local(k) == "name"), "field")
            r.meta["Custom:" + name[:60]] = el.text.strip()[:500]
    content = safe_xml(z.read("content.xml"))
    r.add_text(_odf_text(content))
    for href in attrs_named(content, {"href"}):
        if not href.startswith("#"):
            r.links.append({"type": "hyperlink", "target": href[:1000], "part": "content.xml"})
    for a in [el.text for el in (content.iter() if content is not None else []) if local(el.tag) == "creator" and el.text]:
        r.people.append(("comment_author", a))
    settings = safe_xml(z.read("settings.xml"))
    for el in (settings.iter() if settings is not None else []):
        if local(el.tag) == "config-item" and any(local(k) == "name" and v == "PrinterName" for k, v in el.attrib.items()) and el.text:
            r.meta["PrinterName"] = el.text.strip()
    if any(n.startswith(("Basic/", "Scripts/")) for n in z.names):
        r.flags.append("macros_basic")


def _odf_text(root):
    if root is None:
        return ""
    out = []

    def walk(el):
        n = local(el.tag)
        if n == "table":
            rows = []
            for row in el.iter():
                if local(row.tag) == "table-row":
                    cells = []
                    for c in row:
                        if local(c.tag) == "table-cell":
                            txt = " ".join("".join(x.itertext()).strip() for x in c if local(x.tag) == "p").strip()
                            rep_n = next((int(v) for k, v in c.attrib.items() if local(k) == "number-columns-repeated" and v.isdigit()), 1)
                            cells.extend([txt] * min(rep_n, 50))
                    rows.append(cells)
                    if len(rows) > 20000:
                        break
            out.append(_rows_to_lines(rows) + "\n")
            return
        if el.text:
            out.append(el.text)
        for ch in el:
            walk(ch)
            if ch.tail:
                out.append(ch.tail)
        if n in ("p", "h", "table-row", "list-item"):
            out.append("\n")
        elif n in ("table-cell",):
            out.append("\t")

    walk(root)
    return "".join(out)


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #


def extract_pdf(data, r):
    if re.search(rb"/(?:JavaScript|JS)\s*[(<\[/]", data[:20_000_000]) or b"/OpenAction" in data[:20_000_000] and b"/JS" in data[:20_000_000]:
        r.flags.append("pdf_javascript")
    if b"/EmbeddedFile" in data[:20_000_000]:
        r.flags.append("embedded_files")
    if b"/Encrypt" in data[:20_000_000]:
        r.flags.append("encrypted")
    try:
        import pypdf  # optional, pure Python
    except ImportError:
        r.errors.append("pypdf_not_installed: PDF text skipped (metadata via exiftool)")
        _pdf_info_regex(data, r)
        return
    import logging

    logging.getLogger("pypdf").setLevel(logging.ERROR)
    try:
        pdf = pypdf.PdfReader(io.BytesIO(data), strict=False)
        if pdf.is_encrypted:
            try:
                pdf.decrypt("")
            except Exception:  # noqa: BLE001 - library raises many types
                r.errors.append("encrypted")
                return
        info = pdf.metadata or {}
        for k, v in dict(info).items():
            if v is not None:
                r.meta[str(k).lstrip("/")] = str(v)[:1000]
        try:
            xmp = pdf.xmp_metadata
            if xmp is not None:
                for attr, name in (("dc_creator", "XMP:Creator"), ("xmp_creator_tool", "XMP:CreatorTool"), ("pdf_producer", "XMP:Producer")):
                    v = getattr(xmp, attr, None)
                    if v:
                        r.meta[name] = ", ".join(v) if isinstance(v, list) else str(v)
        except Exception:  # noqa: BLE001
            pass
        for i, page in enumerate(pdf.pages):
            if i >= PDF_MAX_PAGES:
                r.flags.append("pdf_pages_truncated")
                break
            try:
                r.add_text(_fix_glyph_lines(page.extract_text() or ""))
            except Exception as exc:  # noqa: BLE001
                r.errors.append(f"page{i}: {type(exc).__name__}")
            try:
                for annot in page.get("/Annots") or []:
                    a = annot.get_object()
                    uri = (a.get("/A") or {}).get("/URI") if hasattr(a, "get") else None
                    if uri:
                        r.links.append({"type": "hyperlink", "target": str(uri)[:1000], "part": f"page{i + 1}"})
            except Exception:  # noqa: BLE001
                pass
        try:
            names = list((pdf.attachments or {}).keys())
            if names:
                r.members += names[:100]
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001 - malformed PDFs raise anything
        r.errors.append(f"pdf_parse: {type(exc).__name__}")
        _pdf_info_regex(data, r)


def _fix_glyph_lines(t):
    """Some exporters place each glyph separately; pypdf then returns one
    character per line ("M\\ni\\ng..."). Rejoin when that dominates."""
    lines = t.split("\n")
    if len(lines) > 20 and sum(len(x) <= 1 for x in lines) / len(lines) > 0.6:
        return "".join(x if x else "\n" for x in lines)
    return t


def _pdf_info_regex(data, r):
    for key in (b"Author", b"Creator", b"Producer", b"Title", b"Subject", b"Company"):
        m = re.search(rb"/" + key + rb"\s*\(((?:\\.|[^\\)]){1,300})\)", data[:5_000_000])
        if m and key.decode() not in r.meta:
            r.meta[key.decode()] = m.group(1).decode("latin-1", "ignore")


# --------------------------------------------------------------------------- #
# RTF, OLE (legacy Office), SVG, PNG text, text
# --------------------------------------------------------------------------- #


def extract_rtf(data, r):
    s = data[:30_000_000].decode("latin-1", "ignore")
    for key, name in (("author", "Author"), ("operator", "LastModifiedBy"), ("company", "Company"), ("title", "Title"), ("manager", "Manager")):
        m = re.search(r"\{\\" + key + r"\s+([^{}]{1,300})\}", s)
        if m:
            r.meta[name] = m.group(1).strip()
    # Drop pictures/binary blobs, then control words and groups
    s = re.sub(r"\{\\\*?\\(?:pict|object|bin|fonttbl|colortbl|stylesheet|info|themedata|colorschememapping|datastore|xmlnstbl|listtable|listoverridetable|rsidtbl|generator)[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", " ", s)
    s = re.sub(r"\\'([0-9a-fA-F]{2})", lambda m: bytes.fromhex(m.group(1)).decode("cp1252", "ignore"), s)
    s = re.sub(r"\\u(-?\d+)\??", lambda m: chr(int(m.group(1)) % 65536), s)
    s = re.sub(r"\\(?:par|line|row|cell)\b ?", "\n", s)
    s = re.sub(r"\\[a-zA-Z]+-?\d* ?|\\[^a-zA-Z]|[{}]", "", s)
    r.add_text(s)


def extract_ole(data, r):
    """Legacy .doc/.xls/.ppt. Metadata comes from exiftool; text is
    recovered as printable runs (UTF-16LE and cp1252). Runs shorter than
    8 chars and runs that are mostly symbols are dropped (binary junk)."""
    if b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data and b"P\x00R\x00O\x00J\x00E\x00C\x00T" in data:
        r.flags.append("macros_vba")
    if b"W\x00o\x00r\x00k\x00b\x00o\x00o\x00k\x00" in data[:200_000] and _xls_rows(data, r):
        return
    runs = []
    for m in re.finditer(rb"(?:[\x20-\x7e\xa0-\xff][\x00]){8,}", data[:40_000_000]):
        runs.append(m.group(0).decode("utf-16-le", "ignore"))
    for m in re.finditer(rb"[\x20-\x7e\t\r\n]{8,}", data[:40_000_000]):
        runs.append(m.group(0).decode("cp1252", "ignore"))
    good = []
    for s in runs:
        letters = sum(ch.isalnum() or ch == " " for ch in s)
        tripled = sum(len(m.group(0)) for m in re.finditer(r"(.)\1\1+", s))
        if letters / max(len(s), 1) >= 0.75 and re.search(r"[A-Za-z]{3}", s) and tripled / len(s) < 0.3 and len(set(s)) / len(s) > 0.15:
            good.append(s.strip())
    r.add_text("\n".join(good))
    r.flags.append("text_from_strings")


def _xls_rows(data, r):
    try:
        import xlrd  # optional, pure Python, .xls only
    except ImportError:
        return False
    try:
        wb = xlrd.open_workbook(file_contents=data, on_demand=True, logfile=io.StringIO())
    except Exception:  # noqa: BLE001 - malformed files raise anything
        return False
    for sh in wb.sheets()[:50]:
        if sh.visibility:
            r.flags.append("hidden_sheets")
        rows = [[str(c.value).strip() for c in sh.row(i)] for i in range(min(sh.nrows, 20000))]
        r.add_text(_rows_to_lines(rows))
    try:
        for k in ("author", "last_modified_by"):
            v = getattr(wb, "user_name", "") if k == "last_modified_by" else ""
            if v:
                r.meta["LastModifiedBy"] = v
    except AttributeError:
        pass
    r.flags.append("text_from_xlrd")
    return True


def _rows_to_lines(rows):
    """Table -> "Header: value" lines (first non-empty row is the header)."""
    rows = [row for row in rows if any(c for c in row)]
    if not rows:
        return ""
    header = rows[0]
    lines = ["\t".join(header)]
    for row in rows[1:]:
        for i, v in enumerate(row):
            if not v:
                continue
            h = header[i] if i < len(header) else ""
            lines.append(f"{h}: {v}" if h and len(h) < 40 else v)
    return "\n".join(lines)


def extract_svg(data, r):
    s = data[:20_000_000]
    root = safe_xml(s)
    if root is None:
        r.add_text(s.decode("utf-8", "ignore"))
        return
    for el in root.iter():
        for k, v in el.attrib.items():
            n = local(k)
            if n in ("export-filename", "docname", "absref") and v:
                r.meta["SVG:" + n] = v[:500]
            if n == "href" and v and not v.startswith(("data:", "#")):
                r.links.append({"type": "href", "target": v[:1000], "part": "svg"})
        if local(el.tag) in ("title", "desc", "text", "tspan", "rights", "description") and el.text and el.text.strip():
            r.add_text(el.text.strip())
    for el in root.iter():
        if local(el.tag) == "creator":
            name = " ".join((x.text or "").strip() for x in el.iter() if (x.text or "").strip())
            if name:
                r.people.append(("svg_creator", name))


PNG_TEXT_KEYS = {b"tEXt", b"zTXt", b"iTXt"}


def extract_png_text(data, r):
    pos = 8
    n = 0
    while pos + 8 <= len(data) and n < 500:
        n += 1
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if ctype not in PNG_TEXT_KEYS:
            if ctype == b"IEND":
                break
            continue
        key, _, rest = chunk.partition(b"\x00")
        try:
            if ctype == b"tEXt":
                val = rest.decode("latin-1")
            elif ctype == b"zTXt":
                d = zlib.decompressobj()
                val = d.decompress(rest[1:], 2_000_000).decode("latin-1", "ignore")
            else:
                comp_flag = rest[:1]
                rest = rest[2:].split(b"\x00", 2)[-1]
                val = (zlib.decompressobj().decompress(rest, 2_000_000) if comp_flag == b"\x01" else rest).decode("utf-8", "ignore")
        except (zlib.error, ValueError):
            continue
        k = key.decode("latin-1", "ignore")[:60]
        if k == "XML:com.adobe.xmp":
            r.add_text(val)
        else:
            r.meta["PNG:" + k] = val[:2000]


def extract_text(data, r, kind):
    s = data[:30_000_000].decode("utf-8", "ignore")
    if kind == "text" and "," in s[:2000] and "\n" in s[:4000]:
        s = _csv_to_lines(s) or s
    r.add_text(s)


def _csv_to_lines(s):
    import csv

    try:
        rows = list(csv.reader(io.StringIO(s[:5_000_000])))
    except csv.Error:
        return None
    if len(rows) < 2 or len(rows[0]) < 2 or len(rows[0]) > 200:
        return None
    header = rows[0]
    lines = [", ".join(header)]
    for row in rows[1:20000]:
        for h, v in zip(header, row):
            if v.strip():
                lines.append(f"{h.strip()}: {v.strip()}" if h.strip() and len(h) < 40 else v)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Generic zip (one level deep; nested office docs are parsed too)
# --------------------------------------------------------------------------- #

TEXT_MEMBER_EXT = (".txt", ".csv", ".json", ".xml", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".config", ".env", ".properties",
                   ".sql", ".log", ".md", ".html", ".htm", ".js", ".ps1", ".sh", ".bat", ".py", ".php", ".cs", ".java", ".toml", ".pem", ".key", ".ovpn", ".rdp")


def extract_zip(data, r, depth=0):
    z = SafeZip(data)
    r.flags += z.flags
    r.members += z.names[:500]
    for info in z.infos:
        name = info.filename
        low = name.lower()
        if info.is_dir() or info.file_size == 0:
            continue
        base = low.rsplit("/", 1)[-1]
        if low.endswith(TEXT_MEMBER_EXT) or base.startswith(".env") or base in {"id_rsa", "id_ed25519", "credentials", ".npmrc", ".pgpass", "web.config"}:
            if info.file_size <= 5_000_000:
                r.add_text(f"--- {name} ---\n" + z.read(name, cap=5_000_000).decode("utf-8", "ignore"))
        elif depth == 0 and low.endswith((".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".pdf", ".docm", ".xlsm")) and info.file_size <= 20_000_000:
            inner = z.read(name)
            sub = Result(sniff(inner))
            try:
                dispatch(inner, sub, depth=1)
            except Unsafe as exc:
                r.flags.append(f"unsafe_member:{exc}")
                continue
            r.add_text(f"--- {name} ---\n" + "\n".join(sub.text))
            for k, v in sub.meta.items():
                r.meta.setdefault(f"{name}:{k}"[:120], v)
            r.people += sub.people
            r.links += sub.links
            r.flags += [f"member:{f}" for f in sub.flags]
    r.flags += z.flags


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

OFFICE = {"docx": extract_docx, "xlsx": extract_xlsx, "pptx": extract_pptx, "vsdx": extract_vsdx}


def dispatch(data, r, depth=0):
    k = r.kind
    if k in OFFICE:
        OFFICE[k](SafeZip(data), r)
    elif k == "odf":
        extract_odf(SafeZip(data), r)
    elif k == "zip":
        extract_zip(data, r, depth)
    elif k == "pdf":
        extract_pdf(data, r)
    elif k == "rtf":
        extract_rtf(data, r)
    elif k == "ole":
        extract_ole(data, r)
    elif k == "svg":
        extract_svg(data, r)
    elif k == "png":
        extract_png_text(data, r)
    elif k in ("text", "xml", "html"):
        extract_text(data, r, k)
    if k in ("jpeg", "tiff", "webp", "png"):
        extract_exif_fallback(data, r)
    # gif/heif/mp4/binary: metadata only (exiftool in parent)


EXIF_NAMES = {0x013B: "Artist", 0x0131: "Software", 0x010F: "Make", 0x0110: "Model", 0x013C: "HostComputer", 0x010E: "ImageDescription",
              0x8298: "Copyright", 0xA431: "SerialNumber", 0xA435: "LensSerialNumber", 0xA430: "CameraOwnerName"}


def extract_exif_fallback(data, r):
    """EXIF via Pillow (optional) so GPS/people/devices still work without
    exiftool. Stored under "EXIF-fallback:"; the parent prefers exiftool."""
    try:
        from PIL import Image
    except ImportError:
        return
    Image.MAX_IMAGE_PIXELS = 50_000_000  # Pillow's own decompression-bomb guard
    try:
        with Image.open(io.BytesIO(data)) as im:
            exif = im.getexif()
            for tag, name in EXIF_NAMES.items():
                v = exif.get(tag)
                if v is None:
                    v = exif.get_ifd(0x8769).get(tag)  # Exif sub-IFD (serials, owner)
                if v not in (None, "", b""):
                    r.meta["EXIF-fallback:" + name] = v.decode("latin-1", "ignore") if isinstance(v, bytes) else str(v)
            gps = exif.get_ifd(0x8825)
            if gps and 2 in gps and 4 in gps:
                def dec(dms, ref):
                    d, m, sec = (float(x) for x in dms)
                    val = d + m / 60 + sec / 3600
                    return -val if str(ref).upper() in ("S", "W") else val
                r.meta["EXIF-fallback:GPSLatitude"] = dec(gps[2], gps.get(1, "N"))
                r.meta["EXIF-fallback:GPSLongitude"] = dec(gps[4], gps.get(3, "E"))
    except Exception:  # noqa: BLE001 - malformed images
        return


def main(path):
    with open(path, "rb") as fh:
        data = fh.read(200_000_001)
    r = Result(sniff(data))
    if r.kind.startswith("executable"):
        r.errors.append("refused_executable")
    else:
        try:
            dispatch(data, r)
        except Unsafe as exc:
            r.flags.append(f"unsafe:{exc}")
            r.errors.append(f"refused: {exc}")
        except Exception as exc:  # noqa: BLE001 - hostile input; report, never crash
            r.errors.append(f"{type(exc).__name__}: {str(exc)[:120]}")
    sys.stdout.write(json.dumps(r.to_json(), ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1])
