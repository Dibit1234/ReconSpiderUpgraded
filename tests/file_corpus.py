"""Builds a labelled corpus of documents/images for the file-analysis tests.

    python tests/file_corpus.py OUTDIR

Writes OUTDIR/<files> and OUTDIR/truth.json. Secret-shaped values are generated
at runtime (no token literals in the repo). LibreOffice (soffice) and
ExifTool are used when available to produce converted formats and real
EXIF/XMP; anything missing is skipped and recorded in truth.json.
"""

import base64
import binascii
import json
import os
import random
import shutil
import string
import subprocess
import sys
import zipfile

R = random.Random(4242)
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def rnd(n, a=string.ascii_letters + string.digits):
    return "".join(R.choice(a) for _ in range(n))


def gh_token():
    body = rnd(30)
    n = binascii.crc32(body.encode()) & 0xFFFFFFFF
    s = ""
    while n:
        n, r = divmod(n, 62)
        s = B62[r] + s
    return "gh" + "p_" + body + s.rjust(6, "0")


SEC = {
    "vpn_pw": "Wint3r-2026!",
    "comment_pw": "Adm1n#Prod",
    "aws_id": "AK" + "IA" + rnd(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    "aws_secret": rnd(20) + "/" + rnd(19),
    "payroll_pw": "Pa55-Payroll-9",
    "gh": gh_token(),
    "sql_pw": "Fin@nce2026",
    "demo_pw": "Demo!2026x",
    "csv_pw": "Gr33n-Apple-77",
    "env_pw": "pr0d-Mysql-4471",
    "slack": "https://hooks.slack" + ".com/services/T" + rnd(8, string.ascii_uppercase + string.digits) + "/B" + rnd(8, string.ascii_uppercase + string.digits) + "/" + rnd(24),
    "zip_env_pw": "Zip-Env-9x4Q2",
}

# expectation: (file, rule, value-substring). "people"/"software" go to the inventory.
TRUTH = []
PEOPLE = []
DECOY_FILES = []
NOTES = []


def expect(fname, rule, value):
    TRUTH.append({"file": fname, "rule": rule, "value": value})


# --------------------------------------------------------------------------- #
# OOXML builders
# --------------------------------------------------------------------------- #

CT_BASE = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>{over}</Types>'
RELS = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{rels}</Relationships>'
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def core_xml(creator, last):
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>Quarterly ops</dc:title><dc:creator>{creator}</dc:creator><cp:lastModifiedBy>{last}</cp:lastModifiedBy><cp:revision>14</cp:revision>'
            '<dcterms:created xsi:type="dcterms:W3CDTF">2026-03-02T01:10:00Z</dcterms:created></cp:coreProperties>')


def app_xml(app, company, template="Normal.dotm"):
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            f'<Template>{template}</Template><TotalTime>312</TotalTime><Application>{app}</Application><Company>{company}</Company><AppVersion>16.0000</AppVersion></Properties>')


def write_zip(path, parts):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)


def para(text):
    from xml.sax.saxutils import escape

    return f"<w:p><w:r><w:t xml:space=\"preserve\">{escape(text)}</w:t></w:r></w:p>"


def make_docx(path, creator, last, company, body_lines, template_target=None, links=(), comment=None, tracked_author=None, macro=False, extra_xml=""):
    W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = "".join(para(t) for t in body_lines)
    if tracked_author:
        body += f'<w:p><w:ins w:id="1" w:author="{tracked_author}" w:date="2026-03-03T00:00:00Z"><w:r><w:t>Updated figures.</w:t></w:r></w:ins></w:p>'
    hyper_rels = "".join(f'<Relationship Id="rIdL{i}" Type="{R_NS}/hyperlink" Target="{t}" TargetMode="External"/>' for i, t in enumerate(links))
    body += "".join(f'<w:p><w:hyperlink r:id="rIdL{i}"><w:r><w:t>link {i}</w:t></w:r></w:hyperlink></w:p>' for i in range(len(links)))
    doc = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>{extra_xml}<w:document xmlns:w="{W}" xmlns:r="{R_NS}"><w:body>{body}</w:body></w:document>'
    over = ('<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>')
    doc_rels = f'<Relationship Id="rIdS" Type="{R_NS}/settings" Target="settings.xml"/>' + hyper_rels
    parts = {}
    if comment:
        author, text = comment
        over += '<Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>'
        doc_rels += f'<Relationship Id="rIdC" Type="{R_NS}/comments" Target="comments.xml"/>'
        parts["word/comments.xml"] = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:comments xmlns:w="{W}"><w:comment w:id="0" w:author="{author}" w:initials="LW"><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:comment></w:comments>'
    settings = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:settings xmlns:w="{W}" xmlns:r="{R_NS}">'
    settings_rels = ""
    if template_target:
        settings += '<w:attachedTemplate r:id="rIdT"/>'
        settings_rels = f'<Relationship Id="rIdT" Type="{R_NS}/attachedTemplate" Target="{template_target}" TargetMode="External"/>'
    settings += "</w:settings>"
    if macro:
        over += '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
        doc_rels += '<Relationship Id="rIdV" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>'
        parts["word/vbaProject.bin"] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512 + b"Attribute VB_Name = \"ThisDocument\"\r\nSub AutoOpen()\r\nEnd Sub"
    parts.update({
        "[Content_Types].xml": CT_BASE.format(over=over),
        "_rels/.rels": RELS.format(rels=f'<Relationship Id="rId1" Type="{R_NS}/officeDocument" Target="word/document.xml"/>'
                                         f'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
                                         f'<Relationship Id="rId3" Type="{R_NS}/extended-properties" Target="docProps/app.xml"/>'),
        "word/document.xml": doc,
        "word/_rels/document.xml.rels": RELS.format(rels=doc_rels),
        "word/settings.xml": settings,
        "docProps/core.xml": core_xml(creator, last),
        "docProps/app.xml": app_xml("Microsoft Office Word", company),
    })
    if settings_rels:
        parts["word/_rels/settings.xml.rels"] = RELS.format(rels=settings_rels)
    write_zip(path, parts)


def make_xlsx(path, creator, rows, connection=None, external_link=None, hidden_sheet=False):
    S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    strings = []
    idx = {}

    def si(v):
        if v not in idx:
            idx[v] = len(strings)
            strings.append(v)
        return idx[v]

    def cells(r_i, row):
        out = ""
        for c_i, v in enumerate(row):
            ref = f"{chr(65 + c_i)}{r_i}"
            out += f'<c r="{ref}" t="s"><v>{si(v)}</v></c>'
        return f'<row r="{r_i}">{out}</row>'

    from xml.sax.saxutils import escape

    sheet = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="{S}"><sheetData>' + "".join(cells(i + 1, r) for i, r in enumerate(rows)) + "</sheetData></worksheet>"
    sst = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="{S}" count="{len(strings)}" uniqueCount="{len(strings)}">' + "".join(f"<si><t>{escape(s)}</t></si>" for s in strings) + "</sst>"
    sheets = '<sheet name="Systems" sheetId="1" r:id="rId1"/>' + ('<sheet name="creds" sheetId="2" state="hidden" r:id="rId2"/>' if hidden_sheet else "")
    wb = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="{S}" xmlns:r="{R_NS}"><sheets>{sheets}</sheets></workbook>'
    wb_rels = (f'<Relationship Id="rId1" Type="{R_NS}/worksheet" Target="worksheets/sheet1.xml"/>'
               + (f'<Relationship Id="rId2" Type="{R_NS}/worksheet" Target="worksheets/sheet2.xml"/>' if hidden_sheet else "")
               + f'<Relationship Id="rId9" Type="{R_NS}/sharedStrings" Target="sharedStrings.xml"/>')
    over = ('<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>')
    parts = {}
    if hidden_sheet:
        over += '<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        parts["xl/worksheets/sheet2.xml"] = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="{S}"><sheetData/></worksheet>'
    if connection:
        from xml.sax.saxutils import quoteattr

        over += '<Override PartName="/xl/connections.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml"/>'
        wb_rels += f'<Relationship Id="rId8" Type="{R_NS}/connections" Target="connections.xml"/>'
        parts["xl/connections.xml"] = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><connections xmlns="{S}"><connection id="1" name="Finance" type="1"><dbPr connection={quoteattr(connection)} command="SELECT * FROM payroll"/></connection></connections>'
    if external_link:
        over += '<Override PartName="/xl/externalLinks/externalLink1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml"/>'
        wb_rels += f'<Relationship Id="rId7" Type="{R_NS}/externalLink" Target="externalLinks/externalLink1.xml"/>'
        parts["xl/externalLinks/externalLink1.xml"] = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><externalLink xmlns="{S}" xmlns:r="{R_NS}"><externalBook r:id="rId1"/></externalLink>'
        parts["xl/externalLinks/_rels/externalLink1.xml.rels"] = RELS.format(rels=f'<Relationship Id="rId1" Type="{R_NS}/externalLinkPath" Target="{external_link}" TargetMode="External"/>')
    parts.update({
        "[Content_Types].xml": CT_BASE.format(over=over),
        "_rels/.rels": RELS.format(rels=f'<Relationship Id="rId1" Type="{R_NS}/officeDocument" Target="xl/workbook.xml"/>'
                                         f'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
                                         f'<Relationship Id="rId3" Type="{R_NS}/extended-properties" Target="docProps/app.xml"/>'),
        "xl/workbook.xml": wb, "xl/_rels/workbook.xml.rels": RELS.format(rels=wb_rels),
        "xl/worksheets/sheet1.xml": sheet, "xl/sharedStrings.xml": sst,
        "docProps/core.xml": core_xml(creator, creator), "docProps/app.xml": app_xml("Microsoft Excel", "Acme Corp", template=""),
    })
    write_zip(path, parts)


def make_pptx(path, creator, slide_text, notes_text):
    P = "http://schemas.openxmlformats.org/presentationml/2006/main"
    A = "http://schemas.openxmlformats.org/drawingml/2006/main"

    def sp(t):
        return f'<p:sp><p:txBody><a:p><a:r><a:t>{t}</a:t></a:r></a:p></p:txBody></p:sp>'

    slide = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sld xmlns:p="{P}" xmlns:a="{A}" xmlns:r="{R_NS}"><p:cSld><p:spTree>{"".join(sp(t) for t in slide_text)}</p:spTree></p:cSld></p:sld>'
    notes = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:notes xmlns:p="{P}" xmlns:a="{A}"><p:cSld><p:spTree>{sp(notes_text)}</p:spTree></p:cSld></p:notes>'
    over = ('<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
            '<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
            '<Override PartName="/ppt/notesSlides/notesSlide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>')
    pres = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentation xmlns:p="{P}" xmlns:r="{R_NS}"><p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst><p:sldSz cx="9144000" cy="6858000"/></p:presentation>'
    write_zip(path, {
        "[Content_Types].xml": CT_BASE.format(over=over),
        "_rels/.rels": RELS.format(rels=f'<Relationship Id="rId1" Type="{R_NS}/officeDocument" Target="ppt/presentation.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'),
        "ppt/presentation.xml": pres,
        "ppt/_rels/presentation.xml.rels": RELS.format(rels=f'<Relationship Id="rId2" Type="{R_NS}/slide" Target="slides/slide1.xml"/>'),
        "ppt/slides/slide1.xml": slide,
        "ppt/slides/_rels/slide1.xml.rels": RELS.format(rels=f'<Relationship Id="rId1" Type="{R_NS}/notesSlide" Target="../notesSlides/notesSlide1.xml"/>'),
        "ppt/notesSlides/notesSlide1.xml": notes,
        "docProps/core.xml": core_xml(creator, creator),
    })


# --------------------------------------------------------------------------- #
# Corpus
# --------------------------------------------------------------------------- #


def build(out):
    os.makedirs(out, exist_ok=True)
    soffice = None if os.environ.get("RS_CORPUS_NO_SOFFICE") else (shutil.which("soffice") or shutil.which("libreoffice"))
    exiftool = os.environ.get("EXIFTOOL") or shutil.which("exiftool")

    # -- Word
    make_docx(
        os.path.join(out, "report.docx"), "Jordan Smith", "priya.raman", "Acme Corp",
        ["Quarterly operations report", "VPN credentials for the contractor team:", "Username: svc_vpn", f"Password: {SEC['vpn_pw']}",
         f"Backup bucket key {SEC['aws_id']} secret {SEC['aws_secret']}", "Jump host details are in \\\\acme-fs01\\it\\jump.txt", "See the wiki for anything else."],
        template_target="file:///C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Templates\\Acme.dotm",
        links=["file:///\\\\acme-fs01\\finance\\Q3-forecast.xlsx", "http://intranet.acme.local/hr/policies"],
        comment=("Lisa Wong", f"the admin password is {SEC['comment_pw']}"), tracked_author="Mark Chen",
    )
    for rule, v in (("doc_username", "jsmith"), ("doc_internal_share", "acme-fs01"), ("doc_internal_host", "intranet.acme.local"),
                    ("generic_password", SEC["vpn_pw"]), ("generic_password", SEC["comment_pw"]), ("aws_access_key_id", SEC["aws_id"])):
        expect("report.docx", rule, v)
    PEOPLE.extend(["Jordan Smith", "priya.raman", "Lisa Wong", "Mark Chen"])

    make_docx(os.path.join(out, "macro.docm"), "Ops", "Ops", "", ["Enable content to view this document."], macro=True)
    expect("macro.docm", "doc_macros", "macro.docm")

    # decoy: placeholders and default metadata only -> nothing >= low, no people
    make_docx(os.path.join(out, "decoy.docx"), "Microsoft Office User", "Administrator", "", [
        "Password: ********", "Username: <your username>", "Enter your password to continue.", "Reset token: (sent by email)",
        "Password requirements: at least 12 characters", "API key: YOUR_API_KEY_HERE", "Password: changeme",
    ])
    DECOY_FILES.append("decoy.docx")

    # -- Excel
    make_xlsx(
        os.path.join(out, "budget.xlsx"), "Priya Raman",
        [["System", "Username", "Password"], ["Payroll", "payroll_admin", SEC["payroll_pw"]], ["CRM", "crm_api", SEC["gh"]], ["Wiki", "wiki_ro", "********"]],
        connection=f"Provider=SQLOLEDB.1;Password={SEC['sql_pw']};Persist Security Info=True;User ID=sa;Initial Catalog=Finance;Data Source=SQLPROD01\\FIN",
        external_link="file:///\\\\acme-fs02\\shared\\rates.xlsx", hidden_sheet=True,
    )
    for rule, v in (("generic_password", SEC["payroll_pw"]), ("github_token", SEC["gh"]), ("connection_string_password", SEC["sql_pw"]),
                    ("doc_data_connection", "SQLPROD01"), ("doc_internal_share", "acme-fs02")):
        expect("budget.xlsx", rule, v)
    PEOPLE.append("Priya Raman")

    # -- PowerPoint
    make_pptx(os.path.join(out, "deck.pptx"), "Tom Nguyen", ["Migration plan", "Jump host 10.42.7.15 (jump01.acme.corp)"], f"demo login is demo_user and the password is {SEC['demo_pw']}")
    for rule, v in (("internal_ip", "10.42.7.15"), ("doc_internal_host", "jump01.acme.corp"), ("generic_password", SEC["demo_pw"])):
        expect("deck.pptx", rule, v)
    PEOPLE.append("Tom Nguyen")

    # -- text formats
    with open(os.path.join(out, "users.csv"), "w") as fh:
        fh.write(f"email,username,password\nalice@acme-corp.com,alice,{SEC['csv_pw']}\nbob@acme-corp.com,bob,********\n")
    expect("users.csv", "generic_password", SEC["csv_pw"])
    with open(os.path.join(out, "notes.txt"), "w") as fh:
        fh.write(f"deploy notes\nDB_HOST=db01.acme.internal\nDB_PASSWORD={SEC['env_pw']}\nalerts go to {SEC['slack']}\n")
    expect("notes.txt", "generic_password", SEC["env_pw"])
    expect("notes.txt", "slack_webhook", SEC["slack"])
    expect("notes.txt", "doc_internal_host", "db01.acme.internal")

    # -- SVG with Inkscape export path
    with open(os.path.join(out, "logo.svg"), "w") as fh:
        fh.write('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" '
                 'xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd" xmlns:dc="http://purl.org/dc/elements/1.1/" '
                 'xmlns:cc="http://creativecommons.org/ns#" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" width="10" height="10" '
                 'sodipodi:docname="logo-final.svg" inkscape:export-filename="C:\\Users\\dwilliams\\Desktop\\logo-final.png">'
                 '<metadata><rdf:RDF><cc:Work><dc:creator><cc:Agent><dc:title>Dana Williams</dc:title></cc:Agent></dc:creator></cc:Work></rdf:RDF></metadata>'
                 '<rect width="10" height="10"/></svg>')
    expect("logo.svg", "doc_username", "dwilliams")
    PEOPLE.append("Dana Williams")

    # -- images
    try:
        from PIL import Image, PngImagePlugin
    except ImportError:
        Image = None
        NOTES.append("Pillow missing: image files skipped")
    if Image:
        img = Image.new("RGB", (64, 48), (120, 160, 200))
        img.save(os.path.join(out, "photo.jpg"), quality=80)
        img.save(os.path.join(out, "plain.jpg"), quality=80)
        DECOY_FILES.append("plain.jpg")
        info = PngImagePlugin.PngInfo()
        info.add_text("Author", "Dana Williams")
        info.add_text("Comment", "exported from \\\\acme-design\\brand\\logo-master.ai")
        info.add_text("Software", "Adobe Illustrator 28.0 (Windows)")
        img.save(os.path.join(out, "logo.png"), pnginfo=info)
        expect("logo.png", "doc_internal_share", "acme-design")
        img.save(os.path.join(out, "scan.tif"))
        if exiftool:
            def et(f, *args):
                subprocess.run([exiftool, "-q", "-overwrite_original", *args, os.path.join(out, f)], check=False, capture_output=True)

            et("photo.jpg", "-GPSLatitude=33.8688", "-GPSLatitudeRef=S", "-GPSLongitude=151.2093", "-GPSLongitudeRef=E", "-Make=Apple",
               "-Model=iPhone 15 Pro", "-SerialNumber=F2LXK9Q1ABCD", "-Artist=Sam Lee", "-Software=Adobe Photoshop 25.0 (Windows)",
               "-XMP-xmp:CreatorTool=Adobe Photoshop 25.0 (Windows)", "-ImageDescription=Server room, level 3")
            expect("photo.jpg", "doc_gps", "-33.86880,151.20930")
            PEOPLE.append("Sam Lee")
            et("plain.jpg", "-Make=Canon", "-Model=Canon EOS R6", "-Artist=Artist", "-Copyright=Copyright", "-XResolution=300", "-ImageDescription=          ")
            et("scan.tif", "-Software=Canon iR-ADV C5535", "-HostComputer=FINANCE-PC07", "-Artist=unknown")
            expect("scan.tif", "doc_internal_host", "finance-pc07")
        else:
            NOTES.append("exiftool missing: EXIF/GPS not written")

    # -- archive with nested docs, secrets and a traversal name
    pem_body = base64.b64encode(bytes(R.getrandbits(8) for _ in range(900))).decode()
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(pem_body[i:i + 70] for i in range(0, len(pem_body), 70)) + "\n-----END OPENSSH PRIVATE KEY-----\n"
    with zipfile.ZipFile(os.path.join(out, "backup.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("site/.env", f"APP_ENV=prod\nDB_PASSWORD={SEC['zip_env_pw']}\n")
        z.writestr("keys/id_rsa", pem)
        z.writestr("../../etc/cron.d/evil", "* * * * * root id")  # path traversal name: must be harmless
        z.write(os.path.join(out, "report.docx"), "docs/report.docx")
    expect("backup.zip", "generic_password", SEC["zip_env_pw"])
    expect("backup.zip", "private_key", "PRIVATE KEY")
    expect("backup.zip", "generic_password", SEC["vpn_pw"])

    # -- conversions with real office software
    if soffice:
        conv = [("report.docx", "pdf"), ("report.docx", "odt"), ("report.docx", "doc"), ("report.docx", "rtf"),
                ("budget.xlsx", "ods"), ("budget.xlsx", "xls"), ("deck.pptx", "odp"), ("deck.pptx", "ppt"), ("deck.pptx", "pdf:impress_pdf_Export")]
        for src, fmt in conv:
            ext = fmt.split(":")[0]
            target = os.path.splitext(src)[0] + "." + ext
            if src == "deck.pptx" and ext == "pdf":
                target = "deck.pdf"
            tmp = os.path.join(out, "_conv")
            os.makedirs(tmp, exist_ok=True)
            subprocess.run([soffice, "--headless", "--norestore", "--convert-to", fmt, "--outdir", tmp, os.path.join(out, src)], capture_output=True, timeout=180)
            produced = os.path.join(tmp, os.path.splitext(src)[0] + "." + ext)
            if os.path.exists(produced):
                shutil.move(produced, os.path.join(out, target))
                NOTES.append(f"converted {src} -> {target}")
            else:
                NOTES.append(f"conversion failed: {src} -> {ext}")
        shutil.rmtree(os.path.join(out, "_conv"), ignore_errors=True)
    else:
        NOTES.append("LibreOffice missing: converted formats skipped")

    # -- hostile files
    hostile = os.path.join(out, "hostile")
    os.makedirs(hostile, exist_ok=True)
    with zipfile.ZipFile(os.path.join(hostile, "bomb.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.txt", b"\x00" * 150_000_000)
    make_docx(os.path.join(hostile, "xxe.docx"), "x", "x", "", ["&xxe;"], extra_xml='<!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>')
    lol = '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">' + "".join(f'<!ENTITY {chr(98 + i)} "{("&" + chr(97 + i) + ";") * 10}">' for i in range(8)) + ']><svg xmlns="http://www.w3.org/2000/svg"><text>&i;</text></svg>'
    open(os.path.join(hostile, "laughs.svg"), "w").write(lol)
    open(os.path.join(hostile, "invoice.pdf"), "wb").write(b"MZ\x90\x00" + os.urandom(4000))  # executable renamed .pdf
    open(os.path.join(hostile, "soft404.pdf"), "w").write("<!doctype html><html><body>Page not found</body></html>")
    open(os.path.join(hostile, "corrupt.pdf"), "wb").write(b"%PDF-1.7\n" + os.urandom(20000))
    # flate stream that inflates to ~1.2 GB: decompression bomb inside a PDF
    import zlib

    comp = zlib.compressobj(9)
    chunk = b"0" * 1_000_000
    stream = b"".join(comp.compress(chunk) for _ in range(1200)) + comp.flush()
    objs = [b"<</Type/Catalog/Pages 2 0 R>>", b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>",
            b"<</Length " + str(len(stream)).encode() + b"/Filter/FlateDecode>>stream\n" + stream + b"\nendstream"]
    pdf, offsets = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offsets.append(len(pdf))
        pdf += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(pdf)
    pdf += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode() + b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    pdf += f"trailer<</Size {len(objs) + 1}/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF".encode()
    open(os.path.join(hostile, "bomb.pdf"), "wb").write(pdf)

    truth = {"expect": TRUTH, "people": sorted(set(PEOPLE)), "decoy_files": DECOY_FILES, "notes": NOTES,
             "hostile": sorted(os.listdir(hostile)), "secrets": SEC}
    with open(os.path.join(out, "truth.json"), "w") as fh:
        json.dump(truth, fh, indent=2)
    return truth


if __name__ == "__main__":
    t = build(sys.argv[1])
    print(json.dumps({k: (len(v) if isinstance(v, list) else v) for k, v in t.items() if k != "secrets"}, indent=1))
    print("\n".join(t["notes"]))
