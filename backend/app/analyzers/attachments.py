"""Attachments, judged by name and declared type only.

The add-on never sends file contents, only metadata and a SHA-256 hash, so
private documents never leave Gmail. That limits what we can see, so these
checks target the tricks that show up in the name itself.
"""
from app.models import Attachment, EmailPayload, Finding, Severity

NAME = "attachments"

EXECUTABLE = {"exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf",
              "hta", "jar", "msi", "lnk", "cpl", "reg", "dll", "iso", "img"}
MACRO_OFFICE = {"docm", "xlsm", "pptm", "xlam", "dotm"}
LOCAL_WEB_PAGE = {"html", "htm", "shtml", "svg"}
ARCHIVE = {"zip", "rar", "7z", "gz", "tar", "cab"}
LOOKS_LIKE_DOCUMENT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "png", "csv"}
EXECUTABLE_MIME_HINTS = ("x-msdownload", "x-dosexec", "x-msdos-program", "x-executable", "javascript", "x-sh")

# U+202E flips the text that follows, so "invoice\u202efdp.exe" is shown as "invoiceexe.pdf".
_RTL_OVERRIDE = "\u202e"


def _extensions(filename: str) -> list[str]:
    # Windows ignores trailing dots and spaces, so "report.exe. " still runs as .exe.
    name = filename.strip().rstrip(". ").lower()
    parts = [p.strip() for p in name.split(".")[1:]]
    return [p for p in parts if p]


def _worst_problem(att: Attachment) -> tuple[str, str, Severity, int] | None:
    """The most serious problem with one file, or None. Checked from worst to mildest."""
    name = att.filename
    exts = _extensions(name)
    last = exts[-1] if exts else ""
    shown = name.replace(_RTL_OVERRIDE, "")[:80]

    if _RTL_OVERRIDE in name:
        return ("File name is visually reversed",
                f'"{shown}" uses a hidden character to disguise its real type.', Severity.CRITICAL, 50)
    if last in EXECUTABLE and len(exts) >= 2 and exts[-2] in LOOKS_LIKE_DOCUMENT:
        return ("Executable disguised as a document",
                f'"{shown}" looks like a .{exts[-2]} file but is really .{last}.', Severity.CRITICAL, 50)
    if last in EXECUTABLE:
        return ("Executable attachment",
                f'"{shown}" is a program, not a document. Opening it runs code.', Severity.HIGH, 40)
    if last in LOOKS_LIKE_DOCUMENT and any(h in att.content_type.lower() for h in EXECUTABLE_MIME_HINTS):
        return ("File type does not match its name",
                f'"{shown}" is named like a .{last} but declared as {att.content_type[:60]}.', Severity.HIGH, 35)
    if last in LOCAL_WEB_PAGE:
        return ("Web page attachment",
                f'"{shown}" opens in the browser. Attached pages are often fake login forms.', Severity.MEDIUM, 25)
    if last in MACRO_OFFICE:
        return ("Office file with macros",
                f'"{shown}" can run macros, a common way to deliver malware.', Severity.MEDIUM, 25)
    if last in ARCHIVE:
        return ("Compressed attachment",
                f'"{shown}" is an archive, which can hide its contents from scanners.', Severity.LOW, 10)
    return None


def analyze(email: EmailPayload) -> list[Finding]:
    # One finding per kind of problem: six ordinary .zip files are one weak
    # signal repeated, not six times the evidence.
    grouped: dict[str, list] = {}
    for att in email.attachments:
        problem = _worst_problem(att)
        if problem:
            title = problem[0]
            if title in grouped:
                grouped[title][4] += 1
            else:
                grouped[title] = [*problem, 1]

    findings = []
    for title, detail, severity, points, count in grouped.values():
        more = f" ({count} attachments like this)" if count > 1 else ""
        findings.append(Finding(analyzer=NAME, title=title, detail=detail + more,
                                severity=severity, points=points))
    return findings
