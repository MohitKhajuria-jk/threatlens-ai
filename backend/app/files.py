"""Uploaded files: unpacking compressed logs safely, and identifying files for the hash check."""

from __future__ import annotations

import hashlib
import io
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath


class UnpackError(ValueError):
    pass


GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = b"PK\x03\x04"
EMPTY_ZIP = b"PK\x05\x06"
MAX_ZIP_MEMBERS = 50
CHUNK = 1024 * 1024


def is_archive(raw: bytes) -> bool:
    return raw[:2] == GZIP_MAGIC or raw[:4] in (ZIP_MAGIC, EMPTY_ZIP)


def _gunzip(raw: bytes, limit: int) -> bytes:
    """Decompresses in steps so a tiny file that expands to gigabytes (a "zip bomb") is stopped at `limit`."""
    out = bytearray()
    data = raw
    while data:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            while data:
                out += d.decompress(data, CHUNK)
                if len(out) > limit:
                    raise UnpackError(f"it expands to more than {limit // (1024 * 1024)} MB")
                data = d.unconsumed_tail
                if d.eof:
                    break
        except zlib.error as err:
            raise UnpackError("the .gz file is damaged") from err
        if not d.eof:
            raise UnpackError("the .gz file is cut short")
        data = d.unused_data  # concatenated gzip members (logrotate can produce these)
        if data and data[:2] != GZIP_MAGIC:
            break
    return bytes(out)


def _unzip(raw: bytes, limit: int) -> list[tuple[str, bytes]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as err:
        raise UnpackError("the .zip file is damaged") from err
    members = [m for m in archive.infolist() if not m.is_dir() and not PurePosixPath(m.filename).name.startswith(".") and "__MACOSX" not in m.filename]
    if len(members) > MAX_ZIP_MEMBERS:
        raise UnpackError(f"it holds {len(members)} files; the limit is {MAX_ZIP_MEMBERS}")
    files: list[tuple[str, bytes]] = []
    total = 0
    for m in members:
        if m.flag_bits & 0x1:
            raise UnpackError("it is password-protected")
        buf = bytearray()
        try:
            with archive.open(m) as fh:  # read in steps rather than trusting the sizes the archive claims
                while chunk := fh.read(CHUNK):
                    buf += chunk
                    total += len(chunk)
                    if total > limit:
                        raise UnpackError(f"it expands to more than {limit // (1024 * 1024)} MB")
        except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError) as err:
            raise UnpackError(f"{m.filename} inside it can't be read") from err
        files.append((PurePosixPath(m.filename).name, bytes(buf)))
    return files


def unpack(name: str, raw: bytes, limit: int) -> list[tuple[str, bytes]]:
    """Returns the log files inside a .gz or .zip upload (one level deep), or the upload itself.
    A .gz inside a .zip is unpacked too, since rotated logs are often zipped up together."""
    if raw[:2] == GZIP_MAGIC:
        inner = name[:-3] if name.lower().endswith(".gz") else name
        if inner.lower().endswith(".tar"):
            raise UnpackError(".tar.gz archives aren't supported; upload the log files or a .zip")
        return [(inner, _gunzip(raw, limit))]
    if raw[:4] in (ZIP_MAGIC, EMPTY_ZIP):
        out: list[tuple[str, bytes]] = []
        budget = limit
        for inner_name, data in _unzip(raw, limit):
            if data[:2] == GZIP_MAGIC:
                inner_name = inner_name[:-3] if inner_name.lower().endswith(".gz") else inner_name
                data = _gunzip(data, budget)
            elif data[:4] == ZIP_MAGIC:
                raise UnpackError(f"{inner_name} inside it is another .zip; unzip it first")
            budget -= len(data)
            if budget < 0:
                raise UnpackError(f"it expands to more than {limit // (1024 * 1024)} MB")
            out.append((f"{name}/{inner_name}", data))
        if not out:
            raise UnpackError("it's empty")
        return out
    return [(name, raw)]


# ---------------------------------------------------------------- identifying files for the hash check

SIGNATURES: list[tuple[int, bytes, str]] = [
    (0, b"MZ", "Windows program or library (PE)"),
    (0, b"\x7fELF", "Linux program or library (ELF)"),
    (0, b"\xcf\xfa\xed\xfe", "macOS program (Mach-O)"),
    (0, b"\xfe\xed\xfa\xcf", "macOS program (Mach-O)"),
    (0, b"\xca\xfe\xba\xbe", "macOS universal program or Java class"),
    (0, b"%PDF", "PDF document"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Older Office document or MSI installer (OLE)"),
    (0, b"{\\rtf", "Rich Text document (RTF)"),
    (0, b"PK\x03\x04", "ZIP archive"),
    (0, b"Rar!\x1a\x07", "RAR archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (0, b"\x1f\x8b", "gzip archive"),
    (0, b"MSCF", "Windows cabinet archive (CAB)"),
    (0, b"\x89PNG\r\n\x1a\n", "PNG image"),
    (0, b"\xff\xd8\xff", "JPEG image"),
    (0, b"GIF8", "GIF image"),
    (0, b"ElfFile\x00", "Windows event log (EVTX)"),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (LNK)"),
    (0x8001, b"CD001", "Disk image (ISO)"),
    (0, b"#!", "Script"),
]
OFFICE_ZIP = {"word/": "Word document (DOCX)", "xl/": "Excel workbook (XLSX)", "ppt/": "PowerPoint presentation (PPTX)"}
RISKY_TYPES = ("PE", "ELF", "Mach-O", "OLE", "RTF", "LNK", "ISO", "Script", "CAB", "Java")


def sniff(head: bytes, archive_names: list[str] | None = None) -> str:
    """Names a file's type from its first bytes (its "magic number"), not from its extension."""
    for offset, magic, label in SIGNATURES:
        if head[offset:offset + len(magic)] == magic:
            if label == "ZIP archive" and archive_names:
                for prefix, office in OFFICE_ZIP.items():
                    if any(n.startswith(prefix) for n in archive_names):
                        return office
                if "AndroidManifest.xml" in archive_names:
                    return "Android app (APK)"
                if "META-INF/MANIFEST.MF" in archive_names:
                    return "Java archive (JAR)"
            return label
    try:
        head[:4096].decode("utf-8")
        return "Text"
    except UnicodeDecodeError:
        return "Unknown binary data"


@dataclass
class FileInfo:
    name: str
    size: int
    type: str
    md5: str
    sha1: str
    sha256: str

    @property
    def risky_type(self) -> bool:
        return any(token in self.type for token in RISKY_TYPES)

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "size": self.size, "type": self.type, "md5": self.md5, "sha1": self.sha1, "sha256": self.sha256,
                "can_run": self.risky_type}


class Hasher:
    """Hashes a file as it streams in, so it never has to be held in memory or saved to disk."""

    def __init__(self, name: str):
        self.name = name
        self.size = 0
        self.head = b""
        self._md5, self._sha1, self._sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()

    def update(self, chunk: bytes) -> None:
        if len(self.head) < 0x8010:
            self.head += chunk[: 0x8010 - len(self.head)]
        self.size += len(chunk)
        for h in (self._md5, self._sha1, self._sha256):
            h.update(chunk)

    def finish(self, archive_names: list[str] | None = None) -> FileInfo:
        return FileInfo(self.name, self.size, sniff(self.head, archive_names), self._md5.hexdigest(), self._sha1.hexdigest(), self._sha256.hexdigest())
