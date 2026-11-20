"""Ordered analyzers shared by the CLI and the recursive scanner."""
import io
import zipfile
import zlib
from typing import Iterable

from ..decoders import printable_ratio
from ..pe_constants import encoded_constants, pe_header
from .base import Analyzer, Part
from .capture import CaptureAnalyzer
from .elf import ELFAnalyzer, GhidraELFAnalyzer
from .managed import ManagedAnalyzer


class NativePEAnalyzer:
    def identify(self, data):
        return "Windows PE" if pe_header(data) is not None else ""

    def extract(self, data, *, xor, prefixes):
        for label, value in encoded_constants(data, xor, prefixes):
            yield Part(label, value)


class ZipAnalyzer:
    def identify(self, data):
        return "ZIP" if data.startswith((b"PK\x03\x04", b"PK\x05\x06")) else ""

    def extract(self, data, **options):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                remaining = 50 * 1024 * 1024
                for item in archive.infolist()[:200]:
                    if item.is_dir() or item.file_size > remaining:
                        continue
                    try:
                        value = archive.read(item)
                    except (RuntimeError, zipfile.BadZipFile, EOFError, zlib.error):
                        continue
                    remaining -= len(value)
                    yield Part(f"zip:{item.filename}", value, nested=True)
        except zipfile.BadZipFile:
            return


class FormatRegistry:
    def __init__(self, analyzers: Iterable[Analyzer]):
        self.analyzers = tuple(analyzers)

    def identify(self, data):
        for analyzer in self.analyzers:
            label = analyzer.identify(data)
            if label:
                return label, analyzer
        return ("text" if printable_ratio(data[:4096]) >= 0.95 else "binary"), None


FORMATS = FormatRegistry((CaptureAnalyzer(), ManagedAnalyzer(), NativePEAnalyzer(), ZipAnalyzer(),
                          ELFAnalyzer(), GhidraELFAnalyzer()))
