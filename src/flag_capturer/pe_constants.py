"""Carve encoded text following small, zero-padded constants in PE data."""
import re
import struct


_TOKEN = re.compile(rb"[A-Za-z0-9+/]{8,}={0,2}")
_SHIFTED_FLAG = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,19}\{[ -~]{1,200}?\}")


def _data_sections(blob):
    if len(blob) < 64 or blob[:2] != b"MZ":
        return
    offset = struct.unpack_from("<I", blob, 60)[0]
    if offset + 24 > len(blob) or blob[offset:offset + 4] != b"PE\0\0":
        return
    count = struct.unpack_from("<H", blob, offset + 6)[0]
    optional_size = struct.unpack_from("<H", blob, offset + 20)[0]
    table = offset + 24 + optional_size
    if count > 96 or table + count * 40 > len(blob):
        return
    for i in range(count):
        header = table + i * 40
        if blob[header:header + 8].rstrip(b"\0") not in (b".rdata", b".data"):
            continue
        size, start = struct.unpack_from("<II", blob, header + 16)
        if start + size <= len(blob):
            yield memoryview(blob)[start:start + size]


def encoded_constants(blob, xor=True):
    for section in _data_sections(blob):
        # A small constant can occupy a whole alignment slot before an array.
        for pos in range(0, min(len(section) - 16, 64 * 1024), 16):
            key = bytes(section[pos:pos + 16]).rstrip(b"\0")
            if not 1 <= len(key) <= 8:
                continue
            payload = section[pos + 16:pos + 16 + 512]
            if len(key) == 1:
                shift = key[0]
                decoded = bytes((v - shift) % 256 for v in payload)
                token = _SHIFTED_FLAG.match(decoded)
                if token:
                    yield f"subtract({shift})", token.group()
            if xor:
                decoded = bytes(v ^ key[i % len(key)] for i, v in enumerate(payload))
                token = _TOKEN.match(decoded)
                if token:
                    yield f"xor({key.hex()})", token.group()
