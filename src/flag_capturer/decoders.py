"""Small, dependency-free decoders. Each takes bytes and returns bytes or None."""
from __future__ import annotations

import base64
import bz2
import gzip
import lzma
import re
import zlib
from urllib.parse import unquote_to_bytes

PRINTABLE = bytes(range(32, 127)) + b"\t\n\r"
_WS = re.compile(rb"\s+")


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return 1 - len(b.translate(None, PRINTABLE)) / len(b)


def _b64(b):
    s = _WS.sub(b"", b)
    if len(s) < 8 or not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", s):
        return None
    s = s.rstrip(b"=")
    if len(s) % 4 == 1:
        return None
    try:
        return base64.b64decode(s + b"=" * (-len(s) % 4), validate=True)
    except Exception:
        return None


def _b64url(b):
    s = _WS.sub(b"", b)
    if len(s) < 8 or not re.fullmatch(rb"[A-Za-z0-9_-]+={0,2}", s) or not re.search(rb"[-_]", s):
        return None
    s = s.rstrip(b"=")
    try:
        return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))
    except Exception:
        return None


def _b32(b):
    s = _WS.sub(b"", b).upper()
    if len(s) < 8 or not re.fullmatch(rb"[A-Z2-7]+=*", s):
        return None
    s = s.rstrip(b"=")
    try:
        return base64.b32decode(s + b"=" * (-len(s) % 8))
    except Exception:
        return None


def _b85(b):
    s = _WS.sub(b"", b)
    if len(s) < 10:
        return None
    try:
        return base64.b85decode(s)
    except Exception:
        return None


def _a85(b):
    s = _WS.sub(b"", b)
    if not (s.startswith(b"<~") and s.endswith(b"~>")):
        return None
    try:
        return base64.a85decode(s, adobe=True)
    except Exception:
        return None


def _hex(b):
    s = re.sub(rb"0x|\\x|[\s:,]", b"", b)
    if len(s) < 8 or len(s) % 2 or not re.fullmatch(rb"[0-9a-fA-F]+", s):
        return None
    return bytes.fromhex(s.decode())


def _binary(b):
    s = _WS.sub(b"", b)
    if len(s) < 16 or len(s) % 8 or not re.fullmatch(rb"[01]+", s):
        return None
    return int(s, 2).to_bytes(len(s) // 8, "big")


def _decimal(b):
    if not re.fullmatch(rb"\s*\d{1,3}(?:[\s,]+\d{1,3}){3,}\s*", b):
        return None
    nums = [int(x) for x in re.findall(rb"\d+", b)]
    if max(nums) > 255:
        return None
    return bytes(nums)


def _octal(b):
    if not re.fullmatch(rb"\s*[0-7]{3}(?:[\s,]+[0-7]{3}){3,}\s*", b):
        return None
    nums = [int(x, 8) for x in re.findall(rb"[0-7]{3}", b)]
    if max(nums) > 255:
        return None
    return bytes(nums)


def _url(b):
    if not re.search(rb"%[0-9a-fA-F]{2}", b):
        return None
    return unquote_to_bytes(b)


_ROT13 = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def _rot13(b):
    return b.translate(_ROT13) if re.search(rb"[A-Za-z]", b) else None


def _reverse(b):
    return b[::-1]


def _gzip(b):
    if not b.startswith(b"\x1f\x8b"):
        return None
    try:
        return gzip.decompress(b)
    except Exception:
        return None


def _zlib(b):
    if len(b) < 2 or b[0] != 0x78 or b[1] not in (0x01, 0x5E, 0x9C, 0xDA):
        return None
    try:
        return zlib.decompress(b)
    except Exception:
        return None


def _bz2(b):
    if not b.startswith(b"BZh"):
        return None
    try:
        return bz2.decompress(b)
    except Exception:
        return None


def _lzma(b):
    if not (b.startswith(b"\xfd7zXZ") or b.startswith(b"\x5d\x00\x00")):
        return None
    try:
        return lzma.decompress(b)
    except Exception:
        return None


# (name, function, strict). Strict decoders only fire on input that really looks
# like their format, so their output is always followed up; loose ones are only
# followed when the result looks like text.
DECODERS = [
    ("base64", _b64, True),
    ("base64url", _b64url, True),
    ("base32", _b32, True),
    ("hex", _hex, True),
    ("binary", _binary, True),
    ("decimal", _decimal, True),
    ("octal", _octal, True),
    ("ascii85", _a85, True),
    ("gzip", _gzip, True),
    ("zlib", _zlib, True),
    ("bz2", _bz2, True),
    ("lzma", _lzma, True),
    ("base85", _b85, False),
    ("url", _url, False),
    ("rot13", _rot13, False),
    ("reverse", _reverse, False),
]

# substrings worth cutting out of a longer text and trying on their own
CARVERS = [
    re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}"),
    re.compile(rb"[A-Za-z0-9_-]{16,}={0,2}"),
    re.compile(rb"[A-Z2-7]{16,}={0,6}"),
    re.compile(rb"(?:[0-9a-fA-F]{2}){8,}"),
    re.compile(rb"(?:[01]{8}\s?){4,}"),
    re.compile(rb"<~.+?~>", re.S),
]
