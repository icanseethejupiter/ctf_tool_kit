"""Carve encoded text following small, zero-padded constants in PE data."""
import base64
import re
import struct

from .fragments import checked_fragments


_TOKEN = re.compile(rb"[A-Za-z0-9+/]{8,}={0,2}")
_SHIFTED_FLAG = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,19}\{[ -~]{1,200}?\}")


def pe_header(blob):
    if len(blob) < 64 or blob[:2] != b"MZ":
        return
    offset = struct.unpack_from("<I", blob, 60)[0]
    if offset + 24 > len(blob) or blob[offset:offset + 4] != b"PE\0\0":
        return
    return offset


def _sections(blob):
    offset = pe_header(blob)
    if offset is None:
        return
    count = struct.unpack_from("<H", blob, offset + 6)[0]
    optional_size = struct.unpack_from("<H", blob, offset + 20)[0]
    table = offset + 24 + optional_size
    if count > 96 or table + count * 40 > len(blob):
        return
    for i in range(count):
        header = table + i * 40
        name = blob[header:header + 8].rstrip(b"\0")
        if name not in (b".rdata", b".data", b".text"):
            continue
        size, start = struct.unpack_from("<II", blob, header + 16)
        if start + size <= len(blob):
            rva = struct.unpack_from("<I", blob, header + 12)[0]
            yield name, rva, memoryview(blob)[start:start + size]


def _periodic_key(data, plain):
    observed = bytes(a ^ b for a, b in zip(data, plain))
    if len(observed) != len(plain):
        return
    for length in range(2, len(observed) - 1):
        if observed[length:] == observed[:-length]:
            return observed[:length]


def _xor(data, key):
    return bytes(v ^ key[i % len(key)] for i, v in enumerate(data))


def _array_candidates(section, prefixes, xor):
    # C strings followed by an aligned byte-shift parameter.
    for token in re.finditer(rb"(?<![^\x00])([!-~]{8,512})\x00{1,8}([^\x00])\x00{3}", section):
        data, shift_byte = token.groups()
        shift = shift_byte[0]
        shifted = bytes((v - shift) % 256 for v in data)
        if _TOKEN.fullmatch(shifted):
            yield f"subtract({shift})", shifted, token.start(1), len(data)
        if not xor or not re.fullmatch(rb"(?:[0-9a-fA-F]{2}){8,}", data):
            continue
        cipher = bytes.fromhex(data.decode())
        for prefix in prefixes:
            # Only complete six-bit groups are known before the flag body.
            head = bytes((v + shift) % 256 for v in prefix)
            known = base64.b64encode(head)[:len(head) * 8 // 6]
            key = _periodic_key(cipher, known)
            if key:
                encoded = _xor(cipher, key)
                if len(encoded) % 4 == 0 and _TOKEN.fullmatch(encoded):
                    plain = base64.b64decode(encoded)
                    result = bytes((v - shift) % 256 for v in plain)
                    if result.startswith(prefix) and _SHIFTED_FLAG.fullmatch(result):
                        yield f"hex -> xor({key.hex()}) -> base64 -> subtract({shift})", result, token.start(1), len(data)

    # Small integers stored one per little-endian 32-bit word.
    for run in re.finditer(rb"(?:[\x01-\xff].\x00\x00){8,220}", section, re.S):
        words = [v for v, in struct.iter_unpack("<I", run.group())]
        for prefix in prefixes:
            if len(prefix) < 2 or len(words) < len(prefix) or prefix[0] == prefix[1]:
                continue
            scale, remainder = divmod(words[0] - words[1], prefix[0] - prefix[1])
            if remainder or not 1 <= scale <= 32:
                continue
            bias = words[0] - scale * prefix[0]
            decoded = bytearray()
            for word in words:
                value, rem = divmod(word - bias, scale)
                if rem or not 32 <= value <= 126:
                    break
                decoded.append(value)
            if decoded.startswith(prefix):
                yield f"decode integer array (scale {scale}, offset {bias})", bytes(decoded), run.start(), 4*len(decoded)


def constant_evidence(blob, xor=True, prefixes=()):
    sections = list(_sections(blob))
    yield from checked_fragments(sections, xor, evidence=True)
    for name, base, section in sections:
        if name == b".text":
            continue
        for label, value, offset, length in _array_candidates(section[:65536], prefixes, xor):
            yield label, value, {"rva": base+offset, "length": length, "slice": True}
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
                    yield f"subtract({shift})", token.group(), {"rva": base+pos+16, "length": token.end(), "slice": True}
            if xor:
                for prefix in prefixes:
                    periodic = _periodic_key(payload, prefix)
                    if periodic:
                        token = _SHIFTED_FLAG.match(_xor(payload, periodic))
                        if token and token.group().startswith(prefix):
                            yield f"repeating xor({periodic.hex()})", token.group(), {"rva": base+pos+16, "length": token.end(), "slice": True}
                decoded = bytes(v ^ key[i % len(key)] for i, v in enumerate(payload))
                token = _TOKEN.match(decoded)
                if token:
                    yield f"xor({key.hex()})", token.group(), {"rva": base+pos+16, "length": token.end(), "slice": True}


def encoded_constants(blob, xor=True, prefixes=()):
    for label, value, _ in constant_evidence(blob, xor, prefixes):
        yield label, value
