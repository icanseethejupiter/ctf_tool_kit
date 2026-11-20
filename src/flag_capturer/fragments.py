"""Reassemble literals and common MinGW comparison fragments by input offset."""
import base64
import binascii
import codecs
import re
import struct


def assembly_literals(data):
    chunks = []
    for line in data.splitlines():
        match = re.match(rb"\s*mov\s+r\w+,\s*0x([0-9a-f]{8}|[0-9a-f]{16})\b", line, re.I)
        if match:
            chunks.append(bytes.fromhex(match[1].decode())[::-1])
        elif re.match(rb"\s*(?:ret\b|\w+:)", line):
            if chunks:
                yield b"".join(chunks)
            chunks.clear()
    if chunks:
        yield b"".join(chunks)


def _relative(base, match, group):
    return base + match.end(group) + int.from_bytes(match[group], "little", signed=True)


def _part(code, address, read_data, read_code, xor):
    literals = re.findall(rb"\xc7\x00(.{4})", code, re.S)
    if literals:
        result = b"".join(v.rstrip(b"\0") for v in literals)
        if re.fullmatch(rb"[A-Za-z][A-Za-z0-9_]*\{", result):
            return result
    ref = re.search(rb"\x48\x8d[\x05\x15](.{4})", code, re.S)
    if not ref:
        return
    data = read_data(_relative(address, ref, 1))
    call_length = re.search(rb"\xba(.{4})\x48\x89\xc1\xe8(.{4})", code, re.S)
    if call_length:
        length = int.from_bytes(call_length[1], "little")
        token = data.partition(b"\0")[0]
        helper = read_code(_relative(address, call_length, 2))
        if (len(token) == length and token.isalnum()
                and b"\x83\xe8\x34" in helper and b"\x83\xe8\x54" in helper
                and b"\x6b\xca\x1a" in helper):
            return codecs.decode(token.decode("ascii"), "rot13").encode()
        try:
            decoded = base64.b64decode(token, validate=True)
        except (ValueError, binascii.Error):
            return
        if len(decoded) == length:
            return decoded
    bound = re.search(rb"\x83\x7d\xfc(.)\x7e", code, re.S)
    if not bound:
        return
    count = bound[1][0] + 1
    key = re.search(rb"\xb8(.{4})\x89\xd1\x31\xc1", code, re.S)
    if xor and key and len(data) >= count:
        return bytes(v ^ key[1][0] for v in data[:count])
    if b"\x01\xd2\x8d\x0c\x10" in code and len(data) >= count * 4:
        values = [v - 2*i for i, (v,) in enumerate(struct.iter_unpack("<I", data[:4*count]))]
        if all(32 <= v <= 126 for v in values):
            return bytes(values)


_CALL = re.compile(rb"\x48\x8d\x45(.)"
                   rb"(?:\x48\x83\xc0(.))?\x48\x89\xc1\xe8(.{4})\x85\xc0", re.S)


def checked_fragments(sections, xor):
    def read_data(address):
        for name, start, section in sections:
            if name != b".text" and start <= address < start + len(section):
                offset = address - start
                return bytes(section[offset:offset + 1024])
        return b""

    for name, start, section in sections:
        if name != b".text":
            continue
        def read_code(address):
            offset = address - start
            if 0 <= offset < len(section):
                return bytes(section[offset:offset + 256])
            return b""

        groups = {}
        previous = -100
        for call in _CALL.finditer(section):
            if call.start() - previous > 64:
                groups.clear()
            previous = call.start()
            target = _relative(start, call, 3) - start
            if not 0 <= target < len(section):
                continue
            code = bytes(section[target:target + 256]).partition(b"\x5d\xc3")[0]
            part = _part(code, start + target, read_data, read_code, xor)
            if not part:
                continue
            pieces = groups.setdefault(call[1], {})
            pieces[int.from_bytes(call[2] or b"\0", "little")] = part
            ordered = bytearray()
            for offset in sorted(pieces):
                if offset != len(ordered):
                    break
                ordered.extend(pieces[offset])
            if re.fullmatch(rb"[A-Za-z][A-Za-z0-9_]{1,19}\{[!-~]{1,200}\}", ordered):
                yield "join checked fragments by input offset", bytes(ordered)
