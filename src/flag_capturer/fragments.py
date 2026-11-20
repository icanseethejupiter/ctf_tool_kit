"""Reassemble literals and common MinGW comparison fragments by input offset."""
import base64
import binascii
import codecs
import re
import struct


def assembly_evidence(data):
    chunks = []
    entries = []
    pos = 0
    for line in data.splitlines(keepends=True):
        match = re.match(rb"\s*mov\s+r\w+,\s*0x([0-9a-f]{8}|[0-9a-f]{16})\b", line, re.I)
        if match:
            chunks.append(bytes.fromhex(match[1].decode())[::-1])
            entries.append((pos + match.start(1), match[1].decode()))
        elif re.match(rb"\s*(?:ret\b|\w+:)", line):
            if chunks:
                yield b"".join(chunks), {"offset": entries[0][0], "immediates": entries}
            chunks.clear()
            entries = []
        pos += len(line)
    if chunks:
        yield b"".join(chunks), {"offset": entries[0][0], "immediates": entries}


def assembly_literals(data):
    for value, _ in assembly_evidence(data):
        yield value


def _relative(base, match, group):
    return base + match.end(group) + int.from_bytes(match[group], "little", signed=True)


def _part(code, address, read_data, read_code, xor, detail):
    literals = re.findall(rb"\xc7\x00(.{4})", code, re.S)
    if literals:
        result = b"".join(v.rstrip(b"\0") for v in literals)
        if re.fullmatch(rb"[A-Za-z][A-Za-z0-9_]*\{", result):
            detail.update(action="join immediate bytes in store order", literals=literals)
            return result
    ref = re.search(rb"\x48\x8d[\x05\x15](.{4})", code, re.S)
    if not ref:
        return
    detail.update(rva=_relative(address, ref, 1), xref=address + ref.start())
    data = read_data(detail["rva"])
    call_length = re.search(rb"\xba(.{4})\x48\x89\xc1\xe8(.{4})", code, re.S)
    if call_length:
        length = int.from_bytes(call_length[1], "little")
        token = data.partition(b"\0")[0]
        helper = read_code(_relative(address, call_length, 2))
        if (len(token) == length and token.isalnum()
                and b"\x83\xe8\x34" in helper and b"\x83\xe8\x54" in helper
                and b"\x6b\xca\x1a" in helper):
            detail.update(action="ROT13", length=len(token))
            return codecs.decode(token.decode("ascii"), "rot13").encode()
        try:
            decoded = base64.b64decode(token, validate=True)
        except (ValueError, binascii.Error):
            return
        if len(decoded) == length:
            detail.update(action="Base64", length=len(token))
            return decoded
    bound = re.search(rb"\x83\x7d\xfc(.)\x7e", code, re.S)
    if not bound:
        return
    count = bound[1][0] + 1
    key = re.search(rb"\xb8(.{4})\x89\xd1\x31\xc1", code, re.S)
    if xor and key and len(data) >= count:
        detail.update(action=f"XOR with 0x{key[1][0]:02x}", length=count)
        return bytes(v ^ key[1][0] for v in data[:count])
    if b"\x01\xd2\x8d\x0c\x10" in code and len(data) >= count * 4:
        values = [v - 2*i for i, (v,) in enumerate(struct.iter_unpack("<I", data[:4*count]))]
        if all(32 <= v <= 126 for v in values):
            detail.update(action="read little-endian uint32 words and subtract 2*i", length=4*count)
            return bytes(values)


_CALL = re.compile(rb"\x48\x8d\x45(.)"
                   rb"(?:\x48\x83\xc0(.))?\x48\x89\xc1\xe8(.{4})\x85\xc0", re.S)


def checked_fragments(sections, xor, evidence=False):
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
            detail = {"function_rva": start + target, "call_rva": start + call.start(3) - 1}
            part = _part(code, start + target, read_data, read_code, xor, detail)
            if not part:
                continue
            pieces = groups.setdefault(call[1], {})
            pieces[int.from_bytes(call[2] or b"\0", "little")] = part, detail
            ordered = bytearray()
            used = []
            for offset in sorted(pieces):
                if offset != len(ordered):
                    break
                ordered.extend(pieces[offset][0])
                used.append((offset, pieces[offset][1]))
            if re.fullmatch(rb"[A-Za-z][A-Za-z0-9_]{1,19}\{[!-~]{1,200}\}", ordered):
                hit = "join checked fragments by input offset", bytes(ordered)
                yield (*hit, {"fragments": used}) if evidence else hit
