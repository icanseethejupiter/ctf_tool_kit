"""Correlate indexed-XOR configuration and a statically identifiable script write."""
import hashlib
import re

from .base import Part


_LOCAL = r"(\[rbp [+-] (?:0x[0-9a-f]+|\d+)\])"
_NUMBER = r"(0x[0-9a-f]+|\d+)"
_BUFFER = re.compile(r"lea rax, " + _LOCAL + r"\nmov r8, rax\nmov edx, " + _NUMBER + r"\nlea rax, @(0x[0-9a-f]+)\n"
                     r"mov rcx, rax\ncall (0x[0-9a-f]+)")
_FIELD = re.compile(r"lea rax, " + _LOCAL + r"\nmov edx, " + _NUMBER + r"\nmov rcx, rax\n"
                    r"call (0x[0-9a-f]+)\nmov qword ptr " + _LOCAL + r", rax")
_WRITE_CALL = re.compile(r"lea rdx, " + _LOCAL + r"\nlea rax, \[rbp [^\]]+\]\nmov rcx, rax\ncall (0x[0-9a-f]+)")
_HOST_CALL = re.compile(r"mov rax, qword ptr " + _LOCAL + r"\n(?:mov r8, rcx\n)?mov rcx, rax\ncall (0x[0-9a-f]+)")
_WRITE = re.compile(r"mov r8d, (0x[0-9a-f]+|\d+)\n(?:mov [^\n]+\n){0,3}"
                    r"mov rax, qword ptr @WriteFile\ncall rax")
_LOAD = re.compile(rb"\[(?:System\.)?Reflection\.Assembly\]::Load\b(?=\s*\()", re.I)
_NONCODE = re.compile(rb"""<\#.*?\#>|\#[^\r\n]*|'(?:''|[^'])*'|"(?:`.|[^"`])*" """, re.S | re.X)
_HOST = re.compile(rb"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", re.I)


def _decode(raw, seed):
    return bytes(v ^ ((seed+i) & 255) for i, v in enumerate(raw))


class DroppedScriptRule:
    def recognizes(self, data):
        return b"WriteFile\0" in data and b"InternetConnectA\0" in data

    def extract(self, image):
        if "InternetConnectA" not in image.imports.values():
            return
        writers = {addr: int(match[1], 0) for addr, code in image.functions.items()
                   for match in _WRITE.finditer(code)}
        network = {addr for addr, code in image.functions.items()
                   if re.search(r"mov rdx, qword ptr \[rbp \+ 0x10\]\n(?:[^\n]+\n){0,12}"
                                r"mov rax, qword ptr @InternetConnectA\ncall rax", code)}
        for function, code in image.functions.items():
            writes = [(local, writers[int(addr, 0)]) for local, addr in _WRITE_CALL.findall(code)
                      if int(addr, 0) in writers]
            hosts = {local for local, addr in _HOST_CALL.findall(code) if int(addr, 0) in network}
            if not writes or not hosts:
                continue
            buffers = {}
            for local, length, addr, decoder in _BUFFER.findall(code):
                size = int(length, 0)
                body = image.functions.get(int(decoder, 0), "")
                if 1 <= size <= 65536 and "add edx, ecx\nxor eax, edx" in body:
                    raw = image.read(int(addr, 0), size)
                    if raw:
                        buffers[local] = (decoder, raw, int(addr, 0))
            for config, index, getter, dst in _FIELD.findall(code):
                if dst not in hosts or config not in buffers:
                    continue
                if "add rax, 1\nadd qword ptr" not in image.functions.get(int(getter, 0), ""):
                    continue
                decoder, config_bytes, config_rva = buffers[config]
                for source, size in writes:
                    if source in buffers and buffers[source][0] == decoder:
                        detail = {"function_rva": function, "decoder_rva": int(decoder, 0),
                                  "rva": buffers[source][2], "config_rva": config_rva,
                                  "xref_rvas": image.xrefs.get(buffers[source][2], [])}
                        yield from self._correlate(config_bytes, int(index, 0), buffers[source][1], size, detail)

    def _correlate(self, config, field, raw, size, detail=None):
        if not 1 <= size <= len(raw):
            return
        for seed in range(256):
            head = _decode(raw[:min(size, 32)], seed)
            if not all(32 <= c <= 126 or c in b"\r\n\t" for c in head):
                continue
            script = _decode(raw[:size], seed)
            methods = set(_LOAD.findall(_NONCODE.sub(b" ", script)))
            if len(methods) != 1:
                continue
            fields = _decode(config, seed).split(b"\0")
            if field < len(fields) and _HOST.fullmatch(fields[field]):
                digest = hashlib.sha256(script).hexdigest()[:16].encode()
                method = methods.pop()
                body = b"_".join((digest, fields[field], method))
                yield Part(f"IOC candidate: SHA-256 of {size} write bytes + config host + script call",
                           body, wrap=True, evidence=dict(detail or {}, seed=seed, field=field,
                                                          length=size, config_length=len(config), method=method))
