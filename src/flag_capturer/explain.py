"""Offline walkthroughs for recorded search paths. Recipe input is the original file."""
import io
import re
import struct

from .pe_constants import pe_header


def _sections(data):
    header = pe_header(data)
    if header is not None:
        opt = header + 24
        magic = data[opt:opt+2]
        base = None
        if magic == b"\x0b\x02":
            base = int.from_bytes(data[opt+24:opt+32], "little")
        elif magic == b"\x0b\x01":
            base = int.from_bytes(data[opt+28:opt+32], "little")
        table = opt + int.from_bytes(data[header+20:header+22], "little")
        count = int.from_bytes(data[header+6:header+8], "little")
        if count <= 96 and table + count*40 <= len(data):
            for n in range(count):
                entry = table + 40*n
                rva, size, offset = struct.unpack_from("<III", data, entry+12)
                name = data[entry:entry+8].rstrip(b"\0").decode("ascii", "backslashreplace")
                yield name, offset, rva, size, base
    elif data.startswith(b"\x7fELF"):
        from elftools.common.exceptions import ELFError
        from elftools.elf.elffile import ELFFile
        try:
            for section in ELFFile(io.BytesIO(data)).iter_sections():
                if section["sh_flags"] & 2 and section["sh_type"] != "SHT_NOBITS":
                    yield section.name, section["sh_offset"], section["sh_addr"], section["sh_size"], 0
        except (ELFError, ValueError, IndexError, KeyError, struct.error):
            return


def _located(detail, sections):
    d = dict(detail)
    for name, offset, address, size, base in sections:
        if d.get("rva") is not None:
            delta = d["rva"] - address
        elif "offset" in d:
            delta = d["offset"] - offset
        elif "va" in d and base is not None:
            delta = d["va"] - base - address
        else:
            continue
        if 0 <= delta < size:
            d.update(offset=offset + delta, section=name)
            if base is not None:
                d.update(va=base + address + delta, image_base=base)
                if "function_rva" in d:
                    d["function"] = base + d["function_rva"]
                if "xref_rvas" in d:
                    d["xrefs"] = [base+x for x in d["xref_rvas"]]
            break
    return d


def hit_evidence(data, layers, chain, span):
    """Translate recorded positions only. Never search a file for duplicate bytes or xrefs."""
    stages = []
    for i, metadata in enumerate(layers):
        d = metadata.copy()
        container = d.pop("container", data if i == 0 else b"")
        sections = list(_sections(container)) if container else []
        d = _located(d, sections)
        if "config_rva" in d:
            d["config"] = _located({"rva": d["config_rva"]}, sections)
        if "fragments" in d:
            d["fragments"] = [(pos, _located(dict(f, rva=f.get("rva", f["function_rva"]),
                                  xref_rvas=[f["call_rva"]] + ([f["xref"]] if "xref" in f else [])), sections))
                              for pos, f in d["fragments"]]
        if "literals" in d:
            d["literals"] = [(token, _located({"rva": rva, "length": length}, sections))
                             for token, rva, length, _ in d["literals"]]
        stages.append(d)
    first = stages[0] if stages else {}
    if first.get("fragments"):
        first = first["fragments"][0][1]
    if not any(key in first for key in ("va", "rva", "offset")):
        pos = 0
        if span and all(re.fullmatch(r"rot\d+|xor\(0x[\da-f]+\)|reverse", op) for op in chain):
            pos = len(data)-span[1] if chain.count("reverse") % 2 else span[0]
        if not chain or chain[0] in _BASIC or re.fullmatch(r"lzma|rot\d+|xor\(0x[\da-f]+\)", chain[0]):
            first = _located(dict(first, offset=pos), list(_sections(data)))
    return dict(first, layers=stages, span=span, source_bytes=data)


def _place(d):
    fields = []
    if "offset" in d:
        fields.append(f"file offset {d['offset']:#x}")
    if "va" in d:
        fields.append(f"VA {d['va']:#x}")
    elif "rva" in d:
        fields.append(f"RVA {d['rva']:#x}")
    if "section" in d:
        fields.append(f"section {d['section']}")
    if "role" in d:
        fields.append(d["role"])
    return ", ".join(fields)


def _take(pos, size):
    return f"Take_bytes({pos},{size},false)"


def _replace(pattern, replacement):
    return ("Find_/_Replace({'option':'Regex','string':" + repr(pattern) + "},"
            + repr(replacement) + ",true,false,true,false)")


_WS = _replace(r"\s+", "")
_NUMBERS = _replace(r"^\s+|\s+$", "") + _replace(r"[\s,]+", " ")
_RFC85 = r"0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~"
_BASIC = {
    "base64": ("Decode Base64 with alphabet A-Z a-z 0-9 + / and optional = padding.",
               "From_Base64('A-Za-z0-9+/=',true,false)"),
    "base64url": ("Decode URL-safe Base64 with '-' and '_' in positions 62 and 63.",
                  "From_Base64('A-Za-z0-9-_',true,false)"),
    "base32": ("Uppercase the text and decode Base32 with alphabet A-Z2-7 and = padding.",
               "To_Upper_case('All')From_Base32('A-Z2-7=',true)"),
    "base85": ("Decode RFC 1924 Base85, with no zero-group abbreviation.",
               _WS + f"From_Base85({_RFC85!r},false,'')"),
    "ascii85": ("Decode Adobe Ascii85 between <~ and ~>, alphabet ! through u, zero group z.",
                _WS + "From_Base85('!-u',false,'z')"),
    "hex": ("Remove 0x, \\x, whitespace, colons and commas. Decode each hex pair as a byte.",
            _replace(r"0x|\\x|[\s:,]", "") + "From_Hex('None')"),
    "binary": ("Remove whitespace and read binary in groups of 8, most significant bit first.",
               _WS + "From_Binary('None',8)"),
    "decimal": ("Read decimal byte values separated by whitespace or commas.",
                _NUMBERS + "From_Decimal('Space',false)"),
    "octal": ("Read each three-digit octal value as one byte.",
              _NUMBERS + "From_Octal('Space')"),
    "url": ("URL-decode %HH escapes and preserve literal plus signs.", "URL_Decode(false)"),
    "reverse": ("Reverse the byte order.", "Reverse('Byte')"),
    "rot47": ("Rotate printable ASCII by 47.", "ROT47(47)"),
    "gzip": ("Decompress the gzip stream.", "Gunzip()"),
    "zlib": ("Inflate the zlib-wrapped DEFLATE stream.", "Zlib_Inflate(0,0,'Adaptive',false,true)"),
    "bz2": ("Decompress the bzip2 stream.", "Bzip2_Decompress(false)"),
}


def _transform(label, d):
    if label in _BASIC:
        return _BASIC[label]
    match = re.fullmatch(r"rot(\d+)", label)
    if match:
        n = int(match[1])
        return f"Rotate ASCII letters forward by {n}, preserving case and digits.", f"ROT13(true,true,false,{n})"
    match = re.fullmatch(r"(?:repeating )?xor\((?:0x)?([\da-fA-F]+)\)", label)
    if match:
        key = match[1]
        return (f"XOR each byte with repeating hex key {key}, starting at key byte 0. "
                + (f"In the Decompile window look for byte ^ 0x{key}." if len(key) == 2
                   else "In the Decompile window look for XOR against a repeating key array."),
                "XOR({'option':'Hex','string':'" + key + "'},'Standard',false)")
    match = re.fullmatch(r"subtract\((\d+)\)", label)
    if match:
        n = int(match[1])
        return f"Subtract {n} from each byte modulo 256.", "SUB({'option':'Hex','string':'%02x'})" % n
    if label == "lzma":
        if d.get("xz"):
            return "Decompress the XZ container in Python: data = __import__('lzma').decompress(data)", None
        return "Decompress the LZMA-Alone stream.", "LZMA_Decompress()"
    return f"Apply scanner step {label!r} to the preceding output; no recorded recipe template.", None


def _snippet(label, d):
    """Specialized rules consume binary structures rather than flat byte transforms."""
    if "target centers ->" in label:
        if not set(("axes", "shifts", "length", "seed", "digest_seed", "rounds", "multiplier",
                    "increment", "shift", "prime", "byte_shift")).issubset(d):
            return "Trace the coordinate generator, hash update and xorshift release in the Decompile window. Replay parameters unavailable."
        left, right, final = d["shifts"]
        return (f"In the Decompile window follow the two coordinate updates and the release loop. "
                f"Read {d['length']} ciphertext bytes from {_place(d)}. With those bytes as data, run:\n"
                f"mask = (1 << 64) - 1\ns, h = {d['seed']:#x}, {d['digest_seed']:#x}\n"
                f"for _ in range({d['rounds']}):\n    for width, offset in {d['axes']!r}:\n"
                f"        s = (s * {d['multiplier']:#x} + {d['increment']:#x}) & mask\n"
                f"        coord = ((s >> {d['shift']}) & 0xffffffff) % width + offset\n"
                f"        h = ((h ^ coord) * {d['prime']:#x}) & mask\n"
                f"out = bytearray()\nfor b in data:\n    h ^= (h << {left}) & mask\n"
                f"    h ^= h >> {right}\n    h ^= (h << {final}) & mask\n"
                f"    out.append(b ^ ((h >> {d['byte_shift']}) & 255))\ndata = bytes(out)")
    if label.startswith("IOC candidate:"):
        if not {"length", "config_length", "config", "field", "seed", "method"}.issubset(d):
            return "Trace WriteFile's buffer and byte count, InternetConnectA's host, and the assembly load in the written script. Buffer parameters unavailable."
        return (f"In the Decompile window follow WriteFile's buffer and length, then InternetConnectA's host. "
                f"Copy {d['length']} script bytes at {_place(d)} into raw and {d['config_length']} bytes "
                f"at {_place(d['config'])} into cfg. Python:\nimport hashlib\n"
                f"def decode(buf):\n    return bytes(v ^ (({d['seed']} + i) & 255) for i, v in enumerate(buf))\n"
                f"script = decode(raw)\nhost = decode(cfg).split(b'\\0')[{d['field']}]\n"
                "digest = hashlib.sha256(script).hexdigest()[:16].encode()\n"
                f"method = {d['method']!r}\n"
                "assert method in script\ndata = b'_'.join((digest, host, method))")
    affine = re.fullmatch(r"decode integer array \(scale (-?\d+), offset (-?\d+)\)", label)
    if affine:
        scale, bias = affine.groups()
        return (f"In the Decompile window look for multiplication by {scale} and addition of {bias}. "
                f"Python: import struct\ndata = bytes((v - ({bias})) // {scale} "
                "for v, in struct.iter_unpack('<I', data))")
    if label.startswith("connect IPv4"):
        address = d.get("octets")
        return ("In the Decompile window find connect. Inspect RSI (sockaddr_in) and RDX (16). Check "
                "AF_INET (2) and read offsets 4..7 in memory order. "
                + (f"The call is at {d['callsite']:#x}. " if "callsite" in d else "")
                + (f"The recovered bytes are {address.hex(' ')}. " if address else "")
                + "Python: ip = '.'.join(map(str, sockaddr[4:8])). Put ip inside the requested flag wrapper.")
    if label == "join little-endian literals":
        entries = d.get("immediates", [])
        return ("Read the MOV immediates in the assembly listing up to the next label or RET. "
                "Keep each literal's full width. Python:\n"
                + (f"hex_literals = {[h for _, h in entries]!r}\n" if entries else "")
                + "data = b''.join(bytes.fromhex(h)[::-1] for h in hex_literals)")
    if label == "join checked fragments by input offset":
        parts = []
        code = ["import base64, codecs, struct", "parts = {}"]
        for pos, f in d.get("fragments", []):
            where = _place(f)
            fun = f.get("function")
            refs = ", ".join(hex(v) for v in f.get("xrefs", []))
            parts.append(f"input +{pos}: {f['action']} at {where}"
                         + (f", immediates {[v.hex() for v in f['literals']]}" if "literals" in f else "")
                         + (f", {f['length']} bytes" if "length" in f else "")
                         + (f", function {fun:#x}" if fun is not None else "")
                         + (f", references {refs}" if refs else ""))
            if "literals" in f:
                code.append(f"parts[{pos}] = b''.join(v.rstrip(b'\\0') for v in {f['literals']!r})")
            elif "offset" in f and "length" in f:
                code.append(f"chunk = data[{f['offset']}:{f['offset'] + f['length']}]")
                action = f["action"]
                if action == "ROT13":
                    expr = "codecs.decode(chunk.decode('ascii'), 'rot13').encode()"
                elif action == "Base64":
                    expr = "base64.b64decode(chunk)"
                elif action.startswith("XOR with "):
                    expr = f"bytes(v ^ {action.split()[-1]} for v in chunk)"
                else:
                    expr = "bytes(v - 2*i for i, (v,) in enumerate(struct.iter_unpack('<I', chunk)))"
                code.append(f"parts[{pos}] = {expr}")
        code.append("data = b''.join(parts[i] for i in sorted(parts))")
        return ("In the Decompile window follow the input pointer passed to each comparison. "
                + ("\n".join(parts) + "\nPython with data as the PE:\n" + "\n".join(code)
                   if parts else "Record the decoded fragments and join them in increasing input-offset order."))
    if label.startswith(".NET "):
        literals = d.get("literals", [])
        entries = [f"token {token:#010x}, {v['length']} UTF-16LE bytes at {_place(v)}" for token, v in literals]
        ranges = [(v["offset"], v["length"]) for _, v in literals if "offset" in v]
        operands = (f"operands = [data[p:p+n] for p, n in {ranges!r}]\n"
                    if ranges and len(ranges) == len(literals) else "")
        return (f"Inspect {label} in the method's IL. Follow the ldstr tokens in instruction order. "
                + "; ".join(entries) + "\nPython:\n" + operands
                + "data = ''.join(v.decode('utf-16le') for v in operands).encode()")
    if label.startswith(("UDP packet ", "TCP ")):
        packets = d.get("packets")
        if not packets and "frame_size" in d:
            packets = [(0, d["offset"], d["link"], d["frame_size"], 0, 0)]
        if packets:
            # Stored order and overlap trim are exactly those used by the reassembler.
            ranges = [(pos, size, link, trim) for _, pos, link, size, _, trim in packets]
            return (f"Select {label} in the capture. Read these frames in payload order "
                    "(file offset, frame length, link type, overlap to skip). Python with data as the capture:\n"
                    f"import dpkt\nout = bytearray()\nfor pos, size, link, skip in {ranges!r}:\n"
                    "    frame = data[pos:pos+size]\n    if link == 1: ip = dpkt.ethernet.Ethernet(frame).data\n"
                    "    else: ip = (dpkt.ip6.IP6 if frame[0] >> 4 == 6 else dpkt.ip.IP)(frame)\n"
                    "    out.extend(bytes(ip.data.data)[skip:])\ndata = bytes(out)")
        return f"Inspect {label} and extract its transport payload in sequence order. Frame offsets unavailable."
    return None


def walkthrough(hit):
    evidence = hit.evidence or {}
    layers = evidence.get("layers", ())
    where = _place(evidence)
    steps = ["Open the original input in Ghidra" + (f"; start at {where}." if where else ".")]
    if "va" in evidence:
        steps.append(f"Press G, go to {evidence['va']:#x}.")
    if evidence.get("preview"):
        steps.append(f"Window > Defined Strings, filter for {evidence['preview'].decode('ascii', 'backslashreplace')!r}. "
                     "If undefined, inspect the bytes in the Listing.")
    if "section" in evidence or "va" in evidence:
        refs = ", ".join(hex(v) for v in evidence.get("xrefs", ()))
        steps.append("Right-click > References > Show References to Address."
                     + (f" Recorded references: {refs}." if refs else "")
                     + (f" Open the Decompile window at function {evidence['function']:#x}."
                        if "function" in evidence else ""))
    recipe = []
    for i, label in enumerate(hit.chain):
        d = layers[i] if i < len(layers) else {}
        if i and ("section" in d or "function" in d):
            steps.append(f"In this layer's extracted file, go to {_place(d)}."
                         + (f" Function {d['function']:#x}." if "function" in d else "")
                         + (" References: " + ", ".join(hex(v) for v in d["xrefs"]) if d.get("xrefs") else ""))
        if label in ("strings", "utf16", "carve") or d.get("slice"):
            if "offset" in d and "length" in d:
                steps.append(f"Select {d['length']} bytes at offset {d['offset']:#x} of the current input "
                             f"({label if not d.get('slice') else 'constant array'}).")
                recipe.append(_take(d["offset"], d["length"]))
            else:
                steps.append(f"Select the {label} bytes in the current input; exact range unavailable.")
                recipe.append(None)
            if label == "utf16":
                steps.append("Decode the selected bytes as UTF-16LE.")
                recipe.append("Decode_text('UTF-16LE (1200)')")
            if not d.get("slice"):
                continue
        if label.startswith("zip:"):
            name = label[4:]
            steps.append(f"Extract ZIP member {name!r} and use its exact bytes.")
            if d.get("compression") in (0, 8, 12):
                steps.append(f"Member payload begins at offset {d['offset']:#x}, length {d['length']}; "
                             + {0:"stored.", 8:"raw DEFLATE.", 12:"bzip2."}[d["compression"]])
                recipe.append(_take(d["offset"], d["length"]) +
                              {0:"", 8:"Raw_Inflate(0,0,'Adaptive',false,false)", 12:"Bzip2_Decompress(false)"}[d["compression"]])
            else:
                if "member_header" in d:
                    steps.append("Python: import io, zipfile\nz = zipfile.ZipFile(io.BytesIO(data))\n"
                                 f"data = z.read(next(m for m in z.infolist() if m.header_offset == {d['member_header']}))")
                else:
                    steps.append(f"Python: import io, zipfile\ndata = zipfile.ZipFile(io.BytesIO(data)).read({name!r})")
                recipe.append(None)
            continue
        special = _snippet(label, d)
        if special:
            steps.append(special)
            literals = d.get("literals", [])
            if label.startswith(".NET ") and len(literals) == 1 and "offset" in literals[0][1]:
                literal = literals[0][1]
                recipe.append(_take(literal["offset"], literal["length"]) + "Decode_text('UTF-16LE (1200)')")
            else:
                recipe.append(None)
            if label.startswith(("IOC candidate:", "connect IPv4")):
                steps.append(f"Wrap the recovered value as {hit.flag.split('{', 1)[0]}{{value}}.")
            continue
        for op in label.split(" -> "):
            description, operation = _transform(op, d)
            steps.append(description)
            recipe.append(operation)
    span = evidence.get("span")
    if span and (span[0] or span[1] != span[2]):
        steps.append(f"Take {span[1]-span[0]} bytes at offset {span[0]:#x} in the decoded result.")
        recipe.append(_take(span[0], span[1]-span[0]))
    if not hit.chain:
        steps.append("Read the matching bytes directly as text.")
    complete = None if None in recipe else "".join(recipe)
    if complete is None:
        steps.append("A single CyberChef recipe is unavailable for this path. Use the manual or Python steps above.")
    return {"steps": steps, "cyberchef": complete}
