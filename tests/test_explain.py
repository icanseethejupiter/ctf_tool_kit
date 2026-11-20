import base64
import codecs
import gzip
import io
import json
import re
import struct
import zipfile
import zlib
from contextlib import redirect_stdout

from flag_capturer import scan_bytes
from flag_capturer.cli import main
from flag_capturer.decoders import DECODERS
from flag_capturer.explain import walkthrough
from flag_capturer.finder import Hit
from flag_capturer.pe_constants import _xor


FLAG = b"flag{x0r_1s_n0t_encrypt10n}"
DECODES = {label: decode for label, decode, _ in DECODERS}


def replay(blob, expected_chain):
    original = scan_bytes(blob)
    explained = scan_bytes(blob, explain=True)
    assert original == explained
    hit = next(h for h in explained if h.flag.encode() == FLAG)
    assert hit.chain == expected_chain
    data = hit.evidence["source_bytes"]
    assert data == blob
    assert len(hit.chain) == len(hit.evidence["layers"])
    for label, detail in zip(hit.chain, hit.evidence["layers"]):
        if detail.get("slice") or label in ("strings", "carve") or label.startswith("zip:"):
            start, length = detail["offset"], detail["length"]
            data = data[start:start+length]
        if label.startswith("zip:"):
            assert detail["compression"] == zipfile.ZIP_DEFLATED
            data = zlib.decompress(data, -15)
        elif label.startswith("xor("):
            key = re.fullmatch(r"xor\((?:0x)?([a-f0-9]+)\)", label)[1]
            data = _xor(data, bytes.fromhex(key))
        elif label in DECODES:
            data = DECODES[label](data)
        else:
            assert label in ("strings", "carve")
    start, end, size = hit.evidence["span"]
    assert size == len(data) and data[start:end] == FLAG
    return walkthrough(hit)


def test_base64_xor_walkthrough():
    raw = base64.b64encode(_xor(FLAG, b"\x12"))
    info = replay(raw, ["base64", "xor(0x12)"])
    assert "byte ^ 0x12" in "\n".join(info["steps"])
    assert info["cyberchef"] == ("From_Base64('A-Za-z0-9+/=',true,false)"
                                 "XOR({'option':'Hex','string':'12'},'Standard',false)")


def test_hex_rot13_base64_walkthrough():
    raw = codecs.encode(base64.b64encode(FLAG).decode(), "rot13").encode().hex().encode()
    info = replay(raw, ["hex", "rot13", "base64"])
    assert "forward by 13" in "\n".join(info["steps"])
    assert info["cyberchef"].endswith("From_Hex('None')ROT13(true,true,false,13)From_Base64('A-Za-z0-9+/=',true,false)")


def test_gzip_walkthrough():
    info = replay(gzip.compress(b"AB " + FLAG), ["gzip"])
    assert "gzip" in "\n".join(info["steps"])
    assert info["cyberchef"] == f"Gunzip()Take_bytes(3,{len(FLAG)},false)"


def test_zip_walkthrough():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("nested/file.txt", base64.b64encode(FLAG))
    info = replay(buf.getvalue(), ["zip:nested/file.txt", "base64"])
    assert "nested/file.txt" in "\n".join(info["steps"])
    assert info["cyberchef"].startswith("Take_bytes(45,")
    assert "Raw_Inflate(" in info["cyberchef"]


def test_nested_zip_offsets_are_relative_to_each_archive():
    data = base64.b64encode(FLAG)
    for name in ("payload.txt", "inner.zip"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(name, data)
        data = buf.getvalue()
    info = replay(data, ["zip:inner.zip", "zip:payload.txt", "base64"])
    assert info["cyberchef"].count("Raw_Inflate(") == 2
    assert "Take_bytes(39," in info["cyberchef"] and "Take_bytes(41," in info["cyberchef"]


def test_whole_file_xor_reports_source_and_decoded_range():
    data = _xor(b"padding " + FLAG + b"\0", b"\x12")
    info = replay(data, ["xor(0x12)"])
    assert "file offset 0x8" in info["steps"][0]
    assert info["cyberchef"].endswith(f"Take_bytes(8,{len(FLAG)},false)")


def test_pe_constant_walkthrough():
    header = bytearray(512)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 128)
    header[128:132] = b"PE\0\0"
    struct.pack_into("<H", header, 134, 1)
    struct.pack_into("<H", header, 148, 240)
    struct.pack_into("<H", header, 152, 0x20b)
    struct.pack_into("<Q", header, 176, 0x140000000)
    header[392:398] = b".rdata"
    key = bytes.fromhex("ccddee")
    body = key.ljust(16, b"\0") + _xor(base64.b64encode(FLAG[::-1]), key)
    struct.pack_into("<III", header, 404, 0xa000, len(body), len(header))
    info = replay(bytes(header) + body, ["xor(ccddee)", "base64", "reverse"])
    steps = "\n".join(info["steps"])
    assert all(term in steps for term in ("file offset 0x210", ".rdata", "Press G, go to 0x14000a010", "ccddee"))
    assert info["cyberchef"].startswith("Take_bytes(528,36,false)XOR(")


def test_cli_walkthrough_is_opt_in():
    def output(*options):
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert main(["-s", FLAG.decode(), *options]) == 0
        return buf.getvalue()

    old, = json.loads(output("--json"))
    new, = json.loads(output("--json", "-e"))
    assert set(old) == {"flag", "source", "chain"}
    assert {k: new[k] for k in old} == old
    assert new["steps"] and new["cyberchef"] == ""
    assert output("-e").startswith(output().rstrip() + "\n")
    assert "1. Open" in output("--explain")
    unknown = walkthrough(Hit("flag{x}", ["future rule"], "input"))
    assert unknown["cyberchef"] is None and "future rule" in "\n".join(unknown["steps"])
