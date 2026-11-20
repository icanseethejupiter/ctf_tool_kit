import hashlib
import os
import shutil
import struct
import subprocess
import unittest
from pathlib import Path

import pefile

from flag_capturer import scan_bytes
from flag_capturer.formats.pe_ioc import DroppedScriptRule
from flag_capturer.formats.pe_replay import TargetSequence


def test_ioc_exact_write_and_host_field():
    script = b"# synthetic fixture\r\n[System.Reflection.Assembly]::Load()\r\n"
    config = b"decoy.test\0node.example\0"
    def encode(raw):
        return bytes(v ^ ((173 + i) % 256) for i, v in enumerate(raw))

    rule = DroppedScriptRule()
    raw = encode(script + b"padding")
    part, = rule._correlate(encode(config), 1, raw, len(script))
    assert part.wrap
    assert part.data == (hashlib.sha256(script).hexdigest()[:16].encode()
                         + b"_node.example_[System.Reflection.Assembly]::Load")
    assert not list(rule._correlate(encode(config), 2, raw, len(script)))
    assert not list(rule._correlate(encode(config), 1, raw, len(raw)+1))
    comment = b"# [Reflection.Assembly]::Load()"
    assert not list(rule._correlate(encode(config), 1, encode(comment), len(comment)))


def test_coordinate_order():
    # Two rounds with states 2, 3, 4, 5 and offsets 10 and 20.
    seq = TargetSequence(1, 1, 1, 0, 2, ((4, 10), (3, 20)))
    value = 7
    for coord in (12, 20, 10, 22):
        value = (value ^ coord) * 3
    assert seq.hash_centers(7, 3) == value


def _handout(name):
    root = os.environ.get("FLAGCAP_TEST_HANDOUTS")
    if not root:
        raise unittest.SkipTest("set FLAGCAP_TEST_HANDOUTS to the local challenge folder")
    archive = Path(root, name + ".7z")
    exe = Path(root, name + ".exe")
    if exe.is_file():
        return exe.read_bytes()
    seven = shutil.which("7z") or os.environ["FLAGCAP_TEST_7Z"]
    return subprocess.check_output([seven, "x", "-so", str(archive), exe.name])


def _flags(data, prefix):
    return {hit.flag for hit in scan_bytes(data, prefixes=[prefix])}


def test_dropper_handout_and_variant():
    original = _handout("dpcal")
    assert "SEEKER{435d3dacfb1b14d6_gate.umberspire.com_[Reflection.Assembly]::Load}" in _flags(original, "SEEKER")
    changed = bytearray(original)
    pe = pefile.PE(data=original, fast_load=True)
    config = pe.get_offset_from_rva(0x4000)
    script = pe.get_offset_from_rva(0x4080)
    key = changed[config] ^ ord("g")
    host = b"node.labexample.net"
    for i, v in enumerate(host + b"\0"):
        changed[config+i] = v ^ ((key+i) % 256)
    # Change the bytes that are hashed while preserving the recognizable call.
    changed[script + 312] ^= 1
    saved = bytes(changed[script+i] ^ ((key+i) % 256) for i in range(313))
    digest = hashlib.sha256(saved).hexdigest()[:16]
    assert f"LAB{{{digest}_{host.decode()}_[Reflection.Assembly]::Load}}" in _flags(bytes(changed), "LAB")


def test_ioc_walkthrough_prints_a_pasteable_verification():
    import io
    import sys
    import tempfile
    from contextlib import redirect_stdout
    from flag_capturer.cli import main

    with tempfile.TemporaryDirectory() as directory:
        sample = Path(directory, "sample's copy.exe")
        sample.write_bytes(_handout("dpcal"))
        output = io.StringIO()
        with redirect_stdout(output):
            assert main([str(sample), "-p", "LAB", "-e"]) == 0
        text = output.getvalue()
        assert text.index("iris   = ") < text.index("olive  = ") < text.index("celery = ")
        code = text.split("\n@'\n")[1].split("\n'@ | python -\n")[0]
        assert "[Reflection.Assembly]::Load" not in code
        recovered = subprocess.check_output([sys.executable, "-"], input=code, text=True).strip()
        assert recovered.startswith("LAB{") and "[+] " + recovered in text


def test_replay_handout_and_variant():
    original = _handout("bonus-bonus")
    assert "SEEKER{i_let_you_hit_me}" in _flags(original, "SEEKER")
    changed = bytearray(original)
    pe = pefile.PE(data=original, fast_load=True)
    seed = 0x123456789abcdef0
    struct.pack_into("<Q", changed, pe.get_offset_from_rva(0x14d7), seed)
    struct.pack_into("<I", changed, pe.get_offset_from_rva(0x156c), 31)
    mask = 2**64 - 1
    h = 0x14650fb0739d0383
    for _ in range(32):
        for width in (720, 520):
            seed = (seed * 0x5851f42d4c957f2d + 0x14057b7ef767814f) & mask
            h = ((h ^ (40 + (seed >> 33) % width)) * 0x100000001b3) & mask
    plain = b"LAB{different_seed}"
    changed[pe.get_offset_from_rva(0x1a78)] = len(plain)-1
    start = pe.get_offset_from_rva(0xa090)
    for i, v in enumerate(plain):
        h ^= (h << 13) & mask
        h ^= h >> 7
        h ^= (h << 17) & mask
        changed[start+i] = v ^ ((h >> 24) & 255)
    assert plain.decode() in _flags(bytes(changed), "LAB")
    changed[start] ^= 255
    assert plain.decode() not in _flags(bytes(changed), "LAB")
