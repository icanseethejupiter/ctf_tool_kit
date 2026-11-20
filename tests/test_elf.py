import os
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from flag_capturer.finder import Finder


def listing(family=2, callee="connect", pointer="e0"):
    # sockaddr_in at rbp-32, with its IPv4 field at rbp-28.
    rows = [
        (f"66 c7 45 e0 {family:02x} 00", "MOV"),
        ("c7 45 e4 c0 00 02 07", "MOV"),
        (f"48 8d 75 {pointer}", "LEA"),
        ("ba 10 00 00 00", "MOV"),
        ("e8 00 00 00 00", "CALL"),
    ]
    lines = ["Elf64_Ehdr   <EXTERNAL>::connect"]
    addr = 0x601000
    for raw, op in rows:
        lines.append(f"{addr:08x} {raw}    {op}     <EXTERNAL>::{callee}")
        addr += len(bytes.fromhex(raw))
    return "\n".join(lines).encode()


def test_listing_prefix_and_evidence():
    hits = Finder(prefixes=["LAB"]).scan(listing())
    assert [h.flag for h in hits] == ["LAB{192.0.2.7}"]
    assert "connect IPv4" in hits[0].path()
    assert Finder().scan(listing())[0].flag == "flag{192.0.2.7}"


def test_unrelated_constants_are_ignored():
    for sample in (listing(family=10), listing(callee="bind"), listing(pointer="d0")):
        assert Finder().scan(sample) == []


def test_linked_elf():
    zig = os.environ.get("FLAGCAP_TEST_ZIG") or shutil.which("zig")
    if zig:
        cc = [zig, "cc", "-target", "x86_64-linux-gnu"]
    elif platform.system() == "Linux" and platform.machine() == "x86_64" and shutil.which("cc"):
        cc = ["cc"]
    else:
        raise unittest.SkipTest("requires an x86-64 Linux compiler or Zig")
    source = """
        struct Address { unsigned short family, port; unsigned ip; char pad[8]; };
        extern int connect(int, const struct Address *, unsigned);
        int on_stack(int fd) {
            struct Address a;
            a.family = 2;
            a.ip = 0x096433c6;
            return connect(fd, &a, sizeof a);
        }
        static const struct Address fixed = { 2, 0, 0x097100cb };
        int readonly(int fd) { return connect(fd, &fixed, sizeof fixed); }
    """
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "test.c").write_text(source)
        for mode in ("-fplt", "-fno-plt"):
            subprocess.run(cc + ["-O0", "-fno-sanitize=all", "-shared", "-fPIC", "-nostdlib", mode,
                                 "test.c", "-o", "test.so"], cwd=tmp, check=True)
            hits = Finder(prefixes=["LAB"]).scan(Path(tmp, "test.so").read_bytes())
            assert {h.flag for h in hits} == {"LAB{198.51.100.9}", "LAB{203.0.113.9}"}
