import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import dpkt

from flag_capturer.finder import Finder
from flag_capturer.formats import FORMATS, FormatRegistry
from flag_capturer.formats.base import Part


def tcp_frame(seq, payload, port=4400):
    tcp = dpkt.tcp.TCP(sport=port, dport=80, seq=seq, flags=16, data=payload)
    ip = dpkt.ip.IP(src=b"\x0a\0\0\1", dst=b"\x0a\0\0\2", p=6, data=tcp)
    return bytes(dpkt.ethernet.Ethernet(type=0x800, data=ip))


def capture(frames, ng=False):
    buf = io.BytesIO()
    writer = (dpkt.pcapng.Writer if ng else dpkt.pcap.Writer)(buf)
    for frame in frames:
        writer.writepkt(frame, ts=1)
    return buf.getvalue()


def test_tcp_reassembly():
    first = tcp_frame(100, b"flag{")
    frames = [tcp_frame(105, b"ordered}"), tcp_frame(100, b"noise", 3333), first, first]
    for ng, name in ((True, "PCAPNG"), (False, "PCAP")):
        blob = capture(frames, ng)
        assert FORMATS.identify(blob)[0] == name
        hits = Finder().scan(blob)
        assert any(h.flag == "flag{ordered}" and "TCP " in h.path() for h in hits)


def test_tcp_gap_and_direction():
    for second in (tcp_frame(106, b"wrong}"), tcp_frame(105, b"wrong}", 3333)):
        blob = capture([tcp_frame(100, b"flag{"), second])
        assert "flag{wrong}" not in {h.flag for h in Finder().scan(blob)}


def test_udp_and_truncation():
    udp = dpkt.udp.UDP(sport=33, dport=53, data=b"flag{one_datagram}")
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(p=17, data=udp)
    blob = capture([bytes(dpkt.ethernet.Ethernet(type=0x800, data=ip))])
    _, analyzer = FORMATS.identify(blob)
    assert [p.data for p in analyzer.extract(blob)] == [b"flag{one_datagram}"]
    assert list(analyzer.extract(blob[:-1])) == []


def test_register_analyzer():
    class Sample:
        def identify(self, data):
            return "example" if data == b"example file" else ""

        def extract(self, data, **options):
            yield Part("example field", b"flag{extension}")

    hits = Finder(formats=FormatRegistry([Sample()])).scan(b"example file")
    assert hits[0].chain == ["example field"]


def test_compiled_csharp():
    csc = shutil.which("csc") or str(Path(os.environ.get("WINDIR", "")) /
                                     "Microsoft.NET/Framework64/v4.0.30319/csc.exe")
    if not Path(csc).is_file():
        raise unittest.SkipTest("C# compiler unavailable")
    with tempfile.TemporaryDirectory() as folder:
        source = Path(folder) / "sample.cs"
        source.write_text('class Sample { public static string Read() {'
                          'return string.Concat("flag{", "managed", "}"); } }')
        subprocess.run([csc, "/nologo", "/target:library", "/out:sample.dll", source.name],
                       cwd=folder, check=True)
        blob = source.with_suffix(".dll").read_bytes()
    assert FORMATS.identify(blob)[0] == ".NET assembly"
    hits = Finder().scan(blob, "renamed.bin")
    assert any(h.flag == "flag{managed}" and "String.Concat" in h.path() for h in hits)
