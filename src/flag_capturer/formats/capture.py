"""Offline capture records and directional TCP reassembly."""
import struct

from .base import Part


MAGICS = {bytes.fromhex(m): endian for m, endian in (
    ("d4c3b2a1", "<"), ("4d3cb2a1", "<"), ("a1b2c3d4", ">"), ("a1b23c4d", ">"))}
SECTION = b"\x0a\x0d\x0d\x0a"


def _frames(data):
    endian = MAGICS.get(data[:4])
    if endian:
        if len(data) < 24:
            return
        link = struct.unpack_from(endian + "I", data, 20)[0] & 0xffff
        pos = 24
        while pos + 16 <= len(data):
            size = struct.unpack_from(endian + "I", data, pos + 8)[0]
            pos += 16
            if size > len(data) - pos:
                return
            yield 0, link, data[pos:pos + size]
            pos += size
        return
    pos = 0
    section = 0
    links = []
    while pos + 12 <= len(data):
        if data[pos:pos + 4] == SECTION:
            # Section byte-order magic differs from classic capture magic.
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(data[pos + 8:pos + 12])
            links.clear()
            section += 1
        if not endian:
            return
        kind, size = struct.unpack_from(endian + "II", data, pos)
        end = pos + size
        if size < 12 or size % 4 or end > len(data) or struct.unpack_from(endian + "I", data, end-4)[0] != size:
            return
        if kind == 1 and size >= 20:
            links.append(struct.unpack_from(endian + "H", data, pos + 8)[0])
        elif kind == 6 and size >= 32:
            iface, _, _, cap = struct.unpack_from(endian + "IIII", data, pos + 8)
            if iface < len(links) and cap <= size - 32:
                yield (section, iface), links[iface], data[pos + 28:pos + 28 + cap]
        pos = end


class TCPStream:
    def __init__(self, seq):
        self.origin = seq
        self.segments = []

    def add(self, seq, payload):
        offset = ((seq - self.origin + 2**31) % 2**32) - 2**31
        self.segments.append((offset, payload))

    def chunks(self):
        end = None
        chunk = bytearray()
        for offset, payload in sorted(self.segments, key=lambda entry: entry[0]):
            if end is None or offset > end:
                if chunk:
                    yield bytes(chunk)
                chunk.clear()
                end = offset
            chunk.extend(payload[max(0, end - offset):])
            end = max(end, offset + len(payload))
        if chunk:
            yield bytes(chunk)


class CaptureAnalyzer:
    def identify(self, data):
        if data[:4] in MAGICS:
            return "PCAP"
        return "PCAPNG" if data[:4] == SECTION else ""

    def extract(self, data, **options):
        import dpkt

        streams = {}
        for index, (iface, link, frame) in enumerate(_frames(data), 1):
            try:
                if link == 1:
                    ip = dpkt.ethernet.Ethernet(frame).data
                elif link in (101, 228, 229) and frame:
                    ip = dpkt.ip6.IP6(frame) if frame[0] >> 4 == 6 else dpkt.ip.IP(frame)
                else:
                    continue
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                if isinstance(ip, dpkt.ip.IP) and (ip.offset or ip.mf):
                    continue
                if isinstance(ip, dpkt.ip6.IP6) and 44 in ip.extension_hdrs:
                    continue
                segment = ip.data
                if isinstance(segment, dpkt.udp.UDP):
                    yield Part(f"UDP packet {index}", bytes(segment.data))
                elif isinstance(segment, dpkt.tcp.TCP):
                    key = (iface, ip.src, segment.sport, ip.dst, segment.dport)
                    seq = segment.seq
                    if segment.flags & dpkt.tcp.TH_SYN:
                        seq = (seq + 1) % 2**32
                        old = streams.get(key)
                        if old and old.origin != seq:
                            yield from self._parts(streams.pop(key), key)
                    if segment.data:
                        if key not in streams:
                            streams[key] = TCPStream(seq)
                        streams[key].add(seq, bytes(segment.data))
            except (dpkt.UnpackError, ValueError, IndexError, struct.error):
                continue
        for key, stream in streams.items():
            yield from self._parts(stream, key)

    def _parts(self, stream, key):
        from ipaddress import ip_address
        _, src, sport, dst, dport = key
        label = f"TCP {ip_address(src)}:{sport} -> {ip_address(dst)}:{dport}"
        for chunk in stream.chunks():
            yield Part(label, chunk)
