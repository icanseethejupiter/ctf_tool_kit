"""Breadth-first search through decodings until something looks like a flag."""
from __future__ import annotations

import heapq
import itertools
import re
from dataclasses import dataclass, field

from .decoders import CARVERS, DECODERS, printable_ratio
from .formats import FORMATS
from .fragments import assembly_evidence

DEFAULT_PREFIXES = ["flag", "ctf", "htb", "thm"]
_BODY = re.compile(rb"\{[^{}\x00-\x1f\x7f-\xff]{1,200}\}")
_WORD_END = re.compile(rb"[A-Za-z0-9_]{1,20}$")
# a believable flag: a 3+ letter word (letters/digits/_) then a body with no spaces
_LOOKS_LIKE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,19}\{[!-|~]{4,200}\}")
XOR_LIMIT = 8 * 1024 * 1024
_XOR_TABLES = [bytes(c ^ k for c in range(256)) for k in range(256)]
_LOWER = b"abcdefghijklmnopqrstuvwxyz"
_UPPER = _LOWER.upper()
_ROT_TABLES = {
    n: bytes.maketrans(_LOWER + _UPPER, _LOWER[n:] + _LOWER[:n] + _UPPER[n:] + _UPPER[:n])
    for n in range(1, 26)
}
_ROT47 = bytes.maketrans(bytes(range(33, 127)), bytes(range(80, 127)) + bytes(range(33, 80)))


class _Queue:
    """Shallow and readable first, so junk decodings can't starve the real lead."""

    def __init__(self):
        self._h, self._n = [], itertools.count()

    def append(self, item):
        b, chain = item[0], item[1]
        heapq.heappush(self._h, (len(chain), -round(printable_ratio(b[:4096]), 2), next(self._n), item))

    def popleft(self):
        return heapq.heappop(self._h)[-1]

    def __bool__(self):
        return bool(self._h)


@dataclass
class Hit:
    flag: str
    chain: list = field(default_factory=list)
    source: str = ""
    evidence: dict = field(default=None, compare=False, repr=False)

    def path(self) -> str:
        return " -> ".join(self.chain) if self.chain else "plain"


class Finder:
    def __init__(self, prefixes=None, regex=None, max_depth=5, max_nodes=20000,
                 xor=True, loose=False, min_string=6, formats=FORMATS, explain=False):
        self.explain = explain
        self.formats = formats
        prefixes = [p.rstrip("{") for p in (prefixes or [])]
        self.answer_prefixes = [p for p in prefixes if p] or ["flag"]
        self.ctf_like = ("ctf",)
        self.prefix_set = set(DEFAULT_PREFIXES) | {p.lower() for p in prefixes}
        self.custom = re.compile(regex.encode()) if regex else None
        self.loose = loose
        # xor signatures: xor of neighbouring bytes doesn't depend on the key
        sigs = {}
        for p in DEFAULT_PREFIXES + prefixes:
            for v in {p, p.lower(), p.upper(), p.capitalize()}:
                n = (v + "{").encode()
                sigs[bytes(n[k] ^ n[k - 1] for k in range(1, len(n)))] = n[0]
        self.xor_sigs = sigs
        self.prefix_bytes = sorted({(v + "{").encode() for p in DEFAULT_PREFIXES + prefixes
                                    for v in (p, p.lower(), p.upper(), p.capitalize())})
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.xor = xor
        self.min_string = min_string
        self.hits: dict = {}
        self.maybe: dict = {}  # WORD{...} with an unknown prefix

    # ---------- matching ----------
    def _ok_prefix(self, word):
        w = word.lower()
        return w.endswith(self.ctf_like) or w in self.prefix_set

    def _match(self, b, chain, source, guessed=False):
        if b"{" in b:
            # start from each brace (cheap) and look back for the prefix word
            for m in _BODY.finditer(b):
                start = m.start()
                w = _WORD_END.search(b, max(0, start - 20), start)
                if not w:
                    continue
                word = w.group().decode("latin-1")
                # trim to the longest tail that is a known prefix (e.g. "xxflag" -> "flag")
                hit = next((word[k:] for k in range(len(word)) if self._ok_prefix(word[k:])), None)
                if hit is not None:
                    self._add(hit + m.group().decode("latin-1"), chain, source,
                              span=(start-len(hit), m.end(), len(b)))
                elif not guessed and _LOOKS_LIKE.fullmatch(word + m.group().decode("latin-1")):
                    # unknown prefix: keep as a "maybe" (never from brute force, that's all noise)
                    self._add(word + m.group().decode("latin-1"), chain, source, self.maybe,
                              span=(start-len(word), m.end(), len(b)))
        if self.custom:
            for m in self.custom.finditer(b):
                self._add(m.group().decode("latin-1"), chain, source, span=(*m.span(), len(b)))

    def _add(self, flag, chain, source, into=None, span=None, last=None):
        into = self.hits if into is None else into
        old = into.get(flag)
        if old is None or len(chain) < len(old.chain):
            evidence = None
            if self.explain:
                from .explain import hit_evidence
                layers = self._trace + ((last or {},) if len(chain) > len(self._trace) else ())
                evidence = hit_evidence(self._input, layers, chain, span)
            into[flag] = Hit(flag, list(chain), source, evidence)

    def _brute(self, b, chain, source):
        if not b:
            return
        self._match(b[::-1], chain + ["reverse"], source, True)
        # caesar shifts keep the braces, so no braces means nothing to find
        if b"{" in b and b"}" in b and re.search(rb"[A-Za-z]", b):
            for n, table in _ROT_TABLES.items():
                self._match(b.translate(table), chain + [f"rot{n}"], source, True)
            self._match(b.translate(_ROT47), chain + ["rot47"], source, True)
        if not self.xor or len(b) > XOR_LIMIT:
            return
        keys = set()
        n = int.from_bytes(b, "big")
        diff = (n ^ (n >> 8)).to_bytes(len(b), "big")  # diff[i] = b[i] ^ b[i-1]
        for sig, first in self.xor_sigs.items():
            pos = diff.find(sig, 1)
            while pos != -1 and len(keys) < 256:
                keys.add(b[pos - 1] ^ first)
                pos = diff.find(sig, pos + 1)
        for k in sorted(keys):
            if k:
                self._match(b.translate(_XOR_TABLES[k]), chain + [f"xor(0x{k:02x})"], source, True)

    # ---------- search ----------
    def scan(self, data: bytes, source: str = "<input>"):
        queue = _Queue()
        self._input = data if self.explain else None
        queue.append((data, [], True, True, ()))
        seen = set()
        nodes = 0   # decoded/new data: the expensive kind, limited by max_nodes
        slices = 0  # plain substrings (strings/carve): cheap, much higher cap
        while queue:
            b, chain, is_file, fresh, self._trace = queue.popleft()
            key = hash(b)
            if key in seen or not b:
                continue
            if fresh:
                if nodes >= self.max_nodes:
                    continue
                nodes += 1
            else:
                if slices >= 20 * self.max_nodes:
                    continue
                slices += 1
            seen.add(key)
            # after a rot13/reverse step, an unknown-prefix WORD{...} is almost surely noise
            self._match(b, chain, source, guessed=any(c in ("rot13", "reverse") for c in chain))
            if fresh:  # substrings of an already brute-forced parent were covered by it
                self._brute(b, chain, source)
            if len(chain) >= self.max_depth:
                continue
            textish = printable_ratio(b) >= 0.95
            if is_file and textish and b"mov" in b.lower() and b"0x" in b.lower():
                for literal, detail in assembly_evidence(b):
                    self._enqueue(queue, literal, chain, "join little-endian literals", False, True, detail)
            if is_file:
                _, analyzer = self.formats.identify(b)
                if analyzer:
                    parts = analyzer.extract(b, xor=self.xor, prefixes=self.prefix_bytes)
                    for part in itertools.islice(parts, max(0, self.max_nodes - nodes)):
                        detail = getattr(part, "evidence", None)
                        if self.explain and detail:
                            detail = dict(detail, container=b)
                        if part.wrap:
                            for prefix in self.answer_prefixes:
                                self._add(prefix + "{" + part.data.decode("ascii") + "}",
                                          chain + [part.label], source, last=detail)
                            continue
                        self._enqueue(queue, part.data, chain, part.label, part.nested, True, detail)
            if is_file and not textish:
                for label, matches in (("strings", self._strings(b)), ("utf16", self._utf16(b))):
                    for m in matches:
                        value = m.group()
                        if label == "utf16":
                            value = value.decode("utf-16le").encode()
                        self._enqueue(queue, value, chain, label, False, False,
                                      {"container": b, "offset": m.start(), "length": m.end()-m.start(),
                                       "preview": value[:12]} if self.explain else None)
            for name, fn, strict in DECODERS:
                if not textish and name not in ("gzip", "zlib", "bz2", "lzma"):
                    continue
                try:
                    out = fn(b)
                except Exception:
                    out = None
                if not out or out == b:
                    continue
                sliced = any(c in ("strings", "carve") for c in chain)
                r = printable_ratio(out)
                compressed = name in ("gzip", "zlib", "bz2", "lzma")
                # slices of a big binary give lots of accidental "valid" decodings: keep only sensible ones
                if (strict and not sliced) or compressed or r >= (0.75 if strict else 0.9):
                    # rot13/reverse of a slice is still just a rearranged slice: the parent's brute force covered it
                    self._enqueue(queue, out, chain, name, compressed, fresh or name not in ("rot13", "reverse"),
                                  {"xz": b.startswith(b"\xfd7zXZ")} if self.explain and name == "lzma" else None)
            if textish and len(b) > 16:
                self._carve(b, chain, queue)
        if self.loose:
            for k, v in self.maybe.items():
                self.hits.setdefault(k, v)
        for k in self.hits:
            self.maybe.pop(k, None)
        return sorted(self.hits.values(), key=lambda h: (len(h.chain), h.flag))

    def maybes(self):
        return sorted(self.maybe.values(), key=lambda h: (len(h.chain), h.flag))

    def _strings(self, b):
        return re.finditer(rb"[\x20-\x7e\t]{%d,}" % self.min_string, b)

    def _utf16(self, b):
        return re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % self.min_string, b)

    def _enqueue(self, queue, value, chain, label, is_file, fresh, detail=None):
        trace = self._trace + (detail or {},) if self.explain else ()
        queue.append((value, chain + [label], is_file, fresh, trace))

    def _carve(self, b, chain, queue):
        whole = b.strip()
        count = 0
        for rx in CARVERS:
            for m in rx.finditer(b):
                tok = m.group().strip()
                if tok != whole:
                    self._enqueue(queue, tok, chain, "carve", False, False,
                                  {"offset": m.start(), "length": len(tok), "preview": tok[:12]}
                                  if self.explain else None)
                    count += 1
                    if count >= 64:
                        return



def scan_bytes(data: bytes, source: str = "<input>", **kwargs):
    """Convenience wrapper: return a list of Hit for the given bytes."""
    return Finder(**kwargs).scan(data, source)
