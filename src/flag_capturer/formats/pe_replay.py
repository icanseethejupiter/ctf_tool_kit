"""Recover the release produced by an exact-center run of a deterministic aim game."""
import re
from dataclasses import asdict, dataclass

from .base import Part


_N = r"(0x[0-9a-f]+|\d+)"
_MASK = (1 << 64) - 1
_LCG = re.compile(r"mov rax, qword ptr @" + _N + r"\nmovabs rdx, " + _N +
                  r"\nimul rax, rdx\nmovabs rdx, " + _N +
                  r"\nadd rax, rdx\nmov qword ptr @\1, rax\nmov rax, qword ptr @\1\nshr rax, " + _N)
_SEED = re.compile(r"movabs rax, " + _N + r"\nmov qword ptr @" + _N + r", rax")
_AXIS = re.compile(r"imul (?:edx, edx|ecx, eax), " + _N +
                   r"\n(?:mov eax, edx\n)?sub eax, (?:edx|ecx)\nlea ecx, \[rax \+ " + _N + r"\]")
_ROUND = re.compile(r"cmp dword ptr \[rbp - [^\]]+\], " + _N + r"\njle ")
_MIX = re.compile(r"mov rax, qword ptr @" + _N + r"\nxor rdx, rax\nmovabs rax, " +
                  _N + r"\nimul rax, rdx\nmov qword ptr @\1, rax")
_SHIFT = re.compile(r"(shl|shr) rax, " + _N + r"\nxor qword ptr \[rbp - 8\], rax")
_TABLE = re.compile(r"lea rdx, @" + _N + r"\nmov rax, qword ptr \[rbp - 0x10\]\n"
                    r"add rax, rdx\nmovzx edx, byte ptr \[rax\]\n"
                    r"mov rax, qword ptr \[rbp - 8\]\nshr rax, " + _N + r"\nxor eax, edx")
_LENGTH = re.compile(r"cmp qword ptr \[rbp - 0x10\], " + _N + r"\njbe ")


@dataclass(frozen=True)
class TargetSequence:
    seed: int
    multiplier: int
    increment: int
    shift: int
    rounds: int
    axes: tuple

    def hash_centers(self, digest, prime):
        state = self.seed
        for _ in range(self.rounds):
            for width, offset in self.axes:
                state = (state * self.multiplier + self.increment) & _MASK
                coordinate = ((state >> self.shift) & 0xffffffff) % width + offset
                digest = ((digest ^ coordinate) * prime) & _MASK
        return digest


def _release(cipher, digest, shift, steps):
    left, right, final = steps
    plain = bytearray()
    for byte in cipher:
        digest ^= (digest << left) & _MASK
        digest ^= digest >> right
        digest ^= (digest << final) & _MASK
        plain.append(byte ^ ((digest >> shift) & 255))
    return bytes(plain)


class CoordinateReplayRule:
    def recognizes(self, data):
        return b"\x48\x0f\xaf\xc2" in data and b"\x48\x31\x45\xf8" in data

    def extract(self, image):
        seeds = {}
        hashes = {}
        releases = {}
        generators = {}
        for address, code in image.functions.items():
            for value, slot in _SEED.findall(code):
                seeds.setdefault(slot, set()).add(int(value, 0))
            gen = _LCG.search(code)
            if gen:
                generators[address] = gen.groups()
            mix = _MIX.findall(code)
            if len(mix) == 2 and mix[0] == mix[1]:
                slot, prime = mix[0]
                hashes[slot] = int(prime, 0)
            table = _TABLE.search(code)
            length = _LENGTH.search(code)
            shifts = _SHIFT.findall(code)
            state = re.search(r"mov rax, qword ptr @" + _N + r"\ntest rax, rax", code)
            if table and length and state and [op for op, _ in shifts] == ["shl","shr","shl"]:
                size = int(length[1], 0) + 1
                if 5 <= size <= 224:
                    releases[state[1]] = (image.read(int(table[1], 0), size), int(table[2], 0),
                                          [int(n, 0) for _, n in shifts], int(table[1], 0), address)
        for sequence in self._sequences(image, generators):
            for target in hashes.keys() & releases.keys():
                cipher, byte_shift, steps, rva, function = releases[target]
                for seed in seeds.get(target, ()):
                    digest = sequence.hash_centers(seed, hashes[target])
                    plain = _release(cipher, digest, byte_shift, steps)
                    if re.fullmatch(rb"[A-Za-z][A-Za-z0-9_]{1,19}\{[^{}\x00-\x1f\x7f-\xff]{1,200}\}", plain):
                        yield Part(f"{sequence.rounds} target centers -> coordinate hash -> xorshift release",
                                   plain, evidence=dict(asdict(sequence), digest_seed=seed, prime=hashes[target],
                                                        byte_shift=byte_shift, shifts=steps, rva=rva,
                                                        length=len(cipher), function_rva=function,
                                                        xref_rvas=image.xrefs.get(rva, [])))

    def _sequences(self, image, generators):
        for code in image.functions.values():
            axes = tuple((int(width, 0), int(offset, 0)) for width, offset in _AXIS.findall(code))
            bound = _ROUND.search(code)
            if len(axes) != 2 or not all(w for w, _ in axes) or not bound:
                continue
            rounds = int(bound[1], 0) + 1
            if not 1 <= rounds <= 65536:
                continue
            for addr, (slot, multiplier, increment, shift) in generators.items():
                if code.splitlines().count(f"call {addr:#x}") != 2:
                    continue
                initial = [int(v, 0) for v, s in _SEED.findall(code) if s == slot]
                if len(initial) == 1:
                    yield TargetSequence(initial[0], int(multiplier, 0), int(increment, 0),
                                         int(shift, 0), rounds, axes)
