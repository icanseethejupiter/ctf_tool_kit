"""Recover constant IPv4 connect destinations from offline x86-64 evidence."""
import io
import re
from collections import deque
from ipaddress import IPv4Address

from .base import Part


def _decoder():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    return Cs(CS_ARCH_X86, CS_MODE_64)


_MEM = re.compile(r"(?:(byte|word|dword|qword) ptr )?\[(rbp|rsp)(?: ([+-]) (0x[\da-f]+|\d+))?\]")
_WIDTH = {"byte": 1, "word": 2, "dword": 4, "qword": 8}


def _slot(operand):
    match = _MEM.fullmatch(operand)
    if match:
        width, base, sign, offset = match.groups()
        disp = int(offset or "0", 0)
        return base, -disp if sign == "-" else disp, _WIDTH.get(width)


class ConnectIPv4Rule:
    symbol = "connect"

    def findings(self, address, history, read_constant, listing_offset=None):
        detail = {"va": address, "role": "connect call"}
        if listing_offset is not None:
            detail["offset"] = listing_offset
        ip = self.recover(history, read_constant, detail)
        if ip:
            label = f"connect IPv4 at {address:#x} (formatted candidate)"
            yield Part(label, ip.encode(), wrap=True, evidence=detail)

    def recover(self, history, read_constant, detail=None):
        registers = {}
        memory = {}
        for end, op, args, callee in history:
            if op == "call" and callee == "htons":
                registers.clear()
                continue
            operands = args.split(", ")
            if op not in ("mov", "movabs", "lea") or len(operands) != 2:
                registers.clear()
                memory.clear()
                continue
            dst, src = operands
            slot = _slot(src)
            if op == "lea" and slot:
                value = slot[:2]
            elif op == "lea":
                location = _rip_address(end, src)
                value = ("image", location) if location is not None else None
            elif re.fullmatch(r"-?(?:0x[\da-f]+|\d+)", src):
                value = int(src, 0)
            else:
                value = registers.get(src)
            target = _slot(dst)
            if target and target[2]:
                base, offset, size = target
                for i in range(size):
                    memory[base, offset+i] = (value >> (8*i)) & 255 if isinstance(value, int) else None
            elif "[" in dst or dst in ("rsp", "rbp", "esp", "ebp"):
                registers.clear()
                memory.clear()
            else:
                # A partial-register write can invalidate a full pointer.
                for reg in _ALIASES.get(dst, (dst,)):
                    registers.pop(reg, None)
                registers[dst] = value
                if dst.startswith("e") and isinstance(value, int):
                    registers["r" + dst[1:]] = value & 0xffffffff
        addr = registers.get("rsi")
        if not isinstance(addr, tuple) or registers.get("rdx") != 16:
            return
        base, offset = addr
        if base == "image":
            literal = read_constant(offset, 8) if read_constant else b""
            if len(literal) == 8 and literal[:2] == b"\x02\x00":
                if detail is not None:
                    detail.update(va=offset+4, role="sin_addr", callsite=detail["va"], octets=literal[4:])
                return str(IPv4Address(literal[4:]))
            return
        fields = [memory.get((base, offset + i)) for i in (0, 1, 4, 5, 6, 7)]
        if fields[:2] == [2, 0] and None not in fields:
            if detail is not None:
                detail.update(stack_base=base, displacement=offset, octets=bytes(fields[2:]))
            return str(IPv4Address(bytes(fields[2:])))


_GROUPS = (("rax","eax","ax","al","ah"), ("rbx","ebx","bx","bl","bh"),
           ("rcx","ecx","cx","cl","ch"), ("rdx","edx","dx","dl","dh"),
           ("rsi","esi","si","sil"), ("rdi","edi","di","dil"))
_GROUPS += tuple((f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b") for i in range(8, 16))
_ALIASES = {alias: group for group in _GROUPS for alias in group}


_CALL_RULES = {rule.symbol: rule for rule in (ConnectIPv4Rule(),)}


def _call_findings(instructions, read_constant=None):
    history = deque(maxlen=48)
    end = None
    for address, size, op, args, callee, listing_offset in instructions:
        if address != end:
            history.clear()
        if op == "call" and callee in _CALL_RULES:
            yield from _CALL_RULES[callee].findings(address, history, read_constant, listing_offset)
        end = address + size
        history.append((end, op, args, callee))


def _disassemble(decoder, section):
    # Capstone materializes the instruction batch before yielding the first one.
    code = section.data()
    base = section["sh_addr"]
    pos = 0
    while pos < len(code):
        stop = min(pos + 16384, len(code))
        following = pos
        for ins in decoder.disasm_lite(code[pos:stop + 15], base + pos):
            if ins[0] >= base + stop:
                break
            yield ins
            following = ins[0] + ins[1] - base
        if following == pos:
            break
        pos = following


class ELFAnalyzer:
    def identify(self, data):
        if data[:4] == b"\x7fELF" and data[4:5] in (b"\x01", b"\x02"):
            return "ELF64" if data[4] == 2 else "ELF32"
        return ""

    def extract(self, data, **options):
        from elftools.common.exceptions import ELFError
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection

        if data[4:6] != b"\x02\x01" or data[18:20] != b"\x3e\x00":
            return
        try:
            elf = ELFFile(io.BytesIO(data))
            slots = {}
            for section in elf.iter_sections():
                if not isinstance(section, RelocationSection):
                    continue
                symbols = elf.get_section(section["sh_link"])
                for relocation in section.iter_relocations():
                    if relocation["r_info_type"] in (6, 7):
                        symbol = symbols.get_symbol(relocation["r_info_sym"])
                        if symbol["st_shndx"] == "SHN_UNDEF":
                            slots[relocation["r_offset"]] = symbol.name
            if not _CALL_RULES.keys() & set(slots.values()):
                return
            stubs = {}
            decoder = _decoder()
            decoder.skipdata = True
            for section in elf.iter_sections():
                if section.name.startswith(".plt"):
                    previous = None
                    for addr, size, op, args in _disassemble(decoder, section):
                        name = slots.get(_rip_address(addr + size, args))
                        if op.endswith("jmp") and name:
                            stubs[addr] = name
                            if previous and previous[1] == "endbr64":
                                stubs[previous[0]] = name
                        previous = addr, op
            readonly = [seg for seg in elf.iter_segments()
                        if seg["p_type"] == "PT_LOAD" and not seg["p_flags"] & 2]

            def read_constant(address, size):
                for seg in readonly:
                    delta = address - seg["p_vaddr"]
                    if 0 <= delta <= seg["p_filesz"] - size:
                        start = seg["p_offset"] + delta
                        return data[start:start + size]
                return b""

            for section in elf.iter_sections():
                if section["sh_type"] == "SHT_PROGBITS" and section["sh_flags"] & 4:
                    code = _disassemble(decoder, section)
                    yield from _call_findings(self._calls(code, stubs, slots), read_constant)
        except (ELFError, ValueError, IndexError, KeyError, TypeError, AttributeError, OverflowError):
            return

    def _calls(self, code, stubs, slots):
        for addr, size, op, args in code:
            name = None
            if op == "call":
                if args.startswith("0x"):
                    name = stubs.get(int(args, 16))
                else:
                    name = slots.get(_rip_address(addr + size, args))
            yield addr, size, op, args, name, None


def _rip_address(end, args):
    match = re.fullmatch(r"(?:qword ptr )?\[rip ([+-]) (0x[\da-f]+|\d+)\]", args)
    if match:
        offset = int(match[2], 0)
        return end + (offset if match[1] == "+" else -offset)


class GhidraELFAnalyzer:
    _row = re.compile(rb"^\s*([\da-fA-F]{8,16}) ((?:[\da-fA-F]{2} )*[\da-fA-F]{2})\s{2,}([A-Z][A-Z0-9]*)\s+(.*)$")
    _continued = re.compile(rb"^\s+((?:[\da-fA-F]{2} )*[\da-fA-F]{2})\s*$")

    def identify(self, data):
        if b"Elf64_Ehdr" in data[:8192] and b"<EXTERNAL>::" in data:
            return "Ghidra ELF64 listing"
        return ""

    def extract(self, data, **options):
        yield from _call_findings(self._instructions(data))

    def _instructions(self, data):
        decoder = _decoder()
        row = None
        position = 0
        for line in data.splitlines(keepends=True) + [b""]:
            start = position
            position += len(line)
            line = line.rstrip(b"\r\n")
            continuation = self._continued.match(line)
            if row and continuation:
                if len(raw) <= 15:
                    raw.extend(bytes.fromhex(continuation[1].decode()))
                continue
            if row:
                ins = next(decoder.disasm_lite(bytes(raw), int(row[1], 16), 1), None)
                if ins and ins[1] == len(raw):
                    symbol = re.match(rb"<EXTERNAL>::([A-Za-z0-9_]+)", row[4])
                    yield (*ins, symbol[1].decode() if symbol else None, row_offset)
            row = self._row.match(line)
            if row:
                row_offset = start + row.start(1)
                raw = bytearray.fromhex(row[2].decode())
