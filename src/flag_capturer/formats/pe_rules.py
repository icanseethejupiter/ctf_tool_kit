"""Read-only evidence shared by native x64 challenge rules."""
import re

import pefile

from ..pe_constants import pe_header
from .pe_ioc import DroppedScriptRule
from .pe_replay import CoordinateReplayRule


class NativeImage:
    def __init__(self, data):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64

        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[1, 3])  # imports and x64 unwind entries
        self.imports = {i.address - pe.OPTIONAL_HEADER.ImageBase: i.name.decode("ascii", "replace")
                        for lib in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) for i in lib.imports if i.name}
        self.sections = [(s.VirtualAddress, memoryview(data)[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData])
                         for s in pe.sections]
        self.functions = {}
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        budget = 2 * 1024 * 1024
        for entry in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []):
            start, end = entry.struct.BeginAddress, entry.struct.EndAddress
            if start in self.functions or not 0 < end - start <= min(65536, budget):
                continue
            budget -= end - start
            lines = []
            for addr, size, op, args in decoder.disasm_lite(self.read(start, end-start), start):
                ref = re.search(r"\[rip ([+-]) (0x[0-9a-f]+|\d+)\]", args)
                if ref:
                    delta = int(ref[2], 0)
                    rva = addr + size + (delta if ref[1] == "+" else -delta)
                    name = self.imports.get(rva, hex(rva))
                    args = args.replace(ref[0], "@" + name)
                lines.append((op + " " + args).rstrip())
            self.functions[start] = "\n".join(lines)

    def read(self, address, count):
        for base, view in self.sections:
            off = address - base
            if 0 <= off <= len(view) - count:
                return bytes(view[off:off + count])
        return b""


RULES = (DroppedScriptRule(), CoordinateReplayRule())


def native_findings(data, xor):
    if not xor:
        return
    header = pe_header(data)
    if header is None or data[header + 4:header + 6] != b"\x64\x86":
        return
    rules = [rule for rule in RULES if rule.recognizes(data)]
    if not rules:
        return
    try:
        image = NativeImage(data)
    except (pefile.PEFormatError, ValueError, IndexError, OverflowError):
        return
    for rule in rules:
        yield from rule.extract(image)
