"""Read CLR metadata and constant IL expressions without loading the assembly."""
import struct

from ..pe_constants import pe_header
from .base import Part


def _concat_arity(tables, token):
    refs = tables.MemberRef
    if token.table != 10 or not refs or not 1 <= token.rid <= len(refs.rows):
        return 0
    member = refs.rows[token.rid - 1]
    if str(member.Name) != "Concat" or member.Class.table is not tables.TypeRef:
        return 0
    owner = member.Class.row
    if not owner or (str(owner.TypeNamespace), str(owner.TypeName)) != ("System", "String"):
        return 0
    sig = member.Signature.value
    # Static method, string return type and two to four string arguments.
    for count in (2, 3, 4):
        if sig == bytes([0, count]) + b"\x0e" * (count + 1):
            return count
    return 0


class ManagedAnalyzer:
    def identify(self, data):
        off = pe_header(data)
        if off is None:
            return ""
        opt = off + 24
        directories = {b"\x0b\x01": 96, b"\x0b\x02": 112}.get(data[opt:opt + 2])
        size = int.from_bytes(data[off + 20:off + 22], "little")
        if not directories or size < directories + 120 or opt + size > len(data):
            return ""
        count = struct.unpack_from("<I", data, opt + directories - 4)[0]
        rva, length = struct.unpack_from("<II", data, opt + directories + 112)
        if count < 15 or not rva or length < 72:
            return ""
        section_count = struct.unpack_from("<H", data, off + 6)[0]
        table = opt + size
        if section_count > 96 or table + section_count * 40 > len(data):
            return ""

        def locate(address, needed):
            for n in range(section_count):
                start, raw_size, raw = struct.unpack_from("<III", data, table + n*40 + 12)
                delta = address - start
                if 0 <= delta <= raw_size - needed and raw + delta + needed <= len(data):
                    return raw + delta
            return None

        clr = locate(rva, 72)
        if clr is not None:
            meta = locate(struct.unpack_from("<I", data, clr + 8)[0], 4)
            if meta is not None and data[meta:meta + 4] == b"BSJB":
                return ".NET assembly"
        return ""

    def extract(self, data, **options):
        import dnfile
        import pefile
        from dncil.cil.body.reader import read_method_body_from_bytes
        from dncil.cil.error import MethodBodyFormatError

        try:
            image = dnfile.dnPE(data=data, clr_lazy_load=True)
            tables = image.net.mdtables if image.net else None
            if not tables or not tables.MethodDef or not image.net.user_strings:
                return
            for method in tables.MethodDef.rows[:20000]:
                if not method.Rva or not method.ImplFlags.miIL:
                    continue
                try:
                    body = read_method_body_from_bytes(image.get_data(method.Rva, 65536))
                    yield from self._literals(body.instructions, image.net, str(method.Name))
                except (MethodBodyFormatError, pefile.PEFormatError, IndexError, ValueError):
                    continue
        except (pefile.PEFormatError, dnfile.errors.dnFormatError, ValueError, struct.error):
            return

    def _literals(self, instructions, metadata, name):
        stack = []
        for instruction in instructions:
            op = instruction.opcode.name
            if op == "ldstr" and instruction.operand.table == 0x70:
                item = metadata.user_strings.get(instruction.operand.rid)
                if item is not None and item.value is not None:
                    value = item.value.encode("utf-8")
                    stack.append(value)
                    yield Part(f".NET {name} ldstr", value)
                    continue
            elif op == "call":
                count = _concat_arity(metadata.mdtables, instruction.operand)
                if count and len(stack) >= count:
                    value = b"".join(stack[-count:])
                    del stack[-count:]
                    stack.append(value)
                    yield Part(f".NET {name} String.Concat", value)
                    continue
            if op != "nop":
                stack.clear()
