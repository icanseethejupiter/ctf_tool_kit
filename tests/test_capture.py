import base64
import codecs
import gzip
import io
import os
import struct
import zipfile
import zlib

from flag_capturer import scan_bytes

FLAG = b"flag{x0r_1s_n0t_encrypt10n}"


def found(data, flag=FLAG, **kw):
    return flag.decode() in [h.flag for h in scan_bytes(data, **kw)]


def xor(b, k):
    return bytes(c ^ k for c in b)


def junk(mid):
    return os.urandom(300) + mid + os.urandom(300)


def test_plain_in_binary():
    assert found(junk(FLAG))


def test_utf16():
    assert found(junk(FLAG.decode().encode("utf-16le")))


def test_base64_in_binary():
    assert found(junk(b"\x00" + base64.b64encode(FLAG) + b"\x00"))


def test_xor_raw():
    assert found(junk(xor(FLAG, 0x12)))


def test_base64_of_xor():
    assert found(b"key=" + base64.b64encode(xor(FLAG, 0x5A)))


def test_hex_rot13_base64():
    s = codecs.encode(base64.b64encode(FLAG).decode(), "rot13").encode().hex()
    assert found(s.encode())


def test_caesar_shift():
    shifted = bytes((c - 97 + 7) % 26 + 97 if 97 <= c <= 122 else c for c in FLAG)
    assert found(b"note: " + shifted)


def test_binary_and_decimal():
    assert found(" ".join(format(c, "08b") for c in FLAG).encode())
    assert found(" ".join(str(c) for c in FLAG).encode())


def test_base32_reverse():
    assert found(base64.b32encode(FLAG)[::-1])


def test_gzip_and_zlib():
    assert found(gzip.compress(FLAG))
    assert found(base64.b64encode(zlib.compress(FLAG)))


def test_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("inner/secret.txt", base64.b64encode(FLAG))
    assert found(buf.getvalue())


def test_custom_prefix():
    f = b"DUCTF{custom_prefix}"
    assert found(base64.b64encode(f), flag=f)
    f2 = b"ACME{own_prefix_ok}"
    assert found(xor(f2, 0x33), flag=f2, prefixes=["ACME"])


def test_nothing():
    assert scan_bytes(os.urandom(5000)) == []


def pe_with_array(key, payload):
    header = bytearray(512)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 128)
    header[128:132] = b"PE\0\0"
    struct.pack_into("<H", header, 134, 1)
    struct.pack_into("<H", header, 148, 240)
    section = 128 + 24 + 240
    header[section:section + 6] = b".rdata"
    body = key.ljust(16, b"\0") + payload
    struct.pack_into("<II", header, section + 16, len(body), len(header))
    return bytes(header) + body


def test_pe_repeating_xor_base64():
    key = b"\xcc\xdd\xee"
    text = base64.b64encode(FLAG[::-1])
    data = pe_with_array(key, bytes(v ^ key[i % len(key)] for i, v in enumerate(text)))
    assert found(data)
    assert not found(data, xor=False)


def test_pe_byte_shift_rot13():
    rotated = codecs.encode(FLAG.decode(), "rot13").encode()
    assert found(pe_with_array(b"\x09", bytes(v + 9 for v in rotated)))


def test_xor_inferred_from_custom_prefix():
    flag = b"EXAMPLE{another_key}"
    key = b"\x83\x1c\x45"
    cipher = bytes(v ^ key[i % len(key)] for i, v in enumerate(flag))
    assert found(pe_with_array(key[:1], cipher), flag, prefixes=["EXAMPLE"])


def test_separate_assembly_immediates():
    data = b"mov rax, 0x637b67616c66abcd\nmov rbx, 0x7d646362\nret\n"
    assert found(data, b"flag{cbcd}")
    assert not found(data.replace(b"\nmov rbx", b"\nret\nmov rbx"), b"flag{cbcd}")
