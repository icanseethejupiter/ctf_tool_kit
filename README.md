# flag_capturer

Point it at a file, a folder or a string and it digs out CTF flags, peeling off
layers of encoding until something looks like `flag{...}`. Every hit shows the
path it took.

```
$ flag_capturer challenge.bin
[binary] challenge.bin
[+] flag{x0r_1s_n0t_encrypt10n}
    challenge.bin  via  strings -> base64 -> xor(0x12)
```

## Install

```
pip install flag-capturer
```

No admin rights? Use `pip install --user flag-capturer`. Then run
`flag_capturer` (or the short `flagcap`). If the command is not found,
`python -m flag_capturer` always works.

## Use

```
flag_capturer                            # everything in the current folder
flag_capturer file.bin                   # one file
flag_capturer ./challenge_folder         # every file in a folder
flag_capturer -s "ZmxhZ3toaX0="          # a string
cat dump.txt | flag_capturer             # stdin
flag_capturer file -p DUCTF -p picoCTF   # extra flag prefixes (name only)
flag_capturer file -r "SECRET-[0-9]{6}"  # your own regex
flag_capturer file --loose               # also show anything shaped like WORD{...}
flag_capturer file --json                # for scripts
```

Built-in prefixes: `flag`, anything ending in `CTF`, `HTB`, `THM`. Flags with
other prefixes are still listed as `[?]` suggestions.

### 中文快速上手

在资源管理器打开题目文件夹，地址栏输入 `powershell` 回车，然后运行
`python -m flag_capturer .`（点号 = 当前文件夹）。flag 前缀不常见的话加
`-p 前缀名`。PowerShell 出现 `>>` 时按 Ctrl+C 退出。

## What it handles

**Encodings and layers** (stacked up to depth 5)
- ASCII and UTF-16 strings inside binaries
- base64 / base64url / base32 / base85 / ascii85, hex, binary, decimal, octal, URL encoding
- rot13 and every other Caesar shift, rot47, reversed text
- single-byte XOR (all 255 keys, pre-filtered against known prefixes)
- gzip / zlib / bz2 / lzma streams and zip archives
- base64/hex/binary-looking chunks cut out of longer text

**File formats** (the detected format is printed before each scan)
- **Windows PE (MinGW x64):** constant arrays and split comparison fragments,
  repeating-key XOR on Base64 text, byte subtraction on flag-shaped text
- **.NET assemblies:** IL string literals, including adjacent literals joined by
  `String.Concat`; read statically, never executed
- **PCAP / PCAPNG:** UDP payloads and reassembled TCP streams per direction
  (no TLS decryption or IP fragment reassembly)
- **Linux ELF x86-64:** literal IPv4 addresses passed to `connect`, built on the
  stack or read from read-only data; also from Ghidra text listings
- **Intel assembly listings:** little-endian immediates

## Limits

It only finds flags whose bytes are in the file in some encoded form. Flags
computed at runtime, checks against your input, encrypted data with an unknown
key, or values that need branches followed are out of scope: use Ghidra.
Every hit is a candidate recovered from file contents.

## Extending

Implement `formats.base.Analyzer` (`identify` and `extract`) and register the
instance in `formats.FORMATS`. Each extracted `Part` carries its bytes and
provenance; set `nested=True` for embedded files that should be identified again.

## Play fair

Use it on CTFs and practice boxes that allow tools. If a competition or exam says
no automated tools, leave it at home.

## License

PolyForm Strict 1.0.0: free to install and use for noncommercial purposes, but
no redistribution and no modified versions. See `LICENSE`.
