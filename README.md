# flag_capturer

Point it at a file or a string and it digs out CTF flags, peeling off layers of
encoding until something looks like `flag{...}`. Pure Python, no dependencies.

```
$ flag_capturer challenge.bin
[+] flag{x0r_1s_n0t_encrypt10n}
    challenge.bin  via  strings -> base64 -> xor(0x12)
```

## Install

```
pip install --user git+https://github.com/icanseethejupiter/ctf_tool_kit
# no git on the machine? grab the zip instead:
pip install --user https://github.com/icanseethejupiter/ctf_tool_kit/archive/refs/heads/main.zip
```

Then run `flag_capturer` (or the short `flagcap`). If the command is not found,
`python -m flag_capturer` always works.

## Use

在 Windows 资源管理器打开题目文件夹，在地址栏输入 `powershell` 并回车。运行：

```powershell
python -m flag_capturer .
```

点号表示扫描当前文件夹及其子文件夹。只扫一个文件可以用 `python -m flag_capturer .\dist1.exe`。默认识别 flag、CTF 类前缀、HTB 和 THM。自定义前缀只写名字，如 `-p MYTEAM`。PowerShell 出现 `>>` 时按 Ctrl+C 回到命令行。

The static scanner recognizes several MinGW x64 comparison layouts, including checks on separate slices of the input, repeating-key XOR with a known flag prefix, and small integer arrays. It also tries little-endian literals in Intel assembly listings. A hit is a candidate recovered from file contents.

```
flag_capturer                          # everything in the current folder
flag_capturer file.bin                 # a file
flag_capturer ./challenge_folder       # every file in a folder
flag_capturer -s "ZmxhZ3toaX0="        # a string
cat dump.txt | flag_capturer           # stdin
flag_capturer file -p DUCTF -p picoCTF # extra flag prefixes
flag_capturer file -r "SECRET-[0-9]{6}"  # your own regex
flag_capturer file --json              # for scripts
```

## What it tries

- printable ASCII and UTF-16 strings inside binaries
- base64 / base64url / base32 / base85 / ascii85, hex, binary, decimal, octal, URL encoding
- rot13 plus every other Caesar shift, rot47, reversed text
- single-byte XOR (all 255 keys, checked cheaply against known prefixes first)
- PE data arrays following a short, zero-padded key on a 16-byte boundary. The scanner tries repeating-key XOR on Base64 text and byte subtraction on flag-shaped text.
- gzip / zlib / bz2 / lzma streams and zip archives
- cutting base64/hex/binary-looking chunks out of longer text and trying them alone

Layers stack (default depth 5), and each hit shows the path it took.

## Play fair

Use it on CTFs and practice boxes that allow tools. If a competition or exam says
no automated tools, leave it at home.

## License

PolyForm Strict 1.0.0: free to install and use for noncommercial purposes,
but no redistribution and no modified versions. See `LICENSE`.
