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
- gzip / zlib / bz2 / lzma streams and zip archives
- cutting base64/hex/binary-looking chunks out of longer text and trying them alone

Layers stack (default depth 5), and each hit shows the path it took.

## Play fair

Use it on CTFs and practice boxes that allow tools. If a competition or exam says
no automated tools, leave it at home.

## License

PolyForm Strict 1.0.0: free to install and use for noncommercial purposes,
but no redistribution and no modified versions. See `LICENSE`.
