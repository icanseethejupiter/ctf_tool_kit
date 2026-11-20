from __future__ import annotations

import argparse
import itertools
import json
import os
import sys

from . import __version__
from .finder import Finder
from .explain import walkthrough

BANNER = "\n  >> flag_capturer v{v}  -  peel the layers, grab the flag\n"


def _enable_windows_ansi():
    """Old Windows consoles (PowerShell 5.1) print colour codes as junk unless asked nicely."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k.SetConsoleMode(h, mode.value | 0x0004))
    except Exception:
        return False


def _color(on):
    if not on or os.environ.get("NO_COLOR") or not _enable_windows_ansi():
        return lambda s, c: s
    codes = {"g": "32;1", "d": "2", "y": "33", "r": "31"}
    return lambda s, c: f"\033[{codes[c]}m{s}\033[0m"


def _targets(paths, max_size):
    for p in paths:
        if p == "-":
            yield "<stdin>", sys.stdin.buffer.read()
        elif os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    fp = os.path.join(root, f)
                    try:
                        if os.path.getsize(fp) <= max_size:
                            with open(fp, "rb") as fh:
                                yield fp, fh.read()
                    except OSError:
                        continue
        elif os.path.isfile(p):
            if os.path.getsize(p) > max_size:
                print(f"skip {p}: larger than --max-size", file=sys.stderr)
                continue
            with open(p, "rb") as fh:
                yield p, fh.read()
        else:
            print(f"not found: {p}", file=sys.stderr)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="flag_capturer",
        description="Dig CTF flags out of files or strings through layers of encoding "
                    "(base64/32/85, hex, binary, rot, xor, gzip/zlib, zip ...).")
    ap.add_argument("targets", nargs="*", help="files or folders to scan (default: current folder), '-' for stdin")
    ap.add_argument("-s", "--string", action="append", default=[], help="scan this text directly")
    ap.add_argument("-p", "--prefix", action="append", default=[],
                    help="extra flag prefix, e.g. -p DUCTF -p picoCTF")
    ap.add_argument("-r", "--regex", help="your own flag regex (Python syntax)")
    ap.add_argument("-d", "--depth", type=int, default=5, help="max decoding layers (default 5)")
    ap.add_argument("--max-nodes", type=int, default=20000, help="search budget per target")
    ap.add_argument("--max-size", type=int, default=50, help="skip files bigger than N MB (default 50)")
    ap.add_argument("--no-xor", action="store_true", help="skip single-byte xor brute force")
    ap.add_argument("--loose", action="store_true", help="also match any WORD{...} pattern")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("-e", "--explain", action="store_true", help="show a reproducible walkthrough for each hit")
    ap.add_argument("-q", "--quiet", action="store_true", help="print flags only")
    ap.add_argument("-V", "--version", action="version", version=f"flag_capturer {__version__}")
    a = ap.parse_args(argv)

    if not a.targets and not a.string:
        # nothing given: read piped input, otherwise scan the folder you're standing in
        a.targets = ["."] if sys.stdin.isatty() else ["-"]

    paint = _color(sys.stdout.isatty() and not a.json)
    if not (a.quiet or a.json):
        print(paint(BANNER.format(v=__version__), "d"))

    items = [(f"<string {i + 1}>", s.encode()) for i, s in enumerate(a.string)]
    items_iter = itertools.chain(items, _targets(a.targets, a.max_size * 1024 * 1024))
    found = []
    for source, data in items_iter:
        f = Finder(prefixes=a.prefix, regex=a.regex, max_depth=a.depth,
                   max_nodes=a.max_nodes, xor=not a.no_xor, loose=a.loose, explain=a.explain)
        if not (a.quiet or a.json):
            label, _ = f.formats.identify(data)
            print(f"[{label}] {source}")
        hits = f.scan(data, source)
        found += hits
        if a.json:
            continue
        for h in hits:
            if a.quiet:
                print(h.flag)
            else:
                print(paint("[+] ", "g") + paint(h.flag, "g"))
                print(paint(f"    {h.source}  via  {h.path()}", "d"))
            if a.explain:
                info = walkthrough(h)
                print("    How to find it by hand:")
                for n, step in enumerate(info["steps"], 1):
                    safe = step.encode("ascii", "backslashreplace").decode("ascii")
                    prose, marker, code = safe.partition("\n@'\n")
                    print(f"      {n}. " + prose.replace("\n", "\n         "))
                    if marker:
                        # PowerShell 5.1 requires the closing here-string marker in column one.
                        print("@'\n" + code)
                recipe = info["cyberchef"]
                if recipe:
                    print("    CyberChef recipe (original input):\n      " + recipe)

    if a.json:
        print(json.dumps([dict(flag=h.flag, source=h.source, chain=h.chain,
                               **(walkthrough(h) if a.explain else {})) for h in found],
                         ensure_ascii=True, indent=2))
    elif not found:
        # always say so (on stderr in quiet mode) so silence never looks like a crash
        print(paint("[-] no flag found. try --loose, -p <PREFIX>, or a bigger -d", "y"),
              file=sys.stderr if a.quiet else sys.stdout)
    return 0 if found else 1
