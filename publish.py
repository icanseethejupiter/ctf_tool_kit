"""Build this project and upload the current version to PyPI.

Usage (from this folder):  python publish.py

It reads the version from pyproject.toml, checks it matches the package,
builds a fresh wheel + sdist, asks for your PyPI API token in a small
password box (Ctrl+V works there) and uploads only that version's files.
The token is never written to disk.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable


def run(*args, **kw):
    print("> " + " ".join(str(a) for a in args))
    return subprocess.run([str(a) for a in args], cwd=ROOT, **kw)


def read_version():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    name = re.search(r'^name\s*=\s*"([^"]+)"', text, re.M)
    if not (m and name):
        sys.exit("Couldn't find name/version in pyproject.toml")
    init = (ROOT / "src" / "flag_capturer" / "__init__.py").read_text(encoding="utf-8")
    m2 = re.search(r'__version__\s*=\s*"([^"]+)"', init)
    if not m2 or m2.group(1) != m.group(1):
        sys.exit(f"Version mismatch: pyproject.toml says {m.group(1)}, "
                 f"__init__.py says {m2.group(1) if m2 else '?'}. Fix one of them first.")
    return name.group(1), m.group(1)


def ensure_tools():
    missing = [mod for mod in ("build", "twine")
               if subprocess.run([PY, "-c", f"import {mod}"], capture_output=True).returncode]
    if missing:
        print(f"Installing {', '.join(missing)} ...")
        if run(PY, "-m", "pip", "install", "--user", *missing).returncode:
            sys.exit("Couldn't install the build tools.")


def ask_token():
    token = ""
    try:
        import tkinter as tk
        root = tk.Tk()
        root.title("PyPI token")
        root.attributes("-topmost", True)
        tk.Label(root, text="Paste your PyPI API token (starts with pypi-):").pack(padx=14, pady=(12, 4))
        box = tk.Entry(root, show="*", width=48)
        box.pack(padx=14)
        box.focus_set()
        result = {}

        def ok(_=None):
            result["t"] = box.get().strip()
            root.destroy()

        box.bind("<Return>", ok)
        tk.Button(root, text="Upload", command=ok).pack(pady=10)
        root.mainloop()
        token = result.get("t", "")
    except Exception:
        import getpass
        token = getpass.getpass("PyPI API token (input hidden): ").strip()
    if not token.startswith("pypi-"):
        sys.exit("No valid token given (it should start with 'pypi-'). Nothing uploaded.")
    return token


def main():
    name, version = read_version()
    dist_name = name.replace("-", "_")
    print(f"\n== {name} {version} ==\n")

    status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True)
    if status.returncode == 0 and status.stdout.strip():
        print("Note: you have uncommitted changes. They WILL be in this upload.\n")

    if input(f"Upload {name} {version} to PyPI? [y/N] ").strip().lower() != "y":
        sys.exit("Cancelled.")

    ensure_tools()
    dist = ROOT / "dist"
    for old in dist.glob(f"{dist_name}-{version}*"):
        old.unlink()  # rebuild this version cleanly; other versions are left alone
    if run(PY, "-m", "build").returncode:
        sys.exit("Build failed; nothing uploaded.")

    files = sorted(dist.glob(f"{dist_name}-{version}*"))
    if not files:
        sys.exit("Build produced no files for this version.")

    token = ask_token()
    env = dict(os.environ, TWINE_USERNAME="__token__", TWINE_PASSWORD=token)
    rc = run(PY, "-m", "twine", "upload", "--non-interactive", "--verbose", *files, env=env).returncode
    if rc:
        print("\nUpload failed. If it says the file already exists, bump the version "
              "in pyproject.toml and src/flag_capturer/__init__.py, then run this again.")
        sys.exit(rc)
    print(f"\nDone: https://pypi.org/project/{name}/{version}/")
    print("Others can update with:  pip install --upgrade " + name)


if __name__ == "__main__":
    main()
