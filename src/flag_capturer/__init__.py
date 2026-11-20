"""flag_capturer - dig CTF flags out of files and strings, through layers of encoding."""
from .finder import Hit, Finder, scan_bytes

__version__ = "0.5.0"
__all__ = ["Hit", "Finder", "scan_bytes", "__version__"]
