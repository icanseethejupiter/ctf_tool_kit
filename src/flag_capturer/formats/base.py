from dataclasses import dataclass
from typing import Iterable, Protocol


@dataclass(frozen=True)
class Part:
    label: str
    data: bytes
    nested: bool = False


class Analyzer(Protocol):
    def identify(self, data: bytes) -> str:
        """Return a display name for recognized contents, otherwise an empty string."""
        ...

    def extract(self, data: bytes, *, xor: bool, prefixes: list) -> Iterable[Part]:
        ...
