from dataclasses import dataclass
from typing import Iterable, Protocol


@dataclass(frozen=True)
class Part:
    label: str
    data: bytes
    nested: bool = False
    # A recovered value to present inside the user's chosen flag wrapper.
    wrap: bool = False


class Analyzer(Protocol):
    def identify(self, data: bytes) -> str:
        """Return a display name for recognized contents, otherwise an empty string."""
        ...

    def extract(self, data: bytes, *, xor: bool, prefixes: list) -> Iterable[Part]:
        ...
