"""Strict stable software versions; no loose substring coercion."""

from dataclasses import dataclass
import re


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int = 0
    patch: int = 0
    letter: int = 0

    def text(self):
        suffix = chr(96 + self.letter) if self.letter else ""
        return f"{self.major}.{self.minor}.{self.patch}{suffix}"


def parse_version(value, *, openssl=False):
    if not isinstance(value, str) or len(value) > 32:
        raise ValueError("unsupported_version")
    m = re.fullmatch(
        r"(0|[1-9][0-9]{0,3})(?:\.(0|[1-9][0-9]{0,3}))?(?:\.(0|[1-9][0-9]{0,3}))?([a-z]?)",
        value,
    )
    if not m:
        raise ValueError("unsupported_version")
    a, b, c, letter = m.groups()
    if letter and (not openssl or int(a) > 1 or b is None or c is None):
        raise ValueError("unsupported_version")
    return Version(int(a), int(b or 0), int(c or 0), ord(letter) - 96 if letter else 0)
