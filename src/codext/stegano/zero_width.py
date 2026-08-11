# -*- coding: UTF-8 -*-
"""Zero-width Unicode binary steganography codec."""
from ..__common__ import *


ZERO, ONE, SEPARATOR = "\u200b", "\u200c", "\u200d"


def zero_width_encode(text, errors="strict"):
    result = SEPARATOR.join("".join(ONE if bit == "1" else ZERO for bit in format(byte, "08b")) for byte in b(text))
    return result, len(result)


def zero_width_decode(text, errors="strict"):
    text = ensure_str(text)
    bits = "".join("0" if char == ZERO else "1" for char in text if char in (ZERO, ONE))
    if len(bits) % 8 and errors == "strict":
        raise ZeroWidthDecodeError("zero-width bit count must be divisible by eight")
    result = bytes(int(bits[index:index + 8], 2) for index in range(0, len(bits) // 8 * 8, 8))
    return result, len(text)


add("zero_width", zero_width_encode, zero_width_decode, r"^zero[-_]?width(?:[-_]?steg(?:o)?)?$",
    aliases=["zero-width"], entropy=1., printables_rate=0., expansion_factor=8.)
