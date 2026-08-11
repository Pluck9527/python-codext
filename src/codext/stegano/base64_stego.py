# -*- coding: UTF-8 -*-
"""Decoder for Base64 padding-bit steganography."""
import base64
from string import ascii_lowercase, ascii_uppercase, digits

from ..__common__ import *


ALPHABET = ascii_uppercase + ascii_lowercase + digits + "+/"


def base64_stego_decode(text, errors="strict"):
    hidden, error = "", handle_error("base64_stego", errors, decode=True, item="line")
    for index, line in enumerate(ensure_str(text).splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            canonical = base64.b64encode(base64.b64decode(line, validate=True)).decode()
            pads = line.count("=")
            if pads:
                offset = (ALPHABET.index(line.rstrip("=")[-1]) -
                          ALPHABET.index(canonical.rstrip("=")[-1])) % (1 << (pads * 2))
                hidden += format(offset, "0%db" % (pads * 2))
        except (ValueError, IndexError):
            replacement = error(line, index)
            if replacement:
                hidden += "".join(format(byte, "08b") for byte in b(replacement))
    result = bytes(int(hidden[index:index + 8], 2) for index in range(0, len(hidden) // 8 * 8, 8))
    return result, len(ensure_str(text))


add("base64_stego", None, base64_stego_decode, r"^base[-_]?64[-_]?(?:steg|stego|hidden)$",
    aliases=["base64-stego"], expansion_factor=1.)
