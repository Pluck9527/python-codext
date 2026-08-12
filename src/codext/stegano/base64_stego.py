# -*- coding: UTF-8 -*-
"""Base64 padding-bit steganography with generated or caller supplied carriers."""
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


def hide_base64_padding(carriers, secret):
    """Hide bytes in unused Base64 padding bits without changing decoded carriers."""
    lines = [line.strip() for line in ensure_str(carriers).splitlines() if line.strip()]
    bits = "".join(format(byte, "08b") for byte in b(secret))
    capacity = sum(line.count("=") * 2 for line in lines)
    if capacity != len(bits):
        raise ValueError("Base64 carriers provide %d bits, but exactly %d are required" % (capacity, len(bits)))
    output, cursor = [], 0
    for line in lines:
        canonical = base64.b64encode(base64.b64decode(line, validate=True)).decode()
        pads = canonical.count("=")
        if not pads:
            output.append(canonical)
            continue
        width = pads * 2
        index = len(canonical.rstrip("=")) - 1
        value = ALPHABET.index(canonical[index]) + int(bits[cursor:cursor + width], 2)
        output.append(canonical[:index] + ALPHABET[value] + canonical[index + 1:])
        cursor += width
    return "\n".join(output)


def base64_stego_encode(text, errors="strict"):
    source = b(text)
    # "QQ==" carries four bits; two independently decodable lines carry one byte.
    carriers = "\n".join("QQ==" for _ in range(len(source) * 2))
    result = hide_base64_padding(carriers, source)
    return result, len(source)


add("base64_stego", base64_stego_encode, base64_stego_decode, r"^base[-_]?64[-_]?(?:steg|stego|hidden)$",
    aliases=["base64-stego"], expansion_factor=1.)
