# -*- coding: UTF-8 -*-
"""Base92 codec compatible with thenoviceoof/base92."""
from ..__common__ import *


ALPHABET = "!" + "".join(chr(value) for value in range(ord("#"), ord("_") + 1)) + \
           "".join(chr(value) for value in range(ord("a"), ord("}") + 1))


def base92_encode(text, errors="strict"):
    data, buffer, bits, result = b(text), 0, 0, []
    if not data:
        return "~", 1
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 13:
            value = buffer >> (bits - 13)
            buffer &= (1 << (bits - 13)) - 1
            bits -= 13
            result.extend((ALPHABET[value // 91], ALPHABET[value % 91]))
    if bits:
        width = 6 if bits < 7 else 13
        value = buffer << (width - bits)
        result.extend((ALPHABET[value],) if width == 6 else (ALPHABET[value // 91], ALPHABET[value % 91]))
    return (encoded := "".join(result)), len(encoded)


def base92_decode(text, errors="strict"):
    text = ensure_str(text)
    if text in ("", "~"):
        return b"", len(text)
    if len(text) == 1:
        raise Base92DecodeError("one character is not a valid Base92 encoding")
    error = handle_error("base92", errors, decode=True)
    buffer, bits, result, pairs = 0, 0, bytearray(), len(text) // 2 * 2
    for index in range(0, pairs, 2):
        try:
            value = ALPHABET.index(text[index]) * 91 + ALPHABET.index(text[index + 1])
        except ValueError:
            replacement = error(text[index:index + 2], index)
            if replacement:
                result.extend(b(replacement))
            continue
        if value >= 8192:
            raise Base92DecodeError("invalid Base92 pair at position %d" % index)
        buffer = (buffer << 13) | value
        bits += 13
        while bits >= 8:
            result.append(buffer >> (bits - 8))
            buffer &= (1 << (bits - 8)) - 1
            bits -= 8
    if pairs < len(text):
        try:
            buffer = (buffer << 6) | ALPHABET.index(text[-1])
            bits += 6
        except ValueError:
            error(text[-1], len(text) - 1)
        while bits >= 8:
            result.append(buffer >> (bits - 8))
            buffer &= (1 << (bits - 8)) - 1
            bits -= 8
    return bytes(result), len(text)


add("base92", base92_encode, base92_decode, r"^base[-_]?92$", expansion_factor=1.25)
