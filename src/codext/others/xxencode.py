# -*- coding: UTF-8 -*-
"""XXencode binary-to-text codec."""
from ..__common__ import *


ALPHABET = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def xxencode(text, errors="strict"):
    data, lines = b(text), []
    for start in range(0, len(data), 45):
        chunk, encoded = data[start:start + 45], ""
        for index in range(0, len(chunk), 3):
            block = chunk[index:index + 3] + b"\0" * (3 - len(chunk[index:index + 3]))
            value = int.from_bytes(block, "big")
            encoded += "".join(ALPHABET[(value >> shift) & 63] for shift in (18, 12, 6, 0))
        lines.append(ALPHABET[len(chunk)] + encoded)
    return (output := "\n".join(lines)), len(output)


def xxdecode(text, errors="strict"):
    result, error = bytearray(), handle_error("xx", errors, decode=True, kind="line", item="line")
    for index, line in enumerate(ensure_str(text).splitlines()):
        if not line:
            continue
        try:
            length, body, decoded = ALPHABET.index(line[0]), line[1:], bytearray()
            if len(body) % 4:
                raise ValueError
            for offset in range(0, len(body), 4):
                value = 0
                for char in body[offset:offset + 4]:
                    value = (value << 6) | ALPHABET.index(char)
                decoded.extend(value.to_bytes(3, "big"))
            result.extend(decoded[:length])
        except ValueError:
            replacement = error(line, index)
            if replacement:
                result.extend(b(replacement))
    return bytes(result), len(ensure_str(text))


add("xx", xxencode, xxdecode, r"^xx(?:[-_]?encode|[-_]?codec)?$", aliases=["xxencode"])
