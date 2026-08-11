# -*- coding: UTF-8 -*-
"""SNOW-compatible trailing-whitespace steganography (plain and ``-C`` modes)."""
import re

from ..__common__ import add, b, ensure_str
from .snow_huffman import CODES


def _snow_bits(text, compressed):
    data = b(text)
    if compressed:
        return "".join(CODES[byte] for byte in data)
    return "".join(format(byte, "08b") for byte in data)


def snow_encode(compressed=False):
    def encode(text, errors="strict"):
        bits = _snow_bits(text, compressed)
        bits += "0" * (-len(bits) % 3)
        lines = []
        for index in range(0, len(bits), 3):
            value = int(bits[index:index + 3], 2)
            spaces = ((value & 1) << 2) | (value & 2) | ((value & 4) >> 2)
            marker = "\t" if index == 0 or spaces == 0 else ""
            lines.append("SNOW" + marker + " " * spaces)
        result = "\n".join(lines) + ("\n" if lines else "")
        return result, len(b(text))
    return encode


def _extract_bits(text):
    bits, started = "", False
    for line in ensure_str(text).splitlines():
        match = re.search(r"[ \t]+$", line)
        if match is None:
            continue
        whitespace = match.group()
        if not started and whitespace[0] == " ":
            continue
        if not started:
            started = True
            whitespace = whitespace[1:]
            if not whitespace:
                continue
        spaces = 0
        for char in whitespace:
            if char == " ":
                spaces += 1
                continue
            if spaces > 7:
                raise ValueError("SNOW group contains more than seven spaces")
            bits += str(spaces & 1) + str((spaces >> 1) & 1) + str((spaces >> 2) & 1)
            spaces = 0
        if spaces:
            if spaces > 7:
                raise ValueError("SNOW group contains more than seven spaces")
            bits += str(spaces & 1) + str((spaces >> 1) & 1) + str((spaces >> 2) & 1)
    return bits


def snow_decode(compressed=False):
    def decode(text, errors="strict"):
        bits = _extract_bits(text)
        if compressed:
            inverse, pending, output = {code: byte for byte, code in enumerate(CODES)}, "", bytearray()
            prefixes = {code[:length] for code in CODES for length in range(1, len(code) + 1)}
            for bit in bits:
                pending += bit
                if pending in inverse:
                    output.append(inverse[pending])
                    pending = ""
                elif pending not in prefixes:
                    raise ValueError("invalid SNOW Huffman stream")
            return bytes(output), len(ensure_str(text))
        result = bytes(int(bits[index:index + 8], 2) for index in range(0, len(bits) // 8 * 8, 8))
        return result, len(ensure_str(text))
    return decode


add("snow", snow_encode(False), snow_decode(False), r"^(?:snow|stegsnow)$")
add("snow_compressed", snow_encode(True), snow_decode(True),
    r"^(?:snow[-_]?(?:compressed|compress|c)|stegsnow[-_]?c)$", aliases=["snow-compressed"])
