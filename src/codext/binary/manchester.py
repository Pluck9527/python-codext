# -*- coding: UTF-8 -*-
"""Manchester Codec - Manchester content encoding.

This codec:
- en/decodes strings from str to str
- en/decodes strings from bytes to bytes
- decodes file content to str (read)
- encodes file content from str to bytes (write)
"""
from ..__common__ import add, b, ensure_str


__examples1__ = {'enc(manchester)': {'This is a test!': "fei\x95i\x96jZYUi\x96jZYUiVYUjeifjZjeYV"}}
__examples2__ = {
    'enc(manchester-inverted|ethernet|ieee802.4)': {
        'This is a test!': "\x99\x9a\x96j\x96i\x95\xa5\xa6\xaa\x96i\x95\xa5\xa6\xaa\x96\xa9\xa6\xaa\x95\x9a\x96\x99"
                           "\x95\xa5\x95\x9a\xa6\xa9",
    },
}


def manchester_encode(clock):
    def encode(text, errors="strict"):
        r = ""
        for c in text:
            bin_c = bin(ord(c))[2:].zfill(8)
            for i in range(0, 8, 4):
                r += chr(int("".join(2*bit for bit in bin_c[i:i+4]), 2) ^ clock)
        return r, len(b(text))
    return encode


def manchester_decode(clock):
    def decode(text, errors="strict"):
        r, bits = "", ""
        for c in text:
            bin_c = bin(ord(c) ^ clock)[2:].zfill(8)
            bits += "".join(bin_c[i] for i in range(0, len(bin_c), 2))
            if len(bits) == 8:
                r += chr(int(bits, 2))
                bits = ""
        return r, len(b(text))
    return decode


add("manchester", manchester_encode(0x55), manchester_decode(0x55), examples=__examples1__, printables_rate=.25,
    entropy=lambda e: .17616*e+2.56229)
add("manchester-inverted", manchester_encode(0xaa), manchester_decode(0xaa), examples=__examples2__,
    pattern=r"^(?:manchester-inverted|ethernet|ieee802\.4)$", entropy=lambda e: .17616*e+2.56229)


def differential_manchester_encode(initial=0):
    def encode(text, errors="strict"):
        level, output = int(initial), []
        for byte in b(text):
            for bit in format(byte, "08b"):
                if bit == "0":
                    level ^= 1
                output.append(str(level))
                level ^= 1
                output.append(str(level))
        result = "".join(output)
        return result, len(b(text))
    return encode


def differential_manchester_decode(initial=0):
    def decode(text, errors="strict"):
        symbols = "".join(char for char in ensure_str(text) if char in "01")
        if len(symbols) % 16:
            raise ValueError("differential Manchester input must contain 16 symbols per byte")
        level, bits = int(initial), ""
        for index in range(0, len(symbols), 2):
            first, second = int(symbols[index]), int(symbols[index + 1])
            if first == second:
                raise ValueError("differential Manchester pair has no mid-bit transition")
            bits += "1" if first == level else "0"
            level = second
        result = bytes(int(bits[index:index + 8], 2) for index in range(0, len(bits), 8))
        return result, len(ensure_str(text))
    return decode


add("differential_manchester", differential_manchester_encode(0), differential_manchester_decode(0),
    r"^(?:differential[-_]?manchester|manchester[-_]?differential|diff[-_]?manchester)$",
    aliases=["differential-manchester"])
add("differential_manchester_inverted", differential_manchester_encode(1), differential_manchester_decode(1),
    r"^(?:differential[-_]?manchester[-_]?(?:inv|inverted)|diff[-_]?manchester[-_]?(?:inv|inverted))$",
    aliases=["differential-manchester-inverted"])

