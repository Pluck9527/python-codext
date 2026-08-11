# -*- coding: UTF-8 -*-
"""Unicode homoglyph steganography compatible with Twitter Secret Messages."""
import math

from ..__common__ import add, ensure_str


SECRET_ALPHABET = " abcdefghijklmnopqrstuvwxyz123456789'0.:/\\%-_?&;"
EXTRA = {
    "A": "ΑА", "B": "ΒВ", "C": "ϹⅭ", "E": "ΕЕ", "H": "ΗН",
    "I": "ΙІ", "K": "ΚK", "M": "ΜМ", "O": "ΟО", "P": "ΡР",
    "T": "ΤТ", "V": "ѴⅤ", "X": "ΧⅩ", "Y": "ΥҮ", "c": "ϲс",
    "i": "іⅰ", "o": "οо", "v": "νⅴ", "x": "хⅹ",
}
SPACES = "               "


def _homoglyphs():
    result = {char: [chr(ord(char) + 0xfee0)] for char in
              "!\"$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"}
    result.update({char: result[char] + list(EXTRA.get(char, "")) for char in result})
    result[" "] = list(SPACES)
    return result


def hide_twitter_secret(cover, secret):
    bits = "".join(format(SECRET_ALPHABET.index(char), "06b") for char in ensure_str(secret).lower() + " "
                   if char in SECRET_ALPHABET)
    glyphs, output = _homoglyphs(), []
    for char in ensure_str(cover):
        options = glyphs.get(char)
        width = int(math.log2(len(options) + 1)) if options else 0
        if width and bits:
            value = int(bits[:width].ljust(width, "0"), 2)
            bits = bits[width:]
            char = options[value - 1] if value else char
        output.append(char)
    if bits:
        raise ValueError("cover text has insufficient homoglyph capacity")
    return "".join(output)


def reveal_twitter_secret(text):
    lookup = {}
    for char, options in _homoglyphs().items():
        width = int(math.log2(len(options) + 1))
        lookup[char] = "0" * width
        lookup.update({option: format(index + 1, "0%db" % width) for index, option in enumerate(options)})
    bits = "".join(lookup.get(char, "") for char in ensure_str(text))
    decoded = "".join(SECRET_ALPHABET[int(bits[index:index + 6], 2)]
                      for index in range(0, len(bits) - 5, 6)
                      if int(bits[index:index + 6], 2) < len(SECRET_ALPHABET))
    return decoded.rstrip(" ")


def twitter_secret_encode(text, errors="strict"):
    source = ensure_str(text)
    secret, separator, cover = source.partition("\n")
    if not separator:
        cover = ("The quick brown fox jumps over the lazy dog. " * (len(secret) + 2)).strip()
    result = hide_twitter_secret(cover, secret)
    return result, len(source)


def twitter_secret_decode(text, errors="strict"):
    source = ensure_str(text)
    return reveal_twitter_secret(source), len(source)


add("twitter_secret", twitter_secret_encode, twitter_secret_decode,
    r"^(?:twitter[-_]?secret|homoglyph[-_]?steg)$")
