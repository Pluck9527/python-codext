# -*- coding: UTF-8 -*-
"""Vigenere codecs whose keys may contain URLs or other punctuation."""
from string import ascii_lowercase, ascii_uppercase

from ..__common__ import add, ensure_str


def _factory(key, decode=False):
    letters = "".join(char.lower() for char in key if char.lower() in ascii_lowercase)
    if not letters:
        raise ValueError("Vigenere key must contain at least one ASCII letter")

    def code(text, errors="strict"):
        output, cursor = [], 0
        for char in ensure_str(text):
            if char not in ascii_lowercase + ascii_uppercase:
                output.append(char)
                continue
            alphabet = ascii_lowercase if char in ascii_lowercase else ascii_uppercase
            shift = ord(letters[cursor % len(letters)]) - 97
            output.append(alphabet[(alphabet.index(char) + (-shift if decode else shift)) % 26])
            cursor += 1
        result = "".join(output)
        return result, len(result)
    return code


def vigenere_hex_encode(key):
    return _factory(bytes.fromhex(key[1:]).decode("utf-8"))


def vigenere_hex_decode(key):
    return _factory(bytes.fromhex(key[1:]).decode("utf-8"), True)


def add_vigenere_codec(name, key):
    return add(name, _factory(str(key)), _factory(str(key), True))


add("vigenere_hex_key", vigenere_hex_encode, vigenere_hex_decode,
    r"^vigenere[-_](?:key[-_])?(h(?:4[1-9a-fA-F]|5[0-9aA]|6[1-9a-fA-F]|7[0-9aA])"
    r"(?:[0-9a-fA-F]{2})*)$", aliases=["vigenere-hex-key"])
