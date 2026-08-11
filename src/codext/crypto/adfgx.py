# -*- coding: UTF-8 -*-
"""ADFGX and ADFGVX fractionating transposition ciphers."""
from ..__common__ import add, ensure_str


DEFAULT_SQUARES = {
    "adfgx": "phqgmeaynofdxkrcvszwbutil",
    "adfgvx": "ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8",
}


def _order(key):
    return sorted(range(len(key)), key=lambda index: (key[index], index))


def _factory(kind, key="", square_token="", decode=False):
    labels = kind.upper()
    key = (key or "german").lower()
    square = bytes.fromhex(square_token[1:]).decode() if square_token else DEFAULT_SQUARES[kind]
    if not key or len(square) != len(labels) ** 2 or len(set(square)) != len(square):
        raise ValueError("invalid ADFGX/ADFGVX key or square")

    def code(text, errors="strict"):
        source = "".join(ensure_str(text).lower().split())
        if not decode:
            source = source.replace("j", "i") if kind == "adfgx" and "j" not in square else source
            fractions = "".join(labels[square.index(char) // len(labels)] +
                                labels[square.index(char) % len(labels)] for char in source)
            columns = [fractions[index::len(key)] for index in range(len(key))]
            result = "".join(columns[index] for index in _order(key))
            return result, len(source)
        length, remainder = divmod(len(source), len(key))
        sizes = [length + (index < remainder) for index in range(len(key))]
        columns, cursor = [""] * len(key), 0
        for index in _order(key):
            columns[index] = source[cursor:cursor + sizes[index]]
            cursor += sizes[index]
        fractions = "".join(columns[column][row] for row in range(max(map(len, columns), default=0))
                            for column in range(len(key)) if row < len(columns[column]))
        if len(fractions) % 2 or any(char.upper() not in labels for char in fractions):
            raise ValueError("invalid ADFGX/ADFGVX ciphertext")
        result = "".join(square[labels.index(fractions[index].upper()) * len(labels) +
                                labels.index(fractions[index + 1].upper())]
                         for index in range(0, len(fractions), 2))
        return result, len(source)
    return code


def adfgx_encode(key="", square=""):
    return _factory("adfgx", key, square)


def adfgx_decode(key="", square=""):
    return _factory("adfgx", key, square, True)


def adfgvx_encode(key="", square=""):
    return _factory("adfgvx", key, square)


def adfgvx_decode(key="", square=""):
    return _factory("adfgvx", key, square, True)


PATTERN = r"[-_]([a-z]+)(?:[-_](h(?:[0-9a-fA-F]{2})+))?$"
add("adfgx", adfgx_encode, adfgx_decode, r"^adfgx" + PATTERN, aliases=["adfgx-cipher"])
add("adfgvx", adfgvx_encode, adfgvx_decode, r"^adfgvx" + PATTERN, aliases=["adfgvx-cipher"])
