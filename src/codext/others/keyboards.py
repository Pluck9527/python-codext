# -*- coding: UTF-8 -*-
"""Physical keyboard coordinates, phone multi-tap and layout conversions."""
from ..__common__ import add, ensure_str


PC_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
LAYOUTS = {
    "qwerty": ("qwertyuiop", "asdfghjkl", "zxcvbnm"),
    "qwertz": ("qwertzuiop", "asdfghjkl", "yxcvbnm"),
    "azerty": ("azertyuiop", "qsdfghjklm", "wxcvbn"),
    "dvorak": ("',.pyfgcrl", "aoeuidhtns", ";qjkxbmwvz"),
    "colemak": ("qwfpgjluy;", "arstdhneio", "zxcvbkm,./"),
}
T9 = {"2": "abc", "3": "def", "4": "ghi", "5": "jkl", "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz"}


def keyboard_coordinates_encode(text, errors="strict"):
    positions = {char: "%d%d" % (row + 1, column + 1) for row, value in enumerate(PC_ROWS)
                 for column, char in enumerate(value)}
    source = ensure_str(text)
    result = " ".join(positions.get(char.lower(), char) for char in source if not char.isspace())
    return result, len(source)


def keyboard_coordinates_decode(text, errors="strict"):
    positions = {"%d%d" % (row + 1, column + 1): char for row, value in enumerate(PC_ROWS)
                 for column, char in enumerate(value)}
    tokens = ensure_str(text).split()
    result = "".join(positions.get(token, token) for token in tokens)
    return result, len(ensure_str(text))


def _t9_factory(reverse=False, decode=False):
    groups = {number: letters[::-1] if reverse else letters for number, letters in T9.items()}
    by_letter = {letter: number * (index + 1) for number, letters in groups.items()
                 for index, letter in enumerate(letters)}

    def code(text, errors="strict"):
        source = ensure_str(text).lower()
        if decode:
            result = "".join(groups[token[0]][len(token) - 1] for token in source.split())
            return result, len(source)
        result = " ".join(by_letter[char] for char in source if char in by_letter)
        return result, len(source)
    return code


def _layout_factory(target, decode=False):
    pairs = [(left, right) for qwerty, other in zip(LAYOUTS["qwerty"], LAYOUTS[target])
             for left, right in zip(qwerty, other)]
    source, destination = zip(*((right, left) if decode else (left, right) for left, right in pairs))
    table = str.maketrans(dict(zip("".join(source) + "".join(source).upper(),
                                   "".join(destination) + "".join(destination).upper())))

    def code(text, errors="strict"):
        result = ensure_str(text).translate(table)
        return result, len(result)
    return code


def _register_layout(name):
    add("keyboard_" + name, _layout_factory(name), _layout_factory(name, True),
        r"^(?:keyboard[-_])?(?:qwerty[-_](?:to[-_])?)?" + name + r"$", aliases=["qwerty-to-" + name])


add("keyboard_coordinates", keyboard_coordinates_encode, keyboard_coordinates_decode,
    r"^(?:keyboard[-_](?:coordinates?|xy)|qwerty[-_]coordinates?)$")
add("phone_t9", _t9_factory(), _t9_factory(decode=True), r"^phone[-_](?:t9|multi[-_]?tap)$")
add("phone_t9_reverse", _t9_factory(True), _t9_factory(True, True), r"^phone[-_]t9[-_](?:reverse|ctf)$")
[_register_layout(name) for name in ("qwertz", "azerty", "dvorak", "colemak")]
