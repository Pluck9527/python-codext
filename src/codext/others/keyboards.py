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


def _direction_factory(direction="", wrapping="", decode=False):
    vectors = {"left": (0, -1), "right": (0, 1), "up": (-1, 0), "down": (1, 0),
               "up-left": (-1, -1), "up-right": (-1, 1), "down-left": (1, -1), "down-right": (1, 1)}
    row_delta, column_delta = vectors[(direction or "right").replace("_", "-")]
    if decode:
        row_delta, column_delta = -row_delta, -column_delta

    def code(text, errors="strict"):
        output = []
        for char in ensure_str(text):
            position = next(((row, value.index(char.lower())) for row, value in enumerate(PC_ROWS)
                             if char.lower() in value), None)
            if position is None:
                output.append(char)
                continue
            row = position[0] + row_delta
            if wrapping:
                row %= len(PC_ROWS)
            if not 0 <= row < len(PC_ROWS):
                output.append(char)
                continue
            ratio = position[1] / max(1, len(PC_ROWS[position[0]]) - 1)
            column = round(ratio * (len(PC_ROWS[row]) - 1)) + column_delta
            if wrapping:
                column %= len(PC_ROWS[row])
            if not 0 <= column < len(PC_ROWS[row]):
                output.append(char)
                continue
            translated = PC_ROWS[row][column]
            output.append(translated.upper() if char.isupper() else translated)
        result = "".join(output)
        return result, len(result)
    return code


def keyboard_direction_encode(direction="", wrapping=""):
    return _direction_factory(direction, wrapping)


def keyboard_direction_decode(direction="", wrapping=""):
    return _direction_factory(direction, wrapping, True)


add("keyboard_coordinates", keyboard_coordinates_encode, keyboard_coordinates_decode,
    r"^(?:keyboard[-_](?:coordinates?|xy)|qwerty[-_]coordinates?)$")
add("phone_t9", _t9_factory(), _t9_factory(decode=True), r"^phone[-_](?:t9|multi[-_]?tap)$")
add("phone_t9_reverse", _t9_factory(True), _t9_factory(True, True), r"^phone[-_]t9[-_](?:reverse|ctf)$")
[_register_layout(name) for name in ("qwertz", "azerty", "dvorak", "colemak")]
add("keyboard_direction", keyboard_direction_encode, keyboard_direction_decode,
    r"^keyboard[-_](?:shift[-_])?(left|right|up|down|up[-_]left|up[-_]right|down[-_]left|down[-_]right)"
    r"(?:[-_](wrap))?$", aliases=["keyboard-shift-right"])
