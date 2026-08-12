# -*- coding: UTF-8 -*-
"""Physical keyboard coordinates, phone multi-tap and layout conversions."""
from string import ascii_lowercase

from ..__common__ import add, ensure_str


PC_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
LAYOUTS = {
    "qwerty": ("qwertyuiop", "asdfghjkl", "zxcvbnm"),
    "qwertz": ("qwertzuiop", "asdfghjkl", "yxcvbnm"),
    "azerty": ("azertyuiop", "qsdfghjklm", "wxcvbn"),
    "dvorak": ("',.pyfgcrl", "aoeuidhtns", ";qjkxbmwvz"),
    "colemak": ("qwfpgjluy;", "arstdhneio", "zxcvbkm,./"),
}
T9 = {"1": ":_-", "2": "abc", "3": "def", "4": "ghi", "5": "jkl", "6": "mno", "7": "pqrs",
      "8": "tuv", "9": "wxyz"}
KEYBOARD_SEQUENCE = "".join(PC_ROWS)
SHIFT_SYMBOLS = "!@#$%^&*()"
SYMBOL_COLUMNS = tuple("".join(row[index] for row in PC_ROWS if index < len(row)) for index in range(10))


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
            if any(token[0] not in groups or len(token) > len(groups[token[0]]) or len(set(token)) != 1
                   for token in source.split()):
                raise ValueError("invalid phone multi-tap token")
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


def _qwe_factory(decode=False):
    source, destination = (KEYBOARD_SEQUENCE, ascii_lowercase) if decode else (ascii_lowercase, KEYBOARD_SEQUENCE)
    table = str.maketrans(source + source.upper(), destination + destination.upper())

    def code(text, errors="strict"):
        result = ensure_str(text).translate(table)
        return result, len(result)
    return code


def keyboard_symbol_encode(text, errors="strict"):
    reverse = {char: SHIFT_SYMBOLS[column] * (depth + 1) for column, value in enumerate(SYMBOL_COLUMNS)
               for depth, char in enumerate(value)}
    source = ensure_str(text).lower()
    try:
        chunks = [char if char.isspace() else reverse[char] for char in source]
    except KeyError as error:
        raise ValueError("keyboard-symbol-shift supports QWERTY letters and whitespace") from error
    result = ""
    for chunk in chunks:
        if result and not result[-1].isspace() and not chunk[0].isspace() and result[-1] == chunk[0]:
            result += "·"
        result += chunk
    return result, len(source)


def keyboard_symbol_decode(text, errors="strict"):
    source, result, index = ensure_str(text), [], 0
    while index < len(source):
        if source[index] == "·":
            index += 1
            continue
        if source[index].isspace():
            result.append(source[index])
            index += 1
            continue
        if source[index] not in SHIFT_SYMBOLS:
            raise ValueError("keyboard-symbol-shift contains an unknown symbol")
        end = index + 1
        while end < len(source) and source[end] == source[index]:
            end += 1
        column, depth = SHIFT_SYMBOLS.index(source[index]), end - index
        if depth > len(SYMBOL_COLUMNS[column]):
            raise ValueError("keyboard-symbol-shift moves below the keyboard")
        result.append(SYMBOL_COLUMNS[column][depth - 1])
        index = end
    output = "".join(result)
    return output, len(source)


def phone_coordinate_encode(text, errors="strict"):
    reverse = {char: number + str(index + 1) for number, chars in T9.items()
               for index, char in enumerate(chars)}
    source = ensure_str(text).lower()
    try:
        result = " ".join(reverse[char] for char in source if not char.isspace())
    except KeyError as error:
        raise ValueError("phone-t9-coordinate supports T9 letters and punctuation") from error
    return result, len(source)


def phone_coordinate_decode(text, errors="strict"):
    source, result = ensure_str(text), []
    for token in source.split():
        if len(token) != 2 or token[0] not in T9 or not token[1].isdigit() or not 1 <= int(token[1]) <= len(T9[token[0]]):
            raise ValueError("phone-t9-coordinate requires key/index pairs")
        result.append(T9[token[0]][int(token[1]) - 1])
    output = "".join(result)
    return output, len(source)


def phone_26_encode(text, errors="strict"):
    source = ensure_str(text)
    digits = _t9_factory()(source)[0]
    result = digits.translate(str.maketrans("1234567890", PC_ROWS[0]))
    return result, len(source)


def phone_26_decode(text, errors="strict"):
    source = ensure_str(text).lower()
    digits = source.translate(str.maketrans(KEYBOARD_SEQUENCE, "1234567890" + "123456789" + "1234567"))
    result = _t9_factory(decode=True)(digits)[0]
    return result, len(source)


add("keyboard_coordinates", keyboard_coordinates_encode, keyboard_coordinates_decode,
    r"^(?:keyboard[-_](?:coordinates?|xy)|qwerty[-_]coordinates?)$")
add("phone_t9", _t9_factory(), _t9_factory(decode=True), r"^phone[-_](?:t9|multi[-_]?tap)$")
add("phone_t9_reverse", _t9_factory(True), _t9_factory(True, True), r"^phone[-_]t9[-_](?:reverse|ctf)$")
add("phone_t9_coordinate", phone_coordinate_encode, phone_coordinate_decode,
    r"^phone[-_](?:t9[-_])?(?:coordinate|coordinates|key[-_]?index)$", aliases=["phone-t9-coordinate"])
add("phone_26", phone_26_encode, phone_26_decode, r"^phone[-_](?:26|qwerty|keyboard26)$", aliases=["phone-26"])
[_register_layout(name) for name in ("qwertz", "azerty", "dvorak", "colemak")]
add("keyboard_direction", keyboard_direction_encode, keyboard_direction_decode,
    r"^keyboard[-_](?:shift[-_])?(left|right|up|down|up[-_]left|up[-_]right|down[-_]left|down[-_]right)"
    r"(?:[-_](wrap))?$", aliases=["keyboard-shift-right"])
add("keyboard_qwe", _qwe_factory(), _qwe_factory(True), r"^keyboard[-_]qwe$", aliases=["keyboard-qwe"])
add("keyboard_symbol_shift", keyboard_symbol_encode, keyboard_symbol_decode,
    r"^keyboard[-_](?:symbol[-_](?:shift|vertical)|vertical[-_]symbols?)$", aliases=["keyboard-symbol-shift"])
