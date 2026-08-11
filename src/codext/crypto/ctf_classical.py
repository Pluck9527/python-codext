# -*- coding: UTF-8 -*-
"""Classical ciphers commonly seen in CTF tasks."""
from string import ascii_lowercase, ascii_uppercase

from ..__common__ import *


def _shift_factory(name, key, decode=False):
    shifts = [int(char) for char in str(key or "31415")]
    if not shifts:
        raise LookupError("Bad parameter for encoding '%s': key is required" % name)

    def code(text, errors="strict"):
        result, cursor = [], 0
        for char in ensure_str(text):
            if char in ascii_lowercase or char in ascii_uppercase:
                alphabet = ascii_lowercase if char in ascii_lowercase else ascii_uppercase
                shift = shifts[cursor % len(shifts)] * (-1 if decode else 1)
                result.append(alphabet[(alphabet.index(char) + shift) % 26])
                cursor += 1
            else:
                result.append(char)
        return (output := "".join(result)), len(output)
    return code


def gronsfeld_encode(key=""):
    return _shift_factory("gronsfeld", key)


def gronsfeld_decode(key=""):
    return _shift_factory("gronsfeld", key, True)


def _hill_factory(key, decode=False):
    values = [int(value) for value in (key or "3,3,2,5").split(",")]
    if len(values) != 4:
        raise LookupError("Bad parameter for encoding 'hill': a 2x2 key needs four integers")
    a, b_, c, d = values
    determinant = (a * d - b_ * c) % 26
    try:
        inverse = pow(determinant, -1, 26)
    except ValueError as error:
        raise LookupError("Bad parameter for encoding 'hill': matrix is not invertible modulo 26") from error
    if decode:
        a, b_, c, d = d * inverse, -b_ * inverse, -c * inverse, a * inverse

    def code(text, errors="strict"):
        letters = [char for char in ensure_str(text).upper() if char in ascii_uppercase]
        if len(letters) % 2:
            letters.append("X")
        result = []
        for index in range(0, len(letters), 2):
            x, y = ord(letters[index]) - 65, ord(letters[index + 1]) - 65
            result.extend((chr((a * x + b_ * y) % 26 + 65), chr((c * x + d * y) % 26 + 65)))
        return (output := "".join(result)), len(output)
    return code


def hill_encode(key=""):
    return _hill_factory(key)


def hill_decode(key=""):
    return _hill_factory(key, True)


def cloud_shadow_encode(text, errors="strict"):
    result, error = [], handle_error("cloud_shadow", errors)
    for index, char in enumerate(ensure_str(text).upper()):
        if char not in ascii_uppercase:
            replacement = error(char, index)
            if replacement:
                result.append(replacement)
            continue
        value, token = ord(char) - 64, ""
        for weight in (8, 4, 2, 1):
            while value >= weight:
                token += str(weight)
                value -= weight
        result.append(token)
    return (output := "0".join(result)), len(output)


def cloud_shadow_decode(text, errors="strict"):
    result, error = [], handle_error("cloud_shadow", errors, decode=True, kind="token")
    for index, token in enumerate(ensure_str(text).split("0")):
        if not token:
            continue
        if any(char not in "1248" for char in token) or not 1 <= sum(map(int, token)) <= 26:
            replacement = error(token, index)
            if replacement:
                result.append(replacement)
            continue
        result.append(chr(sum(map(int, token)) + 64))
    return (output := "".join(result)), len(output)


add("gronsfeld", gronsfeld_encode, gronsfeld_decode, r"^gronsfeld(?:[-_]cipher)?(?:[-_]([0-9]+))?$")
add("hill", hill_encode, hill_decode, r"^hill(?:[-_]cipher)?(?:[-_]([0-9-]+(?:,[0-9-]+){3}))?$")
add("cloud_shadow", cloud_shadow_encode, cloud_shadow_decode, r"^(?:cloud[-_]?shadow|yunying)$",
    aliases=["cloud-shadow", "yunying"])
