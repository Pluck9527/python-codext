# -*- coding: UTF-8 -*-
"""Chinese socialist core values encoding used in CTF tasks."""
from ..__common__ import *


VALUES = ["富强", "民主", "文明", "和谐", "自由", "平等", "公正", "法治", "爱国", "敬业", "诚信", "友善"]


def core_values_encode(text, errors="strict"):
    result = []
    for char in b(text).hex().upper():
        value = int(char, 16)
        result.extend((VALUES[value],) if value < 10 else (VALUES[10], VALUES[value - 10]))
    return (output := "".join(result)), len(output)


def core_values_decode(text, errors="strict"):
    text, numbers, index = ensure_str(text), [], 0
    while index < len(text):
        token = text[index:index + 2]
        try:
            numbers.append(VALUES.index(token))
        except ValueError:
            raise CoreValuesDecodeError("unknown core-value token at position %d" % index)
        index += 2
    raw, index = "", 0
    while index < len(numbers):
        if numbers[index] < 10:
            raw += format(numbers[index], "X")
            index += 1
        elif numbers[index] == 10 and index + 1 < len(numbers) and numbers[index + 1] < 6:
            raw += format(numbers[index + 1] + 10, "X")
            index += 2
        else:
            raise CoreValuesDecodeError("invalid core-values sequence")
    if len(raw) % 2:
        raise CoreValuesDecodeError("decoded hexadecimal length is odd")
    return bytes.fromhex(raw), len(text)


add("core_values", core_values_encode, core_values_decode,
    r"^(?:core[-_]?values|socialist[-_]?core[-_]?values)$", aliases=["core-values"])
