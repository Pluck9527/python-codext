# -*- coding: UTF-8 -*-
"""Tap code - Tap/knock code encoding.

This codec:
- en/decodes strings from str to str
- en/decodes strings from bytes to bytes
- decodes file content to str (read)
- encodes file content from str to bytes (write)
"""
from ..__common__ import *


__examples__ = {
    'enc(tap|knock-code|tap_code)': {'this is a test' : ".... ....⠀.. ...⠀.. ....⠀.... ...⠀ ⠀.. ....⠀.... ...⠀ ⠀. ."
                                                        "⠀ ⠀.... ....⠀. .....⠀.... ...⠀.... ...."},
}
__guess__ = ["tap", "tap-inv"]


def __build_encmap(a):
    d, i = {}, 0
    for x in range(1,6): 
        for y in range(1,6): 
            d[a[i]] = x * "." + " " + y * "."
            i += 1
    d['k'], d[' '] = d['c'], " "
    return d



ENCMAP = {
    '':    __build_encmap("abcdefghijlmnopqrstuvwxyz"),
    'inv': __build_encmap("abcdefghijlmnopqrstuvwxyz"[::-1]),
}


def tap_numeric_encode(text, errors="strict"):
    alphabet = "abcdefghijlmnopqrstuvwxyz"
    mapping = {char: "%d,%d" % (index // 5 + 1, index % 5 + 1) for index, char in enumerate(alphabet)}
    mapping["k"] = mapping["c"]
    source = ensure_str(text).lower()
    try:
        result = " ".join("/" if char == " " else mapping[char] for char in source)
    except KeyError as error:
        raise ValueError("tap-numeric supports letters and spaces") from error
    return result, len(source)


def tap_numeric_decode(text, errors="strict"):
    alphabet = "abcdefghijlmnopqrstuvwxyz"
    source, result = ensure_str(text), []
    for token in source.split():
        if token == "/":
            result.append(" ")
            continue
        match = re.fullmatch(r"([1-5])(?:[,.:/-]?)([1-5])", token)
        if not match:
            raise ValueError("tap-numeric token must be row,column with values from 1 through 5")
        result.append(alphabet[(int(match.group(1)) - 1) * 5 + int(match.group(2)) - 1])
    output = "".join(result)
    return output, len(source)


add_map("tap", ENCMAP, ignore_case="both", sep="⠀", pattern=r"^(?:tap|knock)(?:[-_]code)?(?:[-_](inv))?$")
add("tap_numeric", tap_numeric_encode, tap_numeric_decode,
    r"^(?:tap|knock)(?:[-_]code)?[-_](?:numeric|coordinates?)$", aliases=["tap-numeric"])

