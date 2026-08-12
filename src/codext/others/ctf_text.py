# -*- coding: UTF-8 -*-
"""Text-only CTF codecs for music symbols and decimal Unicode code points."""
import re

from ..__common__ import add, ensure_str


MUSIC = {
    "A": "♭♭§", "B": "♭♭∮", "C": "♭♭♪", "D": "♭♭♩", "E": "♭♭♫", "F": "♭♭♬", "G": "♭♭¶",
    "H": "♭♯‖", "I": "♭♯♭", "J": "♭♯♯", "K": "♭♯§", "L": "♭♯∮", "M": "♭♯♪", "N": "♭♯♩",
    "O": "♭♯♫", "P": "‖¶♩", "Q": "‖¶♫", "R": "‖¶♬", "S": "‖¶¶", "T": "♭‖‖", "U": "♭‖♭",
    "V": "♭‖♯", "W": "♭‖§", "X": "♭‖∮", "Y": "♭‖♪", "Z": "♭‖♩", "a": "‖♬♭", "b": "‖♬♯",
    "c": "‖♬§", "d": "‖♬∮", "e": "‖♬♪", "f": "‖♬♩", "g": "‖♬♫", "h": "‖♬♬", "i": "‖♬¶",
    "j": "‖¶‖", "k": "‖¶♭", "l": "‖¶♯", "m": "‖¶§", "n": "‖¶∮", "o": "‖¶♪", "p": "‖♩∮",
    "q": "‖♩♪", "r": "‖♩♩", "s": "‖♩♫", "t": "‖♩♬", "u": "‖♩¶", "v": "‖♫‖", "w": "‖♫♭",
    "x": "‖♫♯", "y": "‖♫§", "z": "‖♫∮", "0": "‖‖‖", "1": "‖‖♭", "2": "‖‖♯", "3": "‖‖§",
    "4": "‖‖∮", "5": "‖‖♪", "6": "‖‖♩", "7": "‖‖♫", "8": "‖‖♬", "9": "‖‖¶", "~": "‖♫♬",
    "!": "‖♭♫", "@": "♭♭♯", "#": "‖♭¶", "$": "‖♯‖", "%": "‖♯♭", "^": "♭♭‖", "&": "‖♯♯",
    "*": "‖♯♩", "(": "‖♯∮", ")": "‖♯♪", "_": "♭♭♭", "+": "‖♯♫", "`": "‖♬‖", "-": "‖♯¶",
    "=": "‖♭§", "[": "♭‖♫", "]": "♭‖¶", "\\": "♭‖♬", "{": "‖♫♪", "}": "‖♫♫", "|": "‖♫♩",
    ";": "‖♭♭", "'": "‖♯§", ":": "‖♭‖", '"': "‖♭♬", ",": "‖♯♬", ".": "‖§‖", "/": "‖§♭",
    "<": "‖♭♯", ">": "‖♭∮", "?": "‖♭♪", " ": "‖♭♩", "\n": "‖♪♬",
}
MUSIC_REVERSE = {value: key for key, value in MUSIC.items()}


def music_symbol_encode(text, errors="strict"):
    source = ensure_str(text)
    try:
        result = "".join(MUSIC[char] for char in source) + "§="
    except KeyError as error:
        raise ValueError("music-symbol supports printable ASCII, space and newline") from error
    return result, len(source)


def music_symbol_decode(text, errors="strict"):
    source = re.sub(r"\s+", "", ensure_str(text))
    source = source[:-2] if source.endswith("§=") else source[:-1] if source.endswith("§") else source
    if len(source) % 3:
        raise ValueError("music-symbol payload must contain three-symbol groups and an optional §= terminator")
    try:
        result = "".join(MUSIC_REVERSE[source[index:index + 3]] for index in range(0, len(source), 3))
    except KeyError as error:
        raise ValueError("unknown music-symbol group %s" % error.args[0]) from error
    return result, len(ensure_str(text))


def chinese_ascii_encode(text, errors="strict"):
    source = ensure_str(text)
    result = " ".join(str(ord(char)) for char in source)
    return result, len(source)


def chinese_ascii_decode(text, errors="strict"):
    source = ensure_str(text).strip()
    if "&#" in source:
        matches = re.findall(r"&#(?:(?:x|X)([0-9a-fA-F]+)|([0-9]+));?", source)
        values = [int(hexa, 16) if hexa else int(decimal) for hexa, decimal in matches]
    else:
        if not re.fullmatch(r"[0-9\s,;]+", source):
            raise ValueError("Chinese ASCII requires decimal Unicode code points")
        values = [int(value) for value in re.findall(r"[0-9]+", source)]
    if not values or any(not 0 <= value <= 0x10ffff or 0xd800 <= value <= 0xdfff for value in values):
        raise ValueError("invalid Unicode code point")
    result = "".join(chr(value) for value in values)
    return result, len(source)


add("music_symbol", music_symbol_encode, music_symbol_decode,
    r"^(?:music[-_]symbol|music[-_]cipher|yinyue)$", aliases=["music-symbol"])
add("chinese_ascii", chinese_ascii_encode, chinese_ascii_decode,
    r"^(?:chinese[-_]?ascii|unicode[-_]decimal)$", aliases=["chinese-ascii", "unicode-decimal"])
