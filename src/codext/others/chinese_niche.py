# -*- coding: UTF-8 -*-
"""Chinese CTF encodings based on pinyin tones, pawnshop marks and strokes."""
from ..__common__ import add, ensure_str


PAWNSHOP = {"0": "口", "1": "由", "2": "中", "3": "人", "4": "工", "5": "大", "6": "王", "7": "夫", "8": "井", "9": "羊"}
STROKES = {"乙": 1, "丁": 2, "万": 3, "王": 4, "史": 5, "吕": 6, "李": 7, "周": 8, "赵": 9,
           "秦": 10, "许": 11, "温": 12}


def pinyin_tone_decode(text, errors="strict"):
    import pypinyin
    from pypinyin import lazy_pinyin, pinyin

    result = []
    for char in ensure_str(text):
        plain = lazy_pinyin(char)[0]
        toned = pinyin(char, style=pypinyin.Style.TONE3, heteronym=True)[0][0]
        result.append(chr((sum(map(ord, plain)) + ord(toned[-1])) % 128))
    return "".join(result), len(ensure_str(text))


def pawnshop_encode(text, errors="strict"):
    source = ensure_str(text)
    result = "".join(PAWNSHOP.get(char, char) for char in source)
    return result, len(source)


def pawnshop_decode(text, errors="strict"):
    reverse = {value: key for key, value in PAWNSHOP.items()}
    source = ensure_str(text)
    result = "".join(reverse.get(char, char) for char in source)
    return result, len(source)


def chinese_strokes_encode(text, errors="strict"):
    values = {str(value): char for char, value in STROKES.items()}
    source = ensure_str(text)
    tokens = []
    for char in source:
        decimal, encoded = str(ord(char)), ""
        while decimal:
            value = next((candidate for candidate in ("12", "11", "10") if decimal.startswith(candidate)),
                         decimal[0])
            if value not in values:
                raise ValueError("character code cannot be represented by the 1-12 stroke table")
            encoded += values[value]
            decimal = decimal[len(value):]
        tokens.append(encoded)
    result = " ".join(tokens)
    return result, len(source)


def chinese_strokes_decode(text, errors="strict"):
    result = "".join(chr(int("".join(str(STROKES[char]) for char in token)))
                     for token in ensure_str(text).split())
    return result, len(ensure_str(text))


add("pinyin_tone", None, pinyin_tone_decode, r"^(?:pinyin[-_]?tone|chinese[-_]?pinyin)$")
add("pawnshop", pawnshop_encode, pawnshop_decode, r"^(?:pawnshop|dangpu)(?:[-_]?cipher)?$")
add("chinese_strokes", chinese_strokes_encode, chinese_strokes_decode,
    r"^(?:chinese[-_])?(?:stroke|strokes|bihua)$")
