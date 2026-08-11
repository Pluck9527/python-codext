# -*- coding: UTF-8 -*-
"""Chinese Telegraph Code codec backed by the fixed zhtelecode codebooks."""
from zhtelecode import to_telecode, to_unicode

from ..__common__ import *


def chinese_telegraph_encode(codebook=""):
    def encode(text, errors="strict"):
        result = " ".join(to_telecode(ensure_str(text), None if codebook == "auto" else codebook or "mainland"))
        return result, len(result)
    return encode


def chinese_telegraph_decode(codebook=""):
    def decode(text, errors="strict"):
        tokens = re.findall(r"\d{4}", ensure_str(text))
        result = to_unicode(tokens, None if codebook == "auto" else codebook or "mainland")
        return result, len(result)
    return decode


add("chinese_telegraph", chinese_telegraph_encode, chinese_telegraph_decode,
    r"^(?:chinese[-_]?(?:telegraph|commercial)[-_]?(?:code)?|zh[-_]?telecode)(?:[-_](auto|mainland|taiwan))?$",
    aliases=["chinese-telegraph", "zh-telecode"])
