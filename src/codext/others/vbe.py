# -*- coding: UTF-8 -*-
"""Microsoft Script Encoder VBE encoder and decoder."""
import base64
import re
import struct

from ..__common__ import add, ensure_str


DECODE_TABLE = 'Wn{JLA\x0b\x0b\x0b\x0c\x0c\x0cJLA\x0e\x0e\x0e\x0f\x0f\x0f\x10\x10\x10\x11\x11\x11\x12\x12\x12\x13\x13\x13\x14\x14\x14\x15\x15\x15\x16\x16\x16\x17\x17\x17\x18\x18\x18\x19\x19\x19\x1a\x1a\x1a\x1b\x1b\x1b\x1c\x1c\x1c\x1d\x1d\x1d\x1e\x1e\x1e\x1f\x1f\x1f.-2Gu0zR!V`)Bq[j^8/I3&\\=IbXA}:4)526e[ 9v|\\rzVC\x7fs8kf9cNp3EE+khhbqQYOfx\tv^b1}DdJ#TmuCqJLA~:`JLA^~S@L@wEBJ,\'a*H]tr"\'uK71oD7NyM;YRL/"PoTg&j*rG}jdt9-T{ +?\x7f-8.,wL0g]nS~kGlf4o5xy%]t!0Cd#&MZvR[%cl$?H+{U(xp#)iA(.4sL\tY!*3$D\x7fN?mPwU\t;SVU|si:5a_aceKPFXgX;Q1WIi"OlmFZMhH%|\'(6\\Fp=Jn$2zyA/7=_`_KQOZ B,6eW'
COMBINATION = tuple(map(int, '0120121221210212021200122102122100212120200120210212001220012021'))


def decode_vbe_payload(data):
    result, index = [], -1
    source = data.replace("@&", "\n").replace("@#", "\r").replace("@*", ">").replace("@!", "<").replace("@$", "@")
    for char in source:
        value = ord(char)
        if value < 128:
            index += 1
        if (value == 9 or 31 < value < 128) and value not in (60, 62, 64):
            char = DECODE_TABLE[(value - 9) * 3 + COMBINATION[index % 64]]
        result.append(char)
    return "".join(result)


def encode_vbe_payload(data):
    result = []
    reverse = [{DECODE_TABLE[(value - 9) * 3 + combination]: chr(value)
                for value in range(9, 128) if value not in (60, 62, 64)} for combination in range(3)]
    escapes = {"\n": "@&", "\r": "@#", ">": "@*", "<": "@!", "@": "@$"}
    for index, char in enumerate(data):
        value = ord(char)
        if char in escapes:
            result.append(escapes[char])
            continue
        if (value == 9 or 31 < value < 128) and char in reverse[COMBINATION[index % 64]]:
            result.append(reverse[COMBINATION[index % 64]][char])
            continue
        result.append(char)
    return "".join(result)


def vbe_encode(text, errors="strict"):
    source = ensure_str(text)
    payload = encode_vbe_payload(source)
    length = base64.b64encode(struct.pack("<I", len(payload))).decode()
    checksum = base64.b64encode(struct.pack("<I", sum(map(ord, source)) & 0xffffffff)).decode()
    result = "#@~^" + length + payload + checksum + "^#~@"
    return result, len(source)


def vbe_decode(text, errors="strict"):
    source = ensure_str(text)
    matches = re.findall(r"#@~\^......==(.+?)......==\^#~@", source, re.DOTALL)
    if not matches:
        raise ValueError("no VBE encoded block found")
    result = "".join(decode_vbe_payload(match) for match in matches)
    return result, len(source)


add("vbe", vbe_encode, vbe_decode, r"^(?:vbe|vbs[-_]encoded|script[-_]encoder)$")
