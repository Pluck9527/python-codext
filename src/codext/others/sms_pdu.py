# -*- coding: UTF-8 -*-
"""SMS PDU encoder/decoder for common SMS-SUBMIT and SMS-DELIVER CTF data."""
import re

from ..__common__ import add, ensure_str


GSM7 = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./"
    "0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿"
    "abcdefghijklmnopqrstuvwxyzäöñüà"
)
GSM7_EXT = {10: "\f", 20: "^", 40: "{", 41: "}", 47: "\\", 60: "[", 61: "~", 62: "]", 64: "|", 101: "€"}


def _semi_octets(number):
    digits = number.lstrip("+")
    padded = digits + "F" if len(digits) % 2 else digits
    return "".join(padded[index + 1] + padded[index] for index in range(0, len(padded), 2))


def _read_address(data, offset, digits):
    size = (digits + 1) // 2
    raw = data[offset:offset + size]
    value = "".join("%02X" % byte for byte in raw)
    number = "".join(value[index + 1] + value[index] for index in range(0, len(value), 2)).rstrip("F")[:digits]
    return number, offset + size


def _unpack_gsm7(data, septets):
    values = [((int.from_bytes(data, "little") >> (index * 7)) & 0x7f) for index in range(septets)]
    output, escaped = [], False
    for value in values:
        if escaped:
            output.append(GSM7_EXT.get(value, "?"))
            escaped = False
            continue
        if value == 27:
            escaped = True
            continue
        output.append(GSM7[value])
    return "".join(output)


def sms_pdu_encode(destination=""):
    destination = str(destination or "10086")
    def encode(text, errors="strict"):
        value = ensure_str(text).encode("utf-16-be")
        number = destination.lstrip("+")
        if not number.isdigit():
            raise ValueError("SMS PDU destination must contain decimal digits")
        result = "00" + "01" + "00" + "%02X" % len(number) + ("91" if destination.startswith("+") else "81")
        result += _semi_octets(destination) + "00" + "08" + "%02X" % len(value) + value.hex().upper()
        return result, len(ensure_str(text))
    return encode


def sms_pdu_decode(text, errors="strict"):
    value = re.sub(r"\s+", "", ensure_str(text))
    if len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", value):
        raise ValueError("SMS PDU must be an even-length hexadecimal string")
    data, offset = bytes.fromhex(value), 0
    smsc_length = data[offset]
    offset += 1 + smsc_length
    first = data[offset]
    offset += 1
    mti = first & 3
    if mti == 1:
        offset += 1
        digits = data[offset]
        offset += 2
        _, offset = _read_address(data, offset, digits)
        dcs = data[offset + 1]
        offset += 2
        if (first >> 3) & 3 == 2:
            offset += 1
        if (first >> 3) & 3 in (1, 3):
            offset += 7
    elif mti == 0:
        digits = data[offset]
        offset += 2
        _, offset = _read_address(data, offset, digits)
        dcs = data[offset + 1]
        offset += 2
        offset += 7
    else:
        raise ValueError("only SMS-SUBMIT and SMS-DELIVER PDUs are supported")
    user_length = data[offset]
    offset += 1
    payload = data[offset:]
    if dcs & 0x0c == 0x08:
        result = payload[:user_length].decode("utf-16-be", errors)
    elif dcs & 0x0c == 0x04:
        result = payload[:user_length].decode("latin-1", errors)
    else:
        result = _unpack_gsm7(payload, user_length)
    return result, len(value)


def sms_pdu_decode_factory(destination=""):
    return sms_pdu_decode


add("sms_pdu", sms_pdu_encode, sms_pdu_decode_factory,
    r"^(?:sms[-_]?pdu|pdu[-_]?sms)(?:[-_]([0-9]+))?$", aliases=["sms-pdu"])
