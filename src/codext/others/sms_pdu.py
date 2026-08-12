# -*- coding: UTF-8 -*-
"""SMS PDU codecs with GSM-7, 8-bit, UCS-2, ports, UDH multipart and status reports."""
import json
import re

from ..__common__ import add, ensure_str


GSM7 = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./"
    "0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿"
    "abcdefghijklmnopqrstuvwxyzäöñüà"
)
GSM7_EXT = {10: "\f", 20: "^", 40: "{", 41: "}", 47: "\\", 60: "[", 61: "~", 62: "]", 64: "|", 101: "€"}
GSM7_EXT_REVERSE = {value: key for key, value in GSM7_EXT.items()}


def _semi_octets(number):
    digits = number.lstrip("+")
    padded = digits + "F" if len(digits) % 2 else digits
    return "".join(padded[index + 1] + padded[index] for index in range(0, len(padded), 2))


def _read_numeric_address(data, offset, digits):
    size = (digits + 1) // 2
    value = data[offset:offset + size].hex().upper()
    number = "".join(value[index + 1] + value[index] for index in range(0, len(value), 2)).rstrip("F")[:digits]
    return number, offset + size


def _gsm7_values(text):
    values = []
    for char in text:
        if char in GSM7_EXT_REVERSE:
            values.extend((27, GSM7_EXT_REVERSE[char]))
            continue
        if char not in GSM7 or char == "\x1b":
            raise ValueError("character %r is not representable in GSM-7" % char)
        values.append(GSM7.index(char))
    return values


def _decode_gsm7(values):
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


def _pack_gsm7(values, header=b""):
    header_septets = (len(header) * 8 + 6) // 7
    packed = int.from_bytes(header, "little")
    for index, value in enumerate(values):
        packed |= value << ((header_septets + index) * 7)
    size = (header_septets + len(values)) * 7
    return packed.to_bytes((size + 7) // 8, "little"), header_septets


def _unpack_gsm7(data, septets, skip=0):
    packed = int.from_bytes(data, "little")
    return _decode_gsm7([(packed >> ((skip + index) * 7)) & 0x7f for index in range(septets)])


def _udh_metadata(header):
    offset, result = 1, {}
    while offset + 1 < len(header):
        identifier, size = header[offset], header[offset + 1]
        value = header[offset + 2:offset + 2 + size]
        offset += 2 + size
        if identifier == 0 and size == 3:
            result.update(reference=value[0], total=value[1], part=value[2])
        if identifier == 8 and size == 4:
            result.update(reference=int.from_bytes(value[:2], "big"), total=value[2], part=value[3])
        if identifier == 4 and size == 2:
            result.update(destination_port=value[0], source_port=value[1])
        if identifier == 5 and size == 4:
            result.update(destination_port=int.from_bytes(value[:2], "big"),
                          source_port=int.from_bytes(value[2:], "big"))
        if identifier == 0x24 and size == 1:
            result["national_single_shift"] = value[0]
        if identifier == 0x25 and size == 1:
            result["national_locking_shift"] = value[0]
    return result


def _parse_pdu(text, errors="strict"):
    value = re.sub(r"\s+", "", ensure_str(text))
    if len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", value):
        raise ValueError("SMS PDU must be an even-length hexadecimal string")
    data, offset = bytes.fromhex(value), 0
    smsc_length = data[offset]
    offset += 1 + smsc_length
    first = data[offset]
    offset += 1
    mti = first & 3
    address = ""
    if mti == 1:
        offset += 1
        length, toa = data[offset], data[offset + 1]
        offset += 2
        address, offset = _read_numeric_address(data, offset, length)
        address = ("+" if toa & 0x90 == 0x90 else "") + address
        pid, dcs = data[offset], data[offset + 1]
        offset += 2
        validity = (first >> 3) & 3
        offset += 1 if validity == 2 else 7 if validity in (1, 3) else 0
    elif mti == 0:
        length, toa = data[offset], data[offset + 1]
        offset += 2
        if toa & 0x70 == 0x50:
            size = (length + 1) // 2
            raw = data[offset:offset + size]
            address = _unpack_gsm7(raw, length * 4 // 7)
            offset += size
        else:
            address, offset = _read_numeric_address(data, offset, length)
            address = ("+" if toa & 0x90 == 0x90 else "") + address
        pid, dcs = data[offset], data[offset + 1]
        offset += 2
        offset += 7
    elif mti == 2:
        reference = data[offset]
        offset += 1
        length, toa = data[offset], data[offset + 1]
        offset += 2
        address, offset = _read_numeric_address(data, offset, length)
        address = ("+" if toa & 0x90 == 0x90 else "") + address
        submitted, discharged, status = data[offset:offset + 7], data[offset + 7:offset + 14], data[offset + 14]
        return {"text": "", "address": address, "mti": mti, "reference": reference, "status": status,
                "submitted_at": submitted.hex().upper(), "discharged_at": discharged.hex().upper()}
    else:
        raise ValueError("only SMS-SUBMIT, SMS-DELIVER and SMS-STATUS-REPORT PDUs are supported")
    user_length, payload = data[offset], data[offset + 1:]
    header, multipart = b"", {}
    if first & 0x40:
        header = payload[:payload[0] + 1]
        multipart = _udh_metadata(header)
    if dcs & 0x0c == 0x08:
        result = payload[len(header):user_length].decode("utf-16-be", errors)
    elif dcs & 0x0c == 0x04:
        result = payload[len(header):user_length].decode("latin-1", errors)
    else:
        skipped = (len(header) * 8 + 6) // 7
        result = _unpack_gsm7(payload, user_length - skipped, skipped)
    return {"text": result, "address": address, "pid": pid, "dcs": dcs, "mti": mti, **multipart}


def _chunks(text, alphabet, limit):
    chunks, current, used = [], "", 0
    for char in text:
        width = len(_gsm7_values(char)) if alphabet == "gsm7" else len(char.encode("latin-1")) if alphabet == "8bit" \
            else len(char.encode("utf-16-be")) // 2
        if current and used + width > limit:
            chunks.append(current)
            current, used = "", 0
        current += char
        used += width
    if current or not chunks:
        chunks.append(current)
    return chunks


def sms_pdu_encode(alphabet="", destination="", reference_bits=8, source_port=None, destination_port=None):
    destination = str(destination or "10086")
    alphabet = str(alphabet or "ucs2").lower()

    def encode(text, errors="strict"):
        message = ensure_str(text)
        number = destination.lstrip("+")
        if not number.isdigit():
            raise ValueError("SMS PDU destination must contain decimal digits")
        if alphabet not in ("gsm7", "8bit", "ucs2"):
            raise ValueError("SMS PDU alphabet must be gsm7, 8bit or ucs2")
        single_limit, multipart_limit = ((160, 153) if alphabet == "gsm7" else
                                         (140, 134) if alphabet == "8bit" else (70, 67))
        port_ie = (b"\x05\x04" + int(destination_port).to_bytes(2, "big") + int(source_port or 0).to_bytes(2, "big")
                   if destination_port is not None else b"")
        if port_ie:
            overhead = len(port_ie) + 1
            single_limit = (140 - overhead) * 8 // 7 if alphabet == "gsm7" else \
                140 - overhead if alphabet == "8bit" else (140 - overhead) // 2
        chunks = _chunks(message, alphabet, single_limit)
        if len(chunks) == 1:
            chunks = _chunks(message, alphabet, single_limit)
        else:
            concat_size = 7 if int(reference_bits) == 16 else 6
            overhead = concat_size + len(port_ie)
            multipart_limit = (140 - overhead) * 8 // 7 if alphabet == "gsm7" else \
                140 - overhead if alphabet == "8bit" else (140 - overhead) // 2
            chunks = _chunks(message, alphabet, multipart_limit)
        reference = sum(message.encode("utf-8")) & (0xffff if int(reference_bits) == 16 else 0xff)
        result = []
        for part, chunk in enumerate(chunks, 1):
            concat = (b"\x08\x04" + reference.to_bytes(2, "big") + bytes((len(chunks), part)) if
                      len(chunks) > 1 and int(reference_bits) == 16 else
                      bytes((0, 3, reference, len(chunks), part)) if len(chunks) > 1 else b"")
            elements = concat + port_ie
            header = bytes((len(elements),)) + elements if elements else b""
            first = 0x41 if header else 0x01
            pdu = "00%02X00%02X%s%s00" % (first, len(number), "91" if destination.startswith("+") else "81",
                                           _semi_octets(destination))
            if alphabet == "gsm7":
                payload, header_septets = _pack_gsm7(_gsm7_values(chunk), header)
                user_length = header_septets + len(_gsm7_values(chunk))
                pdu += "00%02X%s" % (user_length, payload.hex().upper())
            elif alphabet == "8bit":
                payload = header + chunk.encode("latin-1", errors)
                pdu += "04%02X%s" % (len(payload), payload.hex().upper())
            else:
                payload = header + chunk.encode("utf-16-be", errors)
                pdu += "08%02X%s" % (len(payload), payload.hex().upper())
            result.append(pdu)
        output = "\n".join(result)
        return output, len(message)
    return encode


def sms_pdu_decode(text, errors="strict"):
    value = ensure_str(text)
    return _parse_pdu(value, errors)["text"], len(value)


def sms_pdu_decode_factory(alphabet="", destination=""):
    return sms_pdu_decode


def sms_pdu_batch_decode(text, errors="strict"):
    value = ensure_str(text)
    records = [_parse_pdu(line, errors) for line in value.splitlines() if line.strip()]
    records.sort(key=lambda record: (record.get("reference", -1), record.get("part", 1)))
    return "".join(record["text"] for record in records), len(value)


def parse_sms_pdu(text, errors="strict"):
    return _parse_pdu(text, errors)


def sms_pdu_info_decode(text, errors="strict"):
    source = ensure_str(text)
    records = [_parse_pdu(line, errors) for line in source.splitlines() if line.strip()]
    result = json.dumps(records[0] if len(records) == 1 else records, ensure_ascii=False, indent=2)
    return result, len(source)


add("sms_pdu", sms_pdu_encode, sms_pdu_decode_factory,
    r"^(?:sms[-_]?pdu|pdu[-_]?sms)(?:[-_](gsm7|8bit|ucs2))?(?:[-_]([0-9]+))?$", aliases=["sms-pdu"])
add("sms_pdu_batch", None, sms_pdu_batch_decode,
    r"^(?:sms[-_]?pdu[-_]?(?:batch|multipart)|pdu[-_]?multipart)$", aliases=["sms-pdu-batch"])
add("sms_pdu_info", None, sms_pdu_info_decode, r"^(?:sms[-_]?pdu|pdu[-_]?sms)[-_](?:info|json)$",
    aliases=["sms-pdu-info"])
