# -*- coding: UTF-8 -*-
"""Offline reversible spam mimic plus an explicit official-site adapter."""
import html
import re
import urllib.parse
import urllib.request
import zlib

from ..__common__ import add, ensure_str


WORD_PAIRS = (
    ("exclusive", "premium"), ("offer", "proposal"), ("selected", "chosen"), ("customer", "member"),
    ("discover", "explore"), ("valuable", "rewarding"), ("benefits", "advantages"), ("today", "now"),
    ("simple", "easy"), ("secure", "protected"), ("service", "program"), ("details", "information"),
    ("reply", "respond"), ("quickly", "promptly"), ("special", "unique"), ("opportunity", "invitation"),
)
WORD_BITS = {word: bit for pair in WORD_PAIRS for bit, word in enumerate(pair)}


def spammimic_encode(text, errors="strict"):
    source = ensure_str(text)
    payload = source.encode("utf-8")
    framed = b"SM1" + len(payload).to_bytes(4, "big") + payload + zlib.crc32(payload).to_bytes(4, "big")
    bits = "".join(format(byte, "08b") for byte in framed)
    words = [WORD_PAIRS[index % len(WORD_PAIRS)][int(bit)] for index, bit in enumerate(bits)]
    result = "Dear friend, " + " ".join(words) + ". Thank you for your attention."
    return result, len(source)


def spammimic_decode(text, errors="strict"):
    source = ensure_str(text)
    bits = "".join(str(WORD_BITS[word.lower()]) for word in re.findall(r"[A-Za-z]+", source)
                   if word.lower() in WORD_BITS)
    data = bytes(int(bits[index:index + 8], 2) for index in range(0, len(bits) // 8 * 8, 8))
    if len(data) < 11 or data[:3] != b"SM1":
        raise ValueError("not an offline CodExt Spammimic message")
    size = int.from_bytes(data[3:7], "big")
    payload = data[7:7 + size]
    if len(payload) != size or data[7 + size:11 + size] != zlib.crc32(payload).to_bytes(4, "big"):
        raise ValueError("invalid or truncated Spammimic payload")
    return payload.decode("utf-8", errors), len(source)


def _request(endpoint, field, value, timeout=15):
    source = ensure_str(value)
    if len(source.encode()) > 65536:
        raise ValueError("Spammimic online input is limited to 64 KiB")
    request = urllib.request.Request("https://www.spammimic.com/" + endpoint,
                                     urllib.parse.urlencode({field: source}).encode(),
                                     headers={"User-Agent": "CodExt-CTF/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise ConnectionError("Spammimic returned HTTP %d" % response.status)
        return response.read(2_000_000).decode("utf-8", "replace")


def spammimic_online_encode(text, errors="strict"):
    source = ensure_str(text)
    match = re.search(r"<textarea[^>]*>(.*?)</textarea>",
                      _request("encode.cgi", "plaintext", source), re.DOTALL | re.IGNORECASE)
    if not match:
        raise ValueError("Spammimic response did not contain encoded spam")
    return html.unescape(match.group(1)).strip(), len(source)


def spammimic_online_decode(text, errors="strict"):
    source = ensure_str(text)
    match = re.search(r'name=plaintext\s+value="([^"]*)"',
                      _request("decode.cgi", "cyphertext", source), re.IGNORECASE)
    if not match:
        raise ValueError("Spammimic response did not contain decoded text")
    return html.unescape(match.group(1)).rstrip("\0"), len(source)


add("spammimic_online", spammimic_online_encode, spammimic_online_decode,
    r"^(?:spammimic|spam[-_]?mimic)[-_]online$")
add("spammimic", spammimic_encode, spammimic_decode, r"^(?:spammimic|spam[-_]?mimic)(?:[-_]offline)?$")
