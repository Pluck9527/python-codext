# -*- coding: UTF-8 -*-
"""Explicit online adapter for the proprietary Spammimic grammar."""
import html
import re
import urllib.parse
import urllib.request

from ..__common__ import add, ensure_str


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
