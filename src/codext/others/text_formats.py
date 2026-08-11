# -*- coding: UTF-8 -*-
"""CTF text transfer encodings, Unicode escapes and mojibake recovery."""
import json
import quopri
import re

from ..__common__ import add, ensure_str


UNICODE_ESCAPE = re.compile(
    r"\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|"
    r"(?:U\+|\+U)([0-9a-fA-F]{4,8})|&#x([0-9a-fA-F]+);|&#([0-9]+);"
)


def quoted_printable_encode(text, errors="strict"):
    result = quopri.encodestring(ensure_str(text).encode("utf-8"), quotetabs=True).decode("ascii")
    return result, len(ensure_str(text))


def quoted_printable_decode(text, errors="strict"):
    result = quopri.decodestring(ensure_str(text).encode("ascii"))
    return result, len(ensure_str(text))


def unicode_escape_encode(text, errors="strict"):
    result = "".join(
        char if 0x20 <= ord(char) < 0x7f and char not in "\\" else
        "\\u%04x" % ord(char) if ord(char) <= 0xffff else "\\U%08x" % ord(char)
        for char in ensure_str(text)
    )
    return result, len(ensure_str(text))


def unicode_escape_decode(text, errors="strict"):
    def replace(match):
        value = next(group for group in match.groups() if group is not None)
        return chr(int(value, 10 if match.group(6) is not None else 16))

    result = UNICODE_ESCAPE.sub(replace, ensure_str(text))
    return result, len(ensure_str(text))


def mojibake_gbk_decode(text, errors="strict"):
    value = ensure_str(text)
    return value.encode("gb18030", errors).decode("utf-8", errors), len(value)


def text_encoding_bruteforce_decode(text, errors="strict"):
    value = ensure_str(text)
    sources = ("latin1", "cp1252", "gb18030", "big5", "shift_jis")
    targets = ("utf-8", "gb18030", "big5", "shift_jis", "euc_kr", "cp1252", "latin1")
    candidates = []
    seen = {value}
    for source in sources:
        for target in targets:
            if source == target:
                continue
            try:
                candidate = value.encode(source).decode(target)
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            controls = sum(ord(char) < 32 and char not in "\r\n\t" for char in candidate)
            replacements = candidate.count("�")
            readable = sum(char.isprintable() or char in "\r\n\t" for char in candidate)
            score = round(readable / max(len(candidate), 1) - controls - replacements +
                          (0.05 if target == "utf-8" else 0), 4)
            candidates.append({"source": source, "target": target, "score": score, "text": candidate})
    result = json.dumps(sorted(candidates, key=lambda item: (-item["score"], item["source"], item["target"])),
                        ensure_ascii=False, indent=2)
    return result, len(value)


add("quoted_printable", quoted_printable_encode, quoted_printable_decode,
    r"^(?:quoted[-_]?printable|quote[-_]?printable|quopri|qp)$", aliases=["quoted-printable"])
add("unicode_escape", unicode_escape_encode, unicode_escape_decode,
    r"^(?:unicode[-_]?escape|unicode[-_]?escapes?|uescape)$", aliases=["unicode-escape"])
add("mojibake_gbk", None, mojibake_gbk_decode,
    r"^(?:mojibake[-_]?(?:gbk|gb18030)|fix[-_]?mojibake|kun[-_]?jin[-_]?kao)$", aliases=["mojibake-gbk"])
add("text_encoding_bruteforce", None, text_encoding_bruteforce_decode,
    r"^(?:text[-_]?encoding[-_]?(?:bruteforce|brute[-_]?force)|encoding[-_]?bruteforce)$",
    aliases=["text-encoding-brute-force"])
