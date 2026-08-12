# -*- coding: UTF-8 -*-
"""PGP biometric word-list codec."""
import json
import os

from ..__common__ import *


with open(os.path.join(os.path.dirname(__file__), "pgp_word_list.json"), encoding="utf-8") as source:
    WORD_LISTS = json.load(source)
TABLES = (WORD_LISTS["even"], WORD_LISTS["odd"])
LOOKUPS = tuple({word.lower(): index for index, word in enumerate(table)} for table in TABLES)


def pgp_words_encode(text, errors="strict"):
    result = " ".join(TABLES[index % 2][byte] for index, byte in enumerate(b(text)))
    return result, len(result)


def pgp_words_decode(text, errors="strict"):
    result, error = bytearray(), handle_error("pgp_words", errors, decode=True, kind="word", item="position")
    for index, word in enumerate(re.findall(r"[A-Za-z]+", ensure_str(text))):
        try:
            result.append(LOOKUPS[index % 2][word.lower()])
        except KeyError:
            replacement = error(word, index)
            if replacement:
                result.extend(b(replacement))
    return bytes(result), len(ensure_str(text))


add("pgp_words", pgp_words_encode, pgp_words_decode, r"^pgp[-_]?(?:words?|word[-_]?list)$",
    aliases=["pgp-word-list"])
