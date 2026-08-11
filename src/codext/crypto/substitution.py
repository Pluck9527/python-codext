# -*- coding: UTF-8 -*-
"""Offline monoalphabetic substitution helpers and frequency reports."""
import json
import math
import random
from collections import Counter
from string import ascii_lowercase, ascii_uppercase

from ..__common__ import add, ensure_str


ENGLISH_ORDER = "etaoinshrdlcumwfgypbvkjxqz"
COMMON = {
    "th": 2.4, "he": 2.2, "in": 1.8, "er": 1.8, "an": 1.7, "re": 1.7, "on": 1.6, "at": 1.5,
    "en": 1.5, "nd": 1.4, "the": 5.0, "and": 4.2, "ing": 4.0, "her": 3.2, "ere": 3.0, "ent": 3.0,
    "tha": 2.8, "nth": 2.7, "was": 2.6, "eth": 2.5, "for": 2.5, "dth": 2.2, "thei": 6.0,
    "tion": 5.8, "that": 5.5, "ther": 5.3, "with": 5.0, "here": 4.7, "ould": 4.5, "ight": 4.4,
}


def frequency_report(text):
    source = ensure_str(text)
    letters = Counter(char.lower() for char in source if char.lower() in ascii_lowercase)
    total = sum(letters.values()) or 1
    words = Counter(word.strip(".,!?;:'\"()[]{}").lower() for word in source.split())
    return {
        "length": len(source),
        "letters": [{"char": char, "count": count, "percent": round(count * 100 / total, 3)}
                    for char, count in letters.most_common()],
        "words": [{"word": word, "count": count} for word, count in words.most_common(32) if word],
    }


def _translate(text, key):
    table = str.maketrans(ascii_lowercase + ascii_uppercase, key + key.upper())
    return text.translate(table)


def _score(text):
    lower = text.lower()
    score = sum(lower.count(token) * weight for token, weight in COMMON.items())
    score += sum(lower.count(" " + word + " ") * 6 for word in
                 ("the", "and", "this", "that", "is", "of", "to", "in", "for", "flag"))
    score -= sum(lower.count(token) * 2 for token in ("qz", "jq", "qj", "zx", "vvv", "jj"))
    return score


def solve_substitution(text, restarts=24, iterations=3000):
    """Return the best deterministic hill-climbed cipher-to-plain alphabet."""
    source = ensure_str(text)
    counts = Counter(char.lower() for char in source if char.lower() in ascii_lowercase)
    ranked = "".join(char for char, _ in counts.most_common()) + "".join(
        char for char in ascii_lowercase if char not in counts)
    initial = [""] * 26
    for cipher, plain in zip(ranked, ENGLISH_ORDER):
        initial[ord(cipher) - 97] = plain
    randomizer = random.Random(source)
    best_key, best_text = "".join(initial), _translate(source, "".join(initial))
    best_score = _score(best_text)
    for restart in range(max(1, int(restarts))):
        key = list(best_key if restart == 0 else "".join(randomizer.sample(ascii_lowercase, 26)))
        current = _score(_translate(source, "".join(key)))
        temperature = 8.0
        for _ in range(max(1, int(iterations))):
            left, right = randomizer.sample(range(26), 2)
            key[left], key[right] = key[right], key[left]
            candidate_text = _translate(source, "".join(key))
            candidate = _score(candidate_text)
            if candidate >= current or randomizer.random() < math.exp((candidate - current) / temperature):
                current = candidate
                if candidate > best_score:
                    best_key, best_text, best_score = "".join(key), candidate_text, candidate
            else:
                key[left], key[right] = key[right], key[left]
            temperature = max(0.15, temperature * 0.998)
    return {"text": best_text, "key": best_key, "score": round(best_score, 3)}


def frequency_decode(text, errors="strict"):
    result = json.dumps(frequency_report(text), ensure_ascii=False, indent=2)
    return result, len(ensure_str(text))


def quipqiup_decode(text, errors="strict"):
    result = solve_substitution(text)["text"]
    return result, len(ensure_str(text))


def substitution_factory(key, decode=False):
    alphabet = bytes.fromhex(key[1:]).decode().lower()
    if len(alphabet) != 26 or set(alphabet) != set(ascii_lowercase):
        raise ValueError("substitution key must be a permutation of 26 ASCII letters")
    mapping = "".join(ascii_lowercase[alphabet.index(char)] for char in ascii_lowercase) if decode else alphabet

    def code(text, errors="strict"):
        result = _translate(ensure_str(text), mapping)
        return result, len(result)
    return code


def substitution_encode(key):
    return substitution_factory(key)


def substitution_decode(key):
    return substitution_factory(key, True)


add("frequency_analysis", None, frequency_decode, r"^(?:frequency[-_]?analysis|freq)$")
add("quipqiup", None, quipqiup_decode, r"^(?:quipqiup|substitution[-_]?solve)$")
add("substitution", substitution_encode, substitution_decode, r"^substitution[-_](h[0-9a-fA-F]{52})$")
