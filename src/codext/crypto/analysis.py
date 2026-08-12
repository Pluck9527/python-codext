# -*- coding: UTF-8 -*-
"""Bounded CTF key recovery for Vigenere, Hill and Enigma I."""
import itertools
import json
import heapq
import math
from collections import Counter
from string import ascii_uppercase

from ..__common__ import add, ensure_str
from .enigma import enigma_factory
from .substitution import _score


ENGLISH = (8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, .153, .772, 4.025,
           2.406, 6.749, 7.507, 1.929, .095, 5.987, 6.327, 9.056, 2.758, .978, 2.360, .150, 1.974, .074)


def _vigenere_decrypt(text, key):
    output, cursor = [], 0
    for char in text:
        if char.upper() not in ascii_uppercase:
            output.append(char)
            continue
        base = 65 if char.isupper() else 97
        output.append(chr((ord(char) - base - key[cursor % len(key)]) % 26 + base))
        cursor += 1
    return "".join(output)


def recover_vigenere_key(plaintext, ciphertext):
    pairs = [(plain.upper(), cipher.upper()) for plain, cipher in zip(ensure_str(plaintext), ensure_str(ciphertext))
             if plain.upper() in ascii_uppercase and cipher.upper() in ascii_uppercase]
    stream = [(ord(cipher) - ord(plain)) % 26 for plain, cipher in pairs]
    for size in range(1, len(stream) + 1):
        if all(value == stream[index % size] for index, value in enumerate(stream)):
            return "".join(chr(value + 65) for value in stream[:size])
    return ""


def crack_vigenere(ciphertext, max_key_length=20, limit=10):
    source = ensure_str(ciphertext)
    letters = [ord(char) - 65 for char in source.upper() if char in ascii_uppercase]
    if len(letters) < 4:
        raise ValueError("Vigenere cracking requires at least four letters")
    candidates = []
    for size in range(1, min(int(max_key_length), max(1, len(letters) // 2)) + 1):
        key = []
        for offset in range(size):
            column = letters[offset::size]
            observed = Counter(column)
            key.append(min(range(26), key=lambda shift: sum(
                (observed[(letter + shift) % 26] - len(column) * ENGLISH[letter] / 100) ** 2 /
                max(.01, len(column) * ENGLISH[letter] / 100) for letter in range(26))))
        plaintext = _vigenere_decrypt(source, key)
        candidates.append({"text": plaintext, "key": "".join(chr(value + 65) for value in key),
                           "key_length": size, "score": round(_score(plaintext), 3)})
    return sorted(candidates, key=lambda value: value["score"], reverse=True)[:max(1, int(limit))]


def _determinant(matrix):
    if len(matrix) == 1:
        return matrix[0][0]
    return sum((-1) ** column * matrix[0][column] * _determinant(
        [row[:column] + row[column + 1:] for row in matrix[1:]]) for column in range(len(matrix)))


def _inverse(matrix):
    determinant = _determinant(matrix) % 26
    inverse = pow(determinant, -1, 26)
    return [[((-1) ** (row + column) * _determinant(
        [line[:row] + line[row + 1:] for index, line in enumerate(matrix) if index != column]) * inverse) % 26
             for column in range(len(matrix))] for row in range(len(matrix))]


def _multiply(left, right):
    return [[sum(left[row][index] * right[index][column] for index in range(len(right))) % 26
             for column in range(len(right[0]))] for row in range(len(left))]


def recover_hill_key(plaintext, ciphertext, dimension=2):
    size = int(dimension)
    plain = [ord(char) - 65 for char in ensure_str(plaintext).upper() if char in ascii_uppercase]
    cipher = [ord(char) - 65 for char in ensure_str(ciphertext).upper() if char in ascii_uppercase]
    blocks = min(len(plain), len(cipher)) // size
    if size < 2 or blocks < size:
        raise ValueError("Hill recovery needs at least dimension squared aligned letters")
    plain_blocks = [plain[index * size:(index + 1) * size] for index in range(blocks)]
    cipher_blocks = [cipher[index * size:(index + 1) * size] for index in range(blocks)]
    for selected in itertools.combinations(range(blocks), size):
        p = [[plain_blocks[column][row] for column in selected] for row in range(size)]
        c = [[cipher_blocks[column][row] for column in selected] for row in range(size)]
        try:
            key = _multiply(c, _inverse(p))
        except ValueError:
            continue
        if all([sum(key[row][column] * block[column] for column in range(size)) % 26 for row in range(size)] ==
               cipher_blocks[index] for index, block in enumerate(plain_blocks)):
            return key
    raise ValueError("no Hill key matches the aligned plaintext/ciphertext")


def crack_hill(ciphertext, dimension=2, limit=10):
    """Exhaustively crack a 2x2 Hill key; larger matrices use recover_hill_key."""
    if int(dimension) != 2:
        raise ValueError("ciphertext-only Hill cracking is bounded to 2x2 matrices")
    source = "".join(char for char in ensure_str(ciphertext).upper() if char in ascii_uppercase)
    if len(source) < 8 or len(source) % 2:
        raise ValueError("2x2 Hill cracking requires an even ciphertext of at least eight letters")
    values = [ord(char) - 65 for char in source]
    candidates = []
    serial = 0
    for a, b_, c, d in itertools.product(range(26), repeat=4):
        determinant = (a * d - b_ * c) % 26
        if math.gcd(determinant, 26) != 1:
            continue
        inverse = pow(determinant, -1, 26)
        matrix = ((d * inverse % 26, -b_ * inverse % 26), (-c * inverse % 26, a * inverse % 26))
        plaintext = "".join(chr((matrix[row][0] * values[index] + matrix[row][1] * values[index + 1]) % 26 + 65)
                            for index in range(0, len(values), 2) for row in range(2))
        item = (_score(plaintext), serial, {"text": plaintext, "key": [[a, b_], [c, d]]})
        serial += 1
        if len(candidates) < limit:
            heapq.heappush(candidates, item)
            continue
        if item[0] > candidates[0][0]:
            heapq.heapreplace(candidates, item)
    return [dict(value, score=round(score, 3)) for score, _, value in sorted(candidates, reverse=True)]


def crack_enigma(ciphertext, crib="", rotor_orders=("I.II.III",), reflectors=("B", "C"), rings="AAA", limit=10):
    source, target = ensure_str(ciphertext), ensure_str(crib).upper()
    if target and (len(target) < 3 or any(char not in ascii_uppercase for char in target)):
        raise ValueError("Enigma recovery requires an alphabetic crib of at least three letters")
    candidates, serial = [], 0
    for rotors, reflector, positions in itertools.product(rotor_orders, reflectors,
                                                          map("".join, itertools.product(ascii_uppercase, repeat=3))):
        plaintext = enigma_factory(rotors, reflector, positions, rings)(source)[0]
        if target and target not in "".join(char for char in plaintext if char in ascii_uppercase):
            continue
        value = {"text": plaintext, "rotors": rotors, "reflector": reflector,
                 "positions": positions, "rings": rings}
        if target:
            candidates.append(value)
            if len(candidates) >= limit:
                break
            continue
        item = (_score(plaintext), serial, value)
        serial += 1
        if len(candidates) < limit:
            heapq.heappush(candidates, item)
            continue
        if item[0] > candidates[0][0]:
            heapq.heapreplace(candidates, item)
    if target:
        return candidates
    return [dict(value, score=round(score, 3)) for score, _, value in sorted(candidates, reverse=True)]


def vigenere_crack_decode(text, errors="strict"):
    source = ensure_str(text)
    result = json.dumps(crack_vigenere(source), ensure_ascii=False, indent=2)
    return result, len(source)


def hill_recover_decode(dimension=""):
    def decode(text, errors="strict"):
        source = ensure_str(text)
        plaintext, ciphertext = source.splitlines()[:2]
        result = json.dumps(recover_hill_key(plaintext, ciphertext, int(dimension or 2)))
        return result, len(source)
    return decode


def hill_crack_decode(text, errors="strict"):
    source = ensure_str(text)
    result = json.dumps(crack_hill(source), ensure_ascii=False, indent=2)
    return result, len(source)


def enigma_crack_decode(crib=""):
    def decode(text, errors="strict"):
        source = ensure_str(text)
        result = json.dumps(crack_enigma(source, crib), ensure_ascii=False, indent=2)
        return result, len(source)
    return decode


add("crack_vigenere", None, vigenere_crack_decode, r"^crack[-_]vigenere$")
add("hill_recover", None, hill_recover_decode, r"^hill[-_](?:recover|known)(?:[-_]([2-6]))?$")
add("hill_crack", None, hill_crack_decode, r"^hill[-_](?:crack|auto)$")
add("enigma_crack", None, enigma_crack_decode,
    r"^enigma[-_](?:crack|recover)(?:[-_]([a-zA-Z]{3,32}))?$")
