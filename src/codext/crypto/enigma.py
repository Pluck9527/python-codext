# -*- coding: UTF-8 -*-
"""Three-rotor Wehrmacht Enigma I codec."""
from string import ascii_uppercase

from ..__common__ import *


ROTORS = {
    "I": ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II": ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV": ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V": ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
}
REFLECTORS = {"B": "YRUHQSLDPXNGOKMIEBFZCWVJAT", "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL"}


def enigma_factory(rotors="", reflector="", positions="", rings="", plugboard=""):
    names = (rotors or "I.II.III").upper().split(".")
    reflector = (reflector or "B").upper()
    positions, rings = (positions or "AAA").upper(), (rings or "AAA").upper()
    if len(names) != 3 or any(name not in ROTORS for name in names) or reflector not in REFLECTORS or \
       len(positions) != 3 or len(rings) != 3:
        raise LookupError("Bad parameter for encoding 'enigma'")
    pairs = [pair.upper() for pair in plugboard.split(".") if pair] if plugboard else []
    if any(len(pair) != 2 or any(char not in ascii_uppercase for char in pair) for pair in pairs):
        raise LookupError("Bad Enigma plugboard pairs")
    if len(set("".join(pairs))) != len("".join(pairs)):
        raise LookupError("Bad Enigma plugboard pairs: a letter cannot be connected twice")

    def code(text, errors="strict"):
        pos, ring = [ord(char) - 65 for char in positions], [ord(char) - 65 for char in rings]
        plug = {char: char for char in ascii_uppercase}
        for pair in pairs:
            plug[pair[0]], plug[pair[1]] = pair[1], pair[0]

        def pass_rotor(value, index, backwards=False):
            wiring = ROTORS[names[index]][0]
            shifted = (value + pos[index] - ring[index]) % 26
            mapped = wiring.index(chr(shifted + 65)) if backwards else ord(wiring[shifted]) - 65
            return (mapped - pos[index] + ring[index]) % 26

        result = []
        for char in ensure_str(text).upper():
            if char not in ascii_uppercase:
                result.append(char)
                continue
            middle_notch = ascii_uppercase[pos[1]] == ROTORS[names[1]][1]
            right_notch = ascii_uppercase[pos[2]] == ROTORS[names[2]][1]
            if middle_notch:
                pos[0], pos[1] = (pos[0] + 1) % 26, (pos[1] + 1) % 26
            elif right_notch:
                pos[1] = (pos[1] + 1) % 26
            pos[2] = (pos[2] + 1) % 26
            value = ord(plug[char]) - 65
            for index in (2, 1, 0):
                value = pass_rotor(value, index)
            value = ord(REFLECTORS[reflector][value]) - 65
            for index in (0, 1, 2):
                value = pass_rotor(value, index, True)
            result.append(plug[chr(value + 65)])
        return (output := "".join(result)), len(output)
    return code


pattern = r"^enigma(?:[-_]([iv]+\.[iv]+\.[iv]+))?(?:[-_]([bc]))?(?:[-_]([a-z]{3}))?(?:[-_]([a-z]{3}))?(?:[-_]([a-z]{2}(?:\.[a-z]{2})*))?$"
add("enigma", enigma_factory, enigma_factory, pattern)
