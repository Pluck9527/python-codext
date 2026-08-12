# -*- coding: UTF-8 -*-
"""ICE cipher and one-bit CFB mode used by the original SNOW utility.

Copyright 1999 Matthew Kwan. Licensed under the Apache License, Version 2.0.
"""

SMOD = ((333, 313, 505, 369), (379, 375, 319, 391),
        (361, 445, 451, 397), (397, 425, 395, 505))
SXOR = ((0x83, 0x85, 0x9b, 0xcd), (0xcc, 0xa7, 0xad, 0x41),
        (0x4b, 0x2e, 0xd4, 0x33), (0xea, 0xcb, 0x2e, 0x04))
PBOX = (
    0x00000001, 0x00000080, 0x00000400, 0x00002000, 0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000, 0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000, 0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000, 0x00040000, 0x00100000, 0x02000000, 0x80000000,
)
KEYROT = (0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2)


def _gf_mult(a, b, modulus):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
        if a >= 256:
            a ^= modulus
    return result


def _gf_exp7(value, modulus):
    if value == 0:
        return 0
    squared = _gf_mult(value, value, modulus)
    cubed = _gf_mult(value, squared, modulus)
    sixth = _gf_mult(cubed, cubed, modulus)
    return _gf_mult(value, sixth, modulus)


def _perm32(value):
    result, index = 0, 0
    while value:
        if value & 1:
            result |= PBOX[index]
        index += 1
        value >>= 1
    return result


def _build_sboxes():
    boxes = [[0] * 1024 for _ in range(4)]
    for index in range(1024):
        column = (index >> 1) & 0xff
        row = (index & 1) | ((index & 0x200) >> 8)
        for box, shift in enumerate((24, 16, 8, 0)):
            boxes[box][index] = _perm32(_gf_exp7(column ^ SXOR[box][row], SMOD[box][row]) << shift)
    return boxes


SBOX = _build_sboxes()


class IceKey:
    def __init__(self, level):
        self.size = max(1, level)
        self.rounds = self.size * 16
        self.schedule = [[0, 0, 0] for _ in range(self.rounds)]

    def set(self, key):
        for index in range(self.size):
            words = [0] * 4
            for word in range(4):
                offset = index * 8 + word * 2
                words[3 - word] = (key[offset] << 8) | key[offset + 1]
            self._schedule_build(words, index * 8, KEYROT[:8])
            self._schedule_build(words, self.rounds - 8 - index * 8, KEYROT[8:])

    def _schedule_build(self, words, offset, rotations):
        for round_index in range(8):
            rotation = rotations[round_index]
            subkey = self.schedule[offset + round_index]
            for step in range(15):
                slot = step % 3
                for word_offset in range(4):
                    word = (rotation + word_offset) & 3
                    bit = words[word] & 1
                    subkey[slot] = (subkey[slot] << 1) | bit
                    words[word] = (words[word] >> 1) | ((bit ^ 1) << 15)

    def _round(self, value, subkey):
        left = ((value >> 16) & 0x3ff) | (((value >> 14) | (value << 18)) & 0xffc00)
        right = (value & 0x3ff) | ((value << 2) & 0xffc00)
        salted = subkey[2] & (left ^ right)
        right = (salted ^ right) ^ subkey[1]
        left = (salted ^ left) ^ subkey[0]
        return (SBOX[0][left >> 10] | SBOX[1][left & 0x3ff] |
                SBOX[2][right >> 10] | SBOX[3][right & 0x3ff])

    def encrypt(self, block):
        left, right = int.from_bytes(block[:4], "big"), int.from_bytes(block[4:8], "big")
        for index in range(0, self.rounds, 2):
            left = (left ^ self._round(right, self.schedule[index])) & 0xffffffff
            right = (right ^ self._round(left, self.schedule[index + 1])) & 0xffffffff
        return right.to_bytes(4, "big") + left.to_bytes(4, "big")


def password_key(password):
    password = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    level = min(128, max(1, (len(password) * 7 + 63) // 64))
    packed, bit_offset = bytearray(1024), 0
    for byte in password:
        value = byte & 0x7f
        index, bit = bit_offset // 8, bit_offset & 7
        if bit == 0:
            packed[index] = (value << 1) & 0xff
        elif bit == 1:
            packed[index] |= value
        else:
            packed[index] |= value >> (bit - 1)
            packed[index + 1] = (value << (9 - bit)) & 0xff
        bit_offset += 7
        if bit_offset > 8184:
            break
    key = IceKey(level)
    key.set(packed[:level * 8])
    return key, bytearray(key.encrypt(packed[:8]))


def cfb_bits(bits, password, decrypt=False):
    if not password:
        return bits
    key, iv = password_key(password)
    output = []
    for symbol in bits:
        input_bit = int(symbol)
        mask = 1 if key.encrypt(iv)[0] & 0x80 else 0
        output_bit = input_bit ^ mask
        cipher_bit = input_bit if decrypt else output_bit
        value = (int.from_bytes(iv, "big") << 1 | cipher_bit) & ((1 << 64) - 1)
        iv[:] = value.to_bytes(8, "big")
        output.append(str(output_bit))
    return "".join(output)
