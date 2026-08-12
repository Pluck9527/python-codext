# -*- coding: UTF-8 -*-
"""Rabbit stream cipher with raw and CryptoJS/OpenSSL passphrase formats."""
import base64
import hashlib
import os

from ..__common__ import add, b, ensure_str
from .modern import _decode_data, _encode_data, _material


MASK = 0xffffffff


def _rotate(value, amount):
    return ((value << amount) | (value >> (32 - amount))) & MASK


def _swap(value):
    return (((value << 8) | (value >> 24)) & 0x00ff00ff) | (((value << 24) | (value >> 8)) & 0xff00ff00)


class Rabbit:
    def __init__(self, key, iv=b""):
        if len(key) != 16 or iv and len(iv) != 8:
            raise ValueError("Rabbit requires a 16-byte key and an optional 8-byte IV")
        words = [_swap(int.from_bytes(key[index:index + 4], "big")) for index in range(0, 16, 4)]
        self.x = [
            words[0], (words[3] << 16 | words[2] >> 16) & MASK,
            words[1], (words[0] << 16 | words[3] >> 16) & MASK,
            words[2], (words[1] << 16 | words[0] >> 16) & MASK,
            words[3], (words[2] << 16 | words[1] >> 16) & MASK,
        ]
        self.c = [
            _rotate(words[2], 16), words[0] & 0xffff0000 | words[1] & 0xffff,
            _rotate(words[3], 16), words[1] & 0xffff0000 | words[2] & 0xffff,
            _rotate(words[0], 16), words[2] & 0xffff0000 | words[3] & 0xffff,
            _rotate(words[1], 16), words[3] & 0xffff0000 | words[0] & 0xffff,
        ]
        self.carry = 0
        for _ in range(4):
            self._next()
        self.c = [(counter ^ self.x[(index + 4) & 7]) & MASK for index, counter in enumerate(self.c)]
        if iv:
            first, second = int.from_bytes(iv[:4], "big"), int.from_bytes(iv[4:], "big")
            i0, i2 = _swap(first), _swap(second)
            i1, i3 = i0 >> 16 | i2 & 0xffff0000, (i2 << 16 | i0 & 0xffff) & MASK
            vectors = (i0, i1, i2, i3, i0, i1, i2, i3)
            self.c = [(counter ^ vectors[index]) & MASK for index, counter in enumerate(self.c)]
            for _ in range(4):
                self._next()

    def _next(self):
        constants = (0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d,
                     0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3)
        carry = self.carry
        for index, constant in enumerate(constants):
            value = (self.c[index] + constant + carry) & MASK
            carry = 1 if value < self.c[index] else 0
            self.c[index] = value
        self.carry = carry
        g = []
        for state, counter in zip(self.x, self.c):
            value = (state + counter) & MASK
            square = value * value
            g.append(((square >> 32) ^ (square & MASK)) & MASK)
        self.x = [
            (g[0] + _rotate(g[7], 16) + _rotate(g[6], 16)) & MASK,
            (g[1] + _rotate(g[0], 8) + g[7]) & MASK,
            (g[2] + _rotate(g[1], 16) + _rotate(g[0], 16)) & MASK,
            (g[3] + _rotate(g[2], 8) + g[1]) & MASK,
            (g[4] + _rotate(g[3], 16) + _rotate(g[2], 16)) & MASK,
            (g[5] + _rotate(g[4], 8) + g[3]) & MASK,
            (g[6] + _rotate(g[5], 16) + _rotate(g[4], 16)) & MASK,
            (g[7] + _rotate(g[6], 8) + g[5]) & MASK,
        ]

    def crypt(self, data):
        output = bytearray()
        for offset in range(0, len(data), 16):
            self._next()
            stream = (
                self.x[0] ^ self.x[5] >> 16 ^ self.x[3] << 16,
                self.x[2] ^ self.x[7] >> 16 ^ self.x[5] << 16,
                self.x[4] ^ self.x[1] >> 16 ^ self.x[7] << 16,
                self.x[6] ^ self.x[3] >> 16 ^ self.x[1] << 16,
            )
            key = b"".join(_swap(word & MASK).to_bytes(4, "big") for word in stream)
            output.extend(left ^ right for left, right in zip(data[offset:offset + 16], key))
        return bytes(output)


def evp_bytes_to_key(password, salt, length):
    password = password.encode() if isinstance(password, str) else bytes(password)
    result, previous = b"", b""
    while len(result) < length:
        previous = hashlib.md5(previous + password + salt).digest()
        result += previous
    return result[:length]


def rabbit_code(key, iv="", output="", decode=False):
    key, iv, output = _material(key), _material(iv) if iv else b"", str(output or "b64")
    def code(text, errors="strict"):
        source = _decode_data(text, output) if decode else b(text)
        result = Rabbit(key, iv).crypt(source)
        return (result if decode else _encode_data(result, output)), len(ensure_str(text))
    return code


def rabbit_encode(key, iv="", output=""):
    return rabbit_code(key, iv, output)


def rabbit_decode(key, iv="", output=""):
    return rabbit_code(key, iv, output, True)


def rabbit_pbe_code(password, decode=False):
    password = _material(password)
    def code(text, errors="strict"):
        if decode:
            envelope = base64.b64decode(ensure_str(text), validate=True)
            if not envelope.startswith(b"Salted__") or len(envelope) < 16:
                raise ValueError("Rabbit PBE input is not an OpenSSL/CryptoJS salted envelope")
            salt, source = envelope[8:16], envelope[16:]
        else:
            salt, source = os.urandom(8), b(text)
        material = evp_bytes_to_key(password, salt, 24)
        result = Rabbit(material[:16], material[16:]).crypt(source)
        if decode:
            return result, len(ensure_str(text))
        envelope = base64.b64encode(b"Salted__" + salt + result).decode()
        return envelope, len(b(text))
    return code


def rabbit_pbe_encode(password):
    return rabbit_pbe_code(password)


def rabbit_pbe_decode(password):
    return rabbit_pbe_code(password, True)


add("rabbit_keyed", rabbit_encode, rabbit_decode,
    r"^rabbit[-_](h[0-9a-fA-F]{32})(?:[-_](h[0-9a-fA-F]{16}))?(?:[-_](hex|b64))?$",
    aliases=["rabbit-keyed"])
add("rabbit_pbe", rabbit_pbe_encode, rabbit_pbe_decode,
    r"^rabbit[-_]pbe[-_](h(?:[0-9a-fA-F]{2})+)$", aliases=["rabbit-pbe"])
