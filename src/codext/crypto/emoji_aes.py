# -*- coding: UTF-8 -*-
"""Emoji-AES compatible with the original CryptoJS web implementation."""
import base64
import os

from ..__common__ import add, b, ensure_str
from .modern import _pad, _unpad
from .rabbit import evp_bytes_to_key


BASE64_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
EMOJIS = [
    "🍎", "🍌", "🏎", "🚪", "👁", "👣", "😀", "🖐", "ℹ", "😂", "🥋", "✉", "🚹",
    "🌉", "👌", "🍍", "👑", "👉", "🎤", "🚰", "☂", "🐍", "💧", "✖", "☀", "🦓",
    "🏹", "🎈", "😎", "🎅", "🐘", "🌿", "🌏", "🌪", "☃", "🍵", "🍴", "🚨", "📮",
    "🕹", "📂", "🛩", "⌨", "🔄", "🔬", "🐅", "🙃", "🐎", "🌊", "🚫", "❓", "⏩",
    "😁", "😆", "💵", "🤣", "☺", "😊", "😇", "😡", "🎃", "😍", "✅", "🔪", "🗒",
]


def _alphabet(rotation):
    offset = int(rotation or 0) % len(EMOJIS)
    return EMOJIS[offset:] + EMOJIS[:offset]


def _aes_passphrase(data, password, salt, decode=False):
    from Crypto.Cipher import AES

    material = evp_bytes_to_key(password, salt, 48)
    cipher = AES.new(material[:32], AES.MODE_CBC, material[32:])
    return _unpad(cipher.decrypt(data), 16, "pkcs7") if decode else cipher.encrypt(_pad(data, 16, "pkcs7"))


def emoji_aes_factory(password, rotation="", decode=False):
    password = bytes.fromhex(password[1:])
    alphabet = _alphabet(rotation)
    to_emoji = dict(zip(BASE64_ALPHABET, alphabet))
    to_base64 = dict(zip(alphabet, BASE64_ALPHABET))

    def code(text, errors="strict"):
        if decode:
            encoded = "".join(to_base64[char] for char in ensure_str(text) if char in to_base64)
            envelope = base64.b64decode(encoded)
            if not envelope.startswith(b"Salted__") or len(envelope) < 32:
                raise ValueError("Emoji-AES input is not a CryptoJS salted envelope")
            return _aes_passphrase(envelope[16:], password, envelope[8:16], True), len(ensure_str(text))
        salt = os.urandom(8)
        envelope = base64.b64encode(b"Salted__" + salt + _aes_passphrase(b(text), password, salt)).decode()
        result = "".join(to_emoji[char] for char in envelope)
        return result, len(b(text))
    return code


def emoji_aes_encode(password, rotation=""):
    return emoji_aes_factory(password, rotation)


def emoji_aes_decode(password, rotation=""):
    return emoji_aes_factory(password, rotation, True)


add("emoji_aes", emoji_aes_encode, emoji_aes_decode,
    r"^emoji[-_]?aes[-_](h(?:[0-9a-fA-F]{2})+)(?:[-_](\d+))?$", aliases=["emoji-aes"])
