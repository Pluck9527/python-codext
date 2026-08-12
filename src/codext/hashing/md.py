# -*- coding: UTF-8 -*-
"""MD Hashing Codecs - string hashing with Message Digest (MD).

These are codecs for hashing strings, for use with other codecs in encoding chains.

These codecs:
- transform strings from str to str
- transform strings from bytes to bytes
- transform file content from str to bytes (write)
"""
from ..__common__ import *


MD2_TABLE = [41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199, 115, 140,
    152, 147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18, 190,
    78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 148,
    194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48,
    179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107,
    226, 156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27, 96, 37, 173,
    174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186,
    197, 234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193,
    171, 250, 36, 225, 123, 8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29,
    57, 242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26,
    219, 153, 141, 51, 159, 17, 131, 20]


def md2(data):
    # see spec in RFC1319
    bs, buff, rnd, data = 16, 48, 18, bytearray(b(data))
    # first pad the input data
    n = bs - len(data) % bs
    data += bytearray([n for _ in range(n)])
    # then compute the checksum and append it to the data
    checksum, prev, l, lt = bytearray(bs), 0, len(data) // bs, len(MD2_TABLE)
    for i in range(l):
        for j in range(bs):
            curr = data[bs * i + j]
            checksum[j] ^= MD2_TABLE[curr ^ prev]
            prev = checksum[j]
    data += checksum
    # now compute the digest
    digest = bytearray(buff)
    for i in range(l + 1):
        for j in range(bs):
            digest[bs + j] = data[i * bs + j]
            digest[2 * bs + j] = digest[bs + j] ^ digest[j]
        prev = 0
        for j in range(rnd):
            for k in range(buff):
                digest[k] = prev = digest[k] ^ MD2_TABLE[prev]
            prev = (prev + j) % lt
    return "".join("{:02x}".format(x) for x in digest[:16])


DEFAULT_MD5_WORDS = (
    "admin", "password", "123456", "12345678", "123456789", "1234567890", "qwerty", "abc123", "111111",
    "123123", "000000", "iloveyou", "dragon", "monkey", "letmein", "welcome", "root", "toor", "test",
    "guest", "flag", "ctf", "admin123", "password1", "1q2w3e4r", "qwerty123",
)


def _md5_format_factory(length="", case=""):
    def encode(text, errors="strict"):
        result = hashlib.md5(b(text)).hexdigest()
        result = result[8:24] if str(length) == "16" else result
        result = result.upper() if case == "upper" else result.lower()
        return result, len(b(text))
    return encode


def md5_format_encode(length="", case="", standalone_case=""):
    return _md5_format_factory(length, case or standalone_case)


def crack_md5(digest, candidates=None):
    """Return the first candidate matching a 16- or 32-character MD5 digest."""
    target = ensure_str(digest).strip().lower()
    if not re.fullmatch(r"(?:[0-9a-f]{16}|[0-9a-f]{32})", target):
        raise ValueError("MD5 digest must contain 16 or 32 hexadecimal characters")
    words = DEFAULT_MD5_WORDS if candidates is None else candidates
    for candidate in words:
        source = ensure_str(candidate).rstrip("\r\n")
        value = hashlib.md5(b(source)).hexdigest()
        if value == target or value[8:24] == target:
            return source
    return None


def md5_crack_decode(text, errors="strict"):
    source = ensure_str(text)
    lines = source.splitlines()
    if not lines:
        raise ValueError("MD5 cracking input is empty")
    result = crack_md5(lines[0], lines[1:] or None)
    if result is None:
        raise ValueError("MD5 digest was not found in the supplied dictionary")
    return result, len(source)


add("md2", lambda s, error="strict": (md2(s), len(s)), guess=None)
add("md5", lambda s, error="strict": (hashlib.new("md5", b(s)).hexdigest(), len(s)), guess=None)
add("md5_format", md5_format_encode, None,
    r"^(?:md5[-_](16)(?:[-_](upper|lower))?|md5[-_](upper|lower)|md5[-_]format)$", guess=None)
add("crack_md5", None, md5_crack_decode, r"^(?:crack[-_]?md5|md5[-_]crack)$", guess=None)
if "md4" in hashlib.algorithms_available:
    add("md4", lambda s, error="strict": (hashlib.new("md4", b(s)).hexdigest(), len(s)), guess=None)
