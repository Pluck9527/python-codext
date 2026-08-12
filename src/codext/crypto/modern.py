# -*- coding: UTF-8 -*-
"""Keyed RC4, DES, 3DES and AES codecs for CTF byte payloads."""
import base64

from ..__common__ import add, b, ensure_str


def _material(token):
    token = str(token)
    if token.startswith("h"):
        return bytes.fromhex(token[1:])
    raise ValueError("key and IV parameters must use h<hex> notation")


def _decode_data(text, output):
    value = ensure_str(text).strip()
    return bytes.fromhex(value) if output == "hex" else base64.b64decode(value, validate=True)


def _encode_data(data, output):
    return data.hex() if output == "hex" else base64.b64encode(data).decode()


def _pad(data, block_size, padding):
    if padding == "none":
        if len(data) % block_size:
            raise ValueError("input length must be a multiple of the block size with no padding")
        return data
    if padding == "zero":
        return data + b"\0" * (-len(data) % block_size)
    length = block_size - len(data) % block_size
    return data + bytes((length,)) * length


def _unpad(data, block_size, padding):
    if padding == "none":
        return data
    if padding == "zero":
        return data.rstrip(b"\0")
    if not data or data[-1] == 0 or data[-1] > block_size or data[-data[-1]:] != bytes((data[-1],)) * data[-1]:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-data[-1]]


def _block_factory(algorithm, mode, key, iv="", output="", padding="", decode=False):
    key, iv = _material(key), _material(iv) if iv else b""
    output, padding = str(output or "b64"), str(padding or "pkcs7")
    block_size = 16 if algorithm == "aes" else 8

    def code(text, errors="strict"):
        from Crypto.Cipher import AES, DES, DES3

        module = {"aes": AES, "des": DES, "3des": DES3}[algorithm]
        mode_value = module.MODE_ECB if mode == "ecb" else module.MODE_CBC
        cipher = module.new(key, mode_value, iv=iv) if mode == "cbc" else module.new(key, mode_value)
        if decode:
            result = _unpad(cipher.decrypt(_decode_data(text, output)), block_size, padding)
            return result, len(ensure_str(text))
        result = _encode_data(cipher.encrypt(_pad(b(text), block_size, padding)), output)
        return result, len(b(text))
    return code


def aes_ecb_encode(key, output="", padding=""):
    return _block_factory("aes", "ecb", key, output=output, padding=padding)


def aes_ecb_decode(key, output="", padding=""):
    return _block_factory("aes", "ecb", key, output=output, padding=padding, decode=True)


def aes_cbc_encode(key, iv, output="", padding=""):
    return _block_factory("aes", "cbc", key, iv, output, padding)


def aes_cbc_decode(key, iv, output="", padding=""):
    return _block_factory("aes", "cbc", key, iv, output, padding, True)


def des_ecb_encode(key, output="", padding=""):
    return _block_factory("des", "ecb", key, output=output, padding=padding)


def des_ecb_decode(key, output="", padding=""):
    return _block_factory("des", "ecb", key, output=output, padding=padding, decode=True)


def des_cbc_encode(key, iv, output="", padding=""):
    return _block_factory("des", "cbc", key, iv, output, padding)


def des_cbc_decode(key, iv, output="", padding=""):
    return _block_factory("des", "cbc", key, iv, output, padding, True)


def triple_des_ecb_encode(key, output="", padding=""):
    return _block_factory("3des", "ecb", key, output=output, padding=padding)


def triple_des_ecb_decode(key, output="", padding=""):
    return _block_factory("3des", "ecb", key, output=output, padding=padding, decode=True)


def triple_des_cbc_encode(key, iv, output="", padding=""):
    return _block_factory("3des", "cbc", key, iv, output, padding)


def triple_des_cbc_decode(key, iv, output="", padding=""):
    return _block_factory("3des", "cbc", key, iv, output, padding, True)


def rc4_code(key, output="", decode=False):
    key, output = _material(key), str(output or "b64")
    def code(text, errors="strict"):
        from Crypto.Cipher import ARC4

        source = _decode_data(text, output) if decode else b(text)
        result = ARC4.new(key).encrypt(source)
        return (result if decode else _encode_data(result, output)), len(ensure_str(text))
    return code


def rc4_encode(key, output=""):
    return rc4_code(key, output)


def rc4_decode(key, output=""):
    return rc4_code(key, output, True)


def add_symmetric_codec(name, algorithm, key, mode="ecb", iv=b"", padding="pkcs7", output="b64"):
    algorithm, mode = algorithm.lower(), mode.lower()
    key_token, iv_token = "h" + bytes(key).hex(), "h" + bytes(iv).hex() if iv else ""
    if algorithm == "rc4":
        return add(name, rc4_code(key_token, output), rc4_code(key_token, output, True))
    return add(name, _block_factory(algorithm, mode, key_token, iv_token, output, padding),
               _block_factory(algorithm, mode, key_token, iv_token, output, padding, True))


FORMAT_PADDING = r"(?:[-_](hex|b64))?(?:[-_](pkcs7|zero|none))?"
add("aes_ecb_keyed", aes_ecb_encode, aes_ecb_decode,
    r"^aes[-_]?ecb[-_](h(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64}))" +
    FORMAT_PADDING + "$", aliases=["aes-ecb-keyed"])
add("aes_cbc_keyed", aes_cbc_encode, aes_cbc_decode,
    r"^aes[-_]?cbc[-_](h(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64}))[-_]"
    r"(h[0-9a-fA-F]{32})" + FORMAT_PADDING + "$",
    aliases=["aes-cbc-keyed"])
add("des_ecb_keyed", des_ecb_encode, des_ecb_decode,
    r"^des[-_]?ecb[-_](h[0-9a-fA-F]{16})" + FORMAT_PADDING + "$", aliases=["des-ecb-keyed"])
add("des_cbc_keyed", des_cbc_encode, des_cbc_decode,
    r"^des[-_]?cbc[-_](h[0-9a-fA-F]{16})[-_](h[0-9a-fA-F]{16})" + FORMAT_PADDING + "$",
    aliases=["des-cbc-keyed"])
add("triple_des_ecb_keyed", triple_des_ecb_encode, triple_des_ecb_decode,
    r"^(?:3des|des3|triple[-_]?des)[-_]?ecb[-_](h(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48}))" +
    FORMAT_PADDING + "$",
    aliases=["3des-ecb-keyed"])
add("triple_des_cbc_keyed", triple_des_cbc_encode, triple_des_cbc_decode,
    r"^(?:3des|des3|triple[-_]?des)[-_]?cbc[-_](h(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48}))[-_]"
    r"(h[0-9a-fA-F]{16})" +
    FORMAT_PADDING + "$", aliases=["3des-cbc-keyed"])
add("rc4_keyed", rc4_encode, rc4_decode,
    r"^rc4[-_](h(?:[0-9a-fA-F]{2})+)(?:[-_](hex|b64))?$", aliases=["rc4-keyed"])
