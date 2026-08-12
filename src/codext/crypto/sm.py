# -*- coding: UTF-8 -*-
"""Chinese commercial cryptography codecs: SM2, SM3 and SM4."""
import base64
import secrets

from ..__common__ import add, b, ensure_str
from .modern import _decode_data, _encode_data, _material, _pad, _unpad


def sm3_encode(text, errors="strict"):
    from gmssl import sm3

    result = sm3.sm3_hash(list(b(text)))
    return result, len(b(text))


def _sm4_factory(mode, key, iv="", output="", padding="", decode=False):
    key, iv = _material(key), _material(iv) if iv else b""
    output, padding = str(output or "b64"), str(padding or "pkcs7")
    if len(key) != 16 or mode == "cbc" and len(iv) != 16:
        raise ValueError("SM4 requires a 16-byte key and CBC requires a 16-byte IV")

    def code(text, errors="strict"):
        from gmssl import sm4

        cipher = sm4.CryptSM4(padding_mode=-1)
        cipher.set_key(key, sm4.SM4_DECRYPT if decode else sm4.SM4_ENCRYPT)
        source = _decode_data(text, output) if decode else _pad(b(text), 16, padding)
        if mode == "ecb":
            result = cipher.crypt_ecb(source)
        else:
            result, previous = bytearray(), iv
            for offset in range(0, len(source), 16):
                block = source[offset:offset + 16]
                transformed = bytes(cipher.one_round(cipher.sk, list(block if decode else
                                    bytes(left ^ right for left, right in zip(block, previous)))))
                result.extend(bytes(left ^ right for left, right in zip(transformed, previous)) if decode else
                              transformed)
                previous = block if decode else transformed
            result = bytes(result)
        result = _unpad(result, 16, padding) if decode else _encode_data(result, output)
        return result, len(ensure_str(text))
    return code


def sm4_ecb_encode(key, output="", padding=""):
    return _sm4_factory("ecb", key, output=output, padding=padding)


def sm4_ecb_decode(key, output="", padding=""):
    return _sm4_factory("ecb", key, output=output, padding=padding, decode=True)


def sm4_cbc_encode(key, iv, output="", padding=""):
    return _sm4_factory("cbc", key, iv, output, padding)


def sm4_cbc_decode(key, iv, output="", padding=""):
    return _sm4_factory("cbc", key, iv, output, padding, True)


def add_sm2_codec(name, private_key="", public_key="", mode=1, output="b64"):
    private_key = private_key[2:] if private_key.startswith("0x") else private_key
    public_key = public_key[2:] if public_key.startswith("0x") else public_key
    public_key = public_key[2:] if public_key.startswith("04") else public_key

    def encode(text, errors="strict"):
        from gmssl import sm2

        if not public_key:
            raise ValueError("SM2 encryption requires a public key")
        result = sm2.CryptSM2(private_key="", public_key=public_key, mode=mode).encrypt(b(text))
        return _encode_data(result, output), len(b(text))

    def decode(text, errors="strict"):
        from gmssl import sm2

        if not private_key:
            raise ValueError("SM2 decryption requires a private key")
        result = sm2.CryptSM2(private_key=private_key, public_key=public_key, mode=mode).decrypt(
            _decode_data(text, output))
        return result, len(ensure_str(text))

    return add(name, encode if public_key else None, decode if private_key else None)


def generate_sm2_keypair():
    from gmssl import sm2

    order = int(sm2.default_ecc_table["n"], 16)
    private_key = "%064x" % (secrets.randbelow(order - 1) + 1)
    engine = sm2.CryptSM2(private_key=private_key, public_key="")
    public_key = engine._kg(int(private_key, 16), sm2.default_ecc_table["g"])
    return private_key, public_key


def generate_sm2_signing_keypair():
    """Return gmalg-compatible SM2 signing keys as hexadecimal strings."""
    from gmalg import SM2

    private_key, public_key = SM2().generate_keypair()
    return private_key.hex(), public_key.hex()


def sm2_sign(message, private_key, uid=b"1234567812345678", output="b64"):
    from gmalg import SM2

    r, s = SM2(sk=bytes.fromhex(private_key), uid=b(uid)).sign(b(message))
    signature = r + s
    return signature.hex() if output == "hex" else base64.b64encode(signature).decode()


def sm2_verify(message, signature, public_key, uid=b"1234567812345678", output="b64"):
    from gmalg import SM2

    value = bytes.fromhex(signature) if output == "hex" else base64.b64decode(signature)
    if len(value) != 64:
        return False
    return SM2(pk=bytes.fromhex(public_key), uid=b(uid)).verify(b(message), value[:32], value[32:])


def generate_sm9_signing_keys(uid):
    """Create an SM9 master pair and a signing private key for an identity."""
    from gmalg import SM9KGC

    identity = b(uid)
    master_secret, master_public = SM9KGC(hid_s=b"\x01").generate_keypair_sign()
    private_key = SM9KGC(hid_s=b"\x01", msk_s=master_secret, mpk_s=master_public).generate_sk_sign(identity)
    return master_secret.hex(), master_public.hex(), private_key.hex()


def sm9_sign(message, identity, master_public, private_key, output="b64"):
    from gmalg import SM9

    h, s = SM9(hid_s=b"\x01", mpk_s=bytes.fromhex(master_public), sk_s=bytes.fromhex(private_key),
               uid=b(identity)).sign(b(message))
    signature = h + s
    return signature.hex() if output == "hex" else base64.b64encode(signature).decode()


def sm9_verify(message, signature, identity, master_public, output="b64"):
    from gmalg import SM9

    value = bytes.fromhex(signature) if output == "hex" else base64.b64decode(signature)
    if len(value) != 97:
        return False
    return SM9(hid_s=b"\x01", mpk_s=bytes.fromhex(master_public), uid=b(identity)).verify(
        b(message), value[:32], value[32:])


def add_sm2_signature_codec(name, private_key="", public_key="", uid="1234567812345678", output="b64"):
    def encode(text, errors="strict"):
        result = sm2_sign(text, private_key, uid.encode(), output)
        return result, len(b(text))

    def decode(text, errors="strict"):
        message, signature = ensure_str(text).splitlines()
        result = str(sm2_verify(message, signature, public_key, uid.encode(), output)).lower()
        return result, len(ensure_str(text))

    return add(name, encode if private_key else None, decode if public_key else None)


def add_sm9_signature_codec(name, identity, master_public, private_key="", output="b64"):
    def encode(text, errors="strict"):
        result = sm9_sign(text, identity, master_public, private_key, output)
        return result, len(b(text))

    def decode(text, errors="strict"):
        message, signature = ensure_str(text).splitlines()
        result = str(sm9_verify(message, signature, identity, master_public, output)).lower()
        return result, len(ensure_str(text))

    return add(name, encode if private_key else None, decode)


FORMAT_PADDING = r"(?:[-_](hex|b64))?(?:[-_](pkcs7|zero|none))?"
add("sm3", sm3_encode, None, r"^sm3(?:[-_]?hash)?$")
add("sm4_ecb_keyed", sm4_ecb_encode, sm4_ecb_decode,
    r"^sm4[-_]?ecb[-_](h[0-9a-fA-F]{32})" + FORMAT_PADDING + "$", aliases=["sm4-ecb-keyed"])
add("sm4_cbc_keyed", sm4_cbc_encode, sm4_cbc_decode,
    r"^sm4[-_]?cbc[-_](h[0-9a-fA-F]{32})[-_](h[0-9a-fA-F]{32})" + FORMAT_PADDING + "$",
    aliases=["sm4-cbc-keyed"])
