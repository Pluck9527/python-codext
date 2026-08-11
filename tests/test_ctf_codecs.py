#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""Regression tests for the CTF-oriented codecs."""
import json
from unittest import TestCase

import codext
from codext.__common__ import codecs
from codext.crypto.emoji_aes import BASE64_ALPHABET, EMOJIS


class TestCtfCodecs(TestCase):
    def roundtrip(self, text, encoding):
        encoded = codecs.encode(text, encoding)
        self.assertEqual(codecs.decode(encoded, encoding), text)
        self.assertEqual(codecs.decode(codecs.encode(text.encode(), encoding), encoding), text.encode())
        return encoded

    def test_base92(self):
        self.assertEqual(self.roundtrip("flag", "base92"), "F#S<I")
        self.assertEqual(codecs.encode("", "base92"), "~")

    def test_base2048(self):
        self.assertEqual(self.roundtrip("flag", "base2048"), "ڥڊװ")

    def test_base65536_and_guide_alias(self):
        self.assertEqual(self.roundtrip("flag", "base65536"), "ꍦ鱡")
        self.assertEqual(codecs.decode("ꍦ鱡", "base65535"), "flag")

    def test_base64_stego_decode(self):
        self.assertEqual(codecs.decode("QU==\nQR==", "base64-stego"), "A")
        self.assertRaises(NotImplementedError, codecs.encode, "A", "base64-stego")

    def test_zero_width(self):
        self.roundtrip("flag{零宽}", "zero-width")

    def test_hill(self):
        self.assertEqual(codecs.encode("HELP", "hill-3,3,2,5"), "HIAT")
        self.assertEqual(codecs.decode("HIAT", "hill-3,3,2,5"), "HELP")
        self.assertRaises(LookupError, codecs.encode, "HELP", "hill-2,4,2,4")

    def test_gronsfeld(self):
        self.assertEqual(self.roundtrip("HELLO", "gronsfeld-31415"), "KFPMT")

    def test_vigenere_url_key(self):
        encoding = "vigenere-key-h" + "http://www.verymuch.net".encode().hex()
        self.roundtrip("ATTACK AT DAWN", encoding)
        codext.add_vigenere_codec("vigenere-url-test", "http://www.verymuch.net")
        self.roundtrip("flag{url_key}", "vigenere-url-test")

    def test_cloud_shadow(self):
        self.assertEqual(self.roundtrip("FLAG", "cloud-shadow"), "42084010421")

    def test_xxencode(self):
        self.assertEqual(self.roundtrip("flag", "xxencode"), "2NalVNk++")

    def test_pgp_word_list(self):
        self.assertEqual(self.roundtrip("flag", "pgp-word-list"),
                         "framework handiwork fallout graduate")
        self.assertRaises(ValueError, codecs.decode, "handiwork framework", "pgp-word-list")

    def test_core_values(self):
        self.roundtrip("flag{核心价值观}", "core-values")

    def test_chinese_telegraph(self):
        encoded = codecs.encode("中文信息", "chinese-telegraph")
        self.assertEqual(encoded, "0022 2429 0207 1873")
        self.assertEqual(codecs.decode(encoded, "chinese-telegraph"), "中文信息")
        self.assertEqual(codecs.decode("5337 5337 2448 2448 0001 2448 0001 2161 1721 1869 6671",
                                       "chinese-telegraph"), "艾艾斯斯一斯一括弧恩达")
        self.assertEqual(codecs.decode("5618 1947 0948", "chinese-telegraph-mainland"), "萧爱国")
        self.assertEqual(codecs.decode("5618 1947 0948", "chinese-telegraph-taiwan"), "蕭愛國")

    def test_enigma(self):
        self.assertEqual(self.roundtrip("HELLOWORLD", "enigma"), "ILBDAAMTAZ")
        encoding = "enigma-iv.ii.i-c-lfp-hrq-hr.qp.fz.sw.eu"
        self.assertEqual(self.roundtrip("HELLOWORLD", encoding), "CTTOJBSHRV")

    def test_quoted_printable_and_unicode_escape(self):
        self.assertEqual(self.roundtrip("flag{中文}", "quoted-printable"),
                         "flag{=E4=B8=AD=E6=96=87}")
        self.assertEqual(self.roundtrip("flag{中文}", "unicode-escape"),
                         r"flag{\u4e2d\u6587}")
        self.assertEqual(codecs.decode(r"\u4e2d+U6587 &#x1F600;", "unicode-escape"), "中文 😀")

    def test_text_encoding_bruteforce_and_mojibake(self):
        candidates = json.loads(codecs.decode("涓枃", "text-encoding-brute-force"))
        self.assertEqual(candidates[0]["text"], "中文")
        self.assertIn("中文", [candidate["text"] for candidate in candidates])
        self.assertEqual(codecs.decode("涓枃", "mojibake-gbk"), "中文")
        self.assertEqual(codecs.decode("锟斤拷", "mojibake-gbk"), "��")
        recursive = json.loads(codecs.decode("æµè¯", "text-encoding-brute-force"))
        self.assertEqual(recursive[0]["text"], "测试")
        self.assertEqual(recursive[0]["depth"], 1)

    def test_brainfuck_and_ook(self):
        self.roundtrip("flag", "brainfuck")
        self.roundtrip("flag", "ook")
        self.roundtrip("flag", "short-ook")
        self.assertEqual(codecs.decode("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.", "brainfuck"), "A")
        self.assertEqual(codecs.decode(",.", "brainfuck"), "\x00")

    def test_aaencode(self):
        encoded = self.roundtrip("console.log('中文😀')", "aaencode")
        self.assertTrue(encoded.startswith("ﾟωﾟﾉ="))
        self.assertTrue(encoded.endswith("(ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');"))

    def test_decabit(self):
        self.assertEqual(self.roundtrip("DECA", "decabit"),
                         "-+-++++--- ++-+--+-+- +--++++--- ++-+++----")

    def test_sms_pdu(self):
        expected = "0001000B813108108300F000080C4F60597D0066006C00610067"
        self.assertEqual(codecs.encode("你好flag", "sms-pdu-13800138000"), expected)
        self.assertEqual(codecs.decode(expected, "sms-pdu"), "你好flag")
        guide = ("0001000D91683106019196F400087200380039003500300034004500340037003000440030004100310041003000410030"
                 "003000300030003000300030004400340039003400380034003400350032003000300030003000300030003400370030"
                 "00300030003000300030003800300038003000320030003000300030")
        self.assertTrue(codecs.decode(guide, "sms-pdu").startswith("89504E470D0A1A0A"))
        gsm7 = self.roundtrip("flag{GSM7^€}", "sms-pdu-gsm7-13800138000")
        self.assertIn("00", gsm7)
        multipart = codecs.encode("A" * 170, "sms-pdu-gsm7-13800138000")
        self.assertEqual(len(multipart.splitlines()), 2)
        self.assertEqual(codecs.decode("\n".join(reversed(multipart.splitlines())), "sms-pdu-batch"), "A" * 170)

    def test_differential_manchester(self):
        self.assertEqual(self.roundtrip("A", "differential-manchester"), "1001010101010110")
        self.roundtrip("flag", "differential-manchester-inverted")
        self.assertRaises(ValueError, codecs.decode, "00" * 8, "differential-manchester")

    def test_snow(self):
        encoded = self.roundtrip("flag{SNOW}", "snow")
        self.assertIn("\t", encoded)
        self.roundtrip("this is a compressed flag", "snow-compressed")
        self.roundtrip("flag{SNOW_PASSWORD}", "snow-compressed-p-h70617373")

    def test_whitespace_language(self):
        encoded = self.roundtrip("flag{ws}", "whitespace-lang")
        self.assertEqual(set(encoded), {" ", "\t", "\n"})
        self.roundtrip("flag", "whitespace")
        program = "   \n" + "\t\n\t " + "   \n" + "\t\t\t" + "\t\n  " + "\n\n\n"
        self.assertEqual(codext.run_whitespace(program, b"A"), b"A")
        self.assertEqual(codecs.decode(program, "whitespace-lang-input-h41"), "A")

    def test_rc4_des_aes(self):
        rc4 = "VWap58FvOtV1VNlmdcyKiaNVhPsWQRFYqt/duezhcddcVXmz5zhQyoc7"
        self.assertEqual(codecs.decode(rc4, "rc4-h3230323530363036-b64"),
                         "flag{edb99a94-f84d-e175-8a7d-e7f658789447}")
        aes = "aes-ecb-h000102030405060708090a0b0c0d0e0f-hex-none"
        self.assertEqual(codecs.encode(bytes.fromhex("00112233445566778899aabbccddeeff"), aes),
                         b"69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(codecs.decode("69c4e0d86a7b0430d8cdb78070b4c55a", aes),
                         bytes.fromhex("00112233445566778899aabbccddeeff").decode("latin-1"))
        self.roundtrip("flag{DES}", "des-cbc-h3132333435363738-h3132333435363738-b64-pkcs7")
        self.roundtrip("flag{3DES}", "3des-ecb-h31323334353637386162636465666768-b64-pkcs7")

    def test_sm_series(self):
        self.assertEqual(codecs.encode("abc", "sm3"),
                         "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
        vector = "sm4-ecb-h0123456789abcdeffedcba9876543210-hex-none"
        self.assertEqual(codecs.encode(bytes.fromhex("0123456789abcdeffedcba9876543210"), vector),
                         b"681edf34d206965e86b3e94f536e4246")
        private_key, public_key = codext.generate_sm2_keypair()
        codext.add_sm2_codec("sm2-test", private_key, public_key)
        self.roundtrip("flag{SM2}", "sm2-test")

    def test_rabbit_and_emoji_aes(self):
        rabbit = "rabbit-h000102030405060708090a0b0c0d0e0f-h1011121314151617-hex"
        self.assertEqual(codecs.encode(bytes.fromhex("000102030405060708090a0b0c0d0e0f"), rabbit),
                         b"637b9392d8a9514c5f6aca776eb4bef7")
        self.roundtrip("flag{rabbit-pbe}", "rabbit-pbe-h70617373776f7264")
        cryptojs = "U2FsdGVkX18c9MGq6/oPxxMSsCNS4T3KdigW1XPUZrs="
        emoji = "".join(dict(zip(BASE64_ALPHABET, EMOJIS))[char] for char in cryptojs)
        self.assertEqual(codecs.decode(emoji, "emoji-aes-h7468317369734b6579"), "flag{emoji}")
        self.roundtrip("flag{emoji-aes}", "emoji-aes-h7468317369734b6579")

    def test_adfgx_and_substitution_tools(self):
        self.roundtrip("attackatonce", "adfgx-german")
        self.roundtrip("attackat1200", "adfgvx-german")
        key = "phqgiumeaylnofdxkrcvstzwbj"
        self.roundtrip("flag", "substitution-h" + key.encode().hex())
        report = json.loads(codecs.decode("AAA bb c", "frequency-analysis"))
        self.assertEqual(report["letters"][0], {"char": "a", "count": 3, "percent": 50.0})

    def test_keyboard_and_chinese_niche(self):
        self.assertEqual(codecs.encode("QAZIJCV", "keyboard-coordinates"), "11 21 31 18 27 33 34")
        self.assertEqual(codecs.decode("11 21 31 18 27 33 34", "keyboard-coordinates"), "qazijcv")
        self.assertEqual(codecs.decode("999 666 88 2 777 33 888 33 777 999 4 666 666 3", "phone-t9"),
                         "youareverygood")
        self.roundtrip("DASCTF", "dvorak")
        self.assertEqual(codecs.decode("王夫 井工 夫口 由中人 井中 夫夫 由中大", "pawnshop"),
                         "67 84 70 123 82 77 125")
        self.roundtrip("flag{}", "chinese-strokes")

    def test_vbe_and_twitter_secret(self):
        vbe = "#@~^HAAAAA==W^lLyPb/P@#@&4*.2{W!!x[mFC&|0AcAAA==^#~@"
        self.assertEqual(codecs.decode(vbe, "vbe"), "flag2 is \r\nh4V3_f0und_7H3_")
        cover = "This is ordinary cover text with enough ASCII characters. " * 4
        hidden = codext.hide_twitter_secret(cover, "flag test")
        self.assertEqual(codext.reveal_twitter_secret(hidden), "flag test")
        self.assertNotEqual(hidden, cover)
