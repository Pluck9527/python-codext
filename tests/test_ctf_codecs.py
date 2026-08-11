#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""Regression tests for the CTF-oriented codecs."""
import json
from unittest import TestCase

from codext.__common__ import codecs


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

    def test_differential_manchester(self):
        self.assertEqual(self.roundtrip("A", "differential-manchester"), "1001010101010110")
        self.roundtrip("flag", "differential-manchester-inverted")
        self.assertRaises(ValueError, codecs.decode, "00" * 8, "differential-manchester")

    def test_snow(self):
        encoded = self.roundtrip("flag{SNOW}", "snow")
        self.assertIn("\t", encoded)
        self.roundtrip("this is a compressed flag", "snow-compressed")

    def test_whitespace_language(self):
        encoded = self.roundtrip("flag{ws}", "whitespace-lang")
        self.assertEqual(set(encoded), {" ", "\t", "\n"})
        self.roundtrip("flag", "whitespace")
