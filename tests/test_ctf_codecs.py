#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""Regression tests for the CTF-oriented codecs."""
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
