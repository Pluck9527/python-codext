# -*- coding: UTF-8 -*-
"""Base2048 and Base65536 Unicode codecs using qntm repertoires."""
from functools import lru_cache

from ..__common__ import *


RANGES = {11: ['89AZazÆÆÐÐØØÞßææððøøþþĐđĦħııĸĸŁłŊŋŒœŦŧƀƟƢƮƱǃǝǝǤǥǶǷȜȝȠȥȴʯͰͳͶͷͻͽͿͿΑΡΣΩαωϏϏϗϯϳϳϷϸϺϿЂЂЄІЈЋЏИКикяђђєіјћџѵѸҁҊӀӃӏӔӕӘәӠӡӨөӶӷӺԯԱՖաֆאתװײؠءاؿفي٠٩ٮٯٱٴٹڿہہۃےەەۮۼۿۿܐܐܒܯݍޥޱޱ߀ߪࠀࠕࡀࡘࡠࡪࢠࢴࢶࢽऄनपरलळवहऽऽॐॐॠॡ०९ॲঀঅঌএঐওনপরললশহঽঽৎৎৠৡ০ৱ৴৹ৼৼਅਊਏਐਓਨਪਰਲਲਵਵਸਹੜੜ੦੯ੲੴઅઍએઑઓનપરલળવહઽઽૐૐૠૡ૦૯ૹૹଅଌଏଐଓନପରଲଳଵହଽଽୟୡ୦୯ୱ୷ஃஃஅஊஎஐஒஓககஙசஜஜஞடணதநபமஹௐௐ௦௲అఌఎఐఒనపహఽఽౘౚౠౡ౦౯౸౾ಀಀಅಌಎಐಒನಪಳವಹಽಽೞೞೠೡ೦೯ೱೲഅഌഎഐഒഺഽഽൎൎൔൖ൘ൡ൦൸ൺൿඅඖකනඳරලලවෆ෦෯กะาาเๅ๐๙ກຂຄຄງຈຊຊຍຍດທນຟມຣລລວວສຫອະາາຽຽເໄ໐໙ໞໟༀༀ༠༳ཀགངཇཉཌཎདནབམཛཝཨཪཬྈྌကဥဧဪဿ၉ၐၕ', '07'], 16: ['㐀䳿一黿ꄀꏿꔀꗿ𐘀𐛿𒀀𒋿𓀀𓏿𔐀𔗿𖠀𖧿𠀀𨗿', 'ᔀᗿ']}


@lru_cache(maxsize=2)
def _tables(bits_per_char):
    repertoires = []
    for encoded in RANGES[bits_per_char]:
        chars = []
        for index in range(0, len(encoded), 2):
            chars.extend(chr(value) for value in range(ord(encoded[index]), ord(encoded[index + 1]) + 1))
        repertoires.append(chars)
    widths = (bits_per_char, bits_per_char - 8)
    lookup = {char: (widths[index], 256 * (value % 256) + (value >> 8)
              if bits_per_char == 16 and index == 0 else value)
              for index, repertoire in enumerate(repertoires) for value, char in enumerate(repertoire)}
    return repertoires, lookup


def _make(bits_per_char, name):
    def encode(text, errors="strict"):
        repertoires, _ = _tables(bits_per_char)
        data, buffer, bits, result = b(text), 0, 0, []
        for byte in data:
            buffer = (buffer << 8) | byte
            bits += 8
            while bits >= bits_per_char:
                value = buffer >> (bits - bits_per_char)
                buffer &= (1 << (bits - bits_per_char)) - 1
                bits -= bits_per_char
                index = 256 * (value % 256) + (value >> 8) if bits_per_char == 16 else value
                result.append(repertoires[0][index])
        if bits:
            widths = (bits_per_char, bits_per_char - 8)
            while bits not in widths:
                buffer = (buffer << 1) | 1
                bits += 1
            result.append(repertoires[widths.index(bits)][buffer])
        return (encoded := "".join(result)), len(encoded)

    def decode(text, errors="strict"):
        text, (_, lookup) = ensure_str(text), _tables(bits_per_char)
        error = handle_error(name, errors, decode=True)
        buffer, bits, result = 0, 0, bytearray()
        for index, char in enumerate(text):
            try:
                width, value = lookup[char]
            except KeyError:
                replacement = error(char, index)
                if replacement:
                    result.extend(b(replacement))
                continue
            if width != bits_per_char and index != len(text) - 1:
                raise ValueError("secondary character found before end of input")
            buffer = (buffer << width) | value
            bits += width
            while bits >= 8:
                result.append(buffer >> (bits - 8))
                buffer &= (1 << (bits - 8)) - 1
                bits -= 8
        if bits and bits_per_char == 11 and buffer != (1 << bits) - 1:
            raise ValueError("padding mismatch")
        return bytes(result), len(text)
    return encode, decode


add("base2048", *_make(11, "base2048"), r"^base[-_]?2048$", expansion_factor=.75)
add("base65536", *_make(16, "base65536"), r"^base[-_]?(?:65535|65536)$", aliases=["base65535"], expansion_factor=.5)
