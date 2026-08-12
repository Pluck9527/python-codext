# -*- coding: UTF-8 -*-
"""DNA Codec - dna content encoding.

This implements the 8 methods of ATGC nucleotides following the rule of complementary pairing, according the literature4
 about coding and computing of DNA sequences.

This codec:
- en/decodes strings from str to str
- en/decodes strings from bytes to bytes
- decodes file content to str (read)
- encodes file content from str to bytes (write)
"""
from ..__common__ import *


__examples__ = {
    'enc(dna0|dna9)': None,
    'enc(dna1)':      {'this is a test': "GTGAGCCAGCCGGTATACAAGCCGGTATACAAGCAGACAAGTGAGCGGGTATGTGA"},
    'enc(dna-2)':     {'this is a test': "CTCACGGACGGCCTATAGAACGGCCTATAGAACGACAGAACTCACGCCCTATCTCA"},
    'enc(dna_3)':     {'this is a test': "ACAGATTGATTAACGCGTGGATTAACGCGTGGATGAGTGGACAGATAAACGCACAG"},
    'enc(dna4)':      {'this is a test': "AGACATTCATTAAGCGCTCCATTAAGCGCTCCATCACTCCAGACATAAAGCGAGAC"},
    'enc(dna-5)':     {'this is a test': "TCTGTAAGTAATTCGCGAGGTAATTCGCGAGGTAGTGAGGTCTGTATTTCGCTCTG"},
    'enc(dna_6)':     {'this is a test': "TGTCTAACTAATTGCGCACCTAATTGCGCACCTACTCACCTGTCTATTTGCGTGTC"},
    'enc(dna7)':      {'this is a test': "GAGTGCCTGCCGGATATCTTGCCGGATATCTTGCTGTCTTGAGTGCGGGATAGAGT"},
    'enc(dna-8)':     {'this is a test': "CACTCGGTCGGCCATATGTTCGGCCATATGTTCGTCTGTTCACTCGCCCATACACT"},
}
__guess__ = ["dna%d" % i for i in range(1, 9)]


SEQUENCES = {
    '00': "AAGCGCTT",
    '11': "TTCGCGAA",
    '01': "GCAATTGC",
    '10': "CGTTAACG",
}
ENCMAP = []
for i in range(8):
    ENCMAP.append({k: v[i] for k, v in SEQUENCES.items()})


TRIPLETS = [left + middle + right for left in "ACGT" for middle in "ACGT" for right in "ACGT"]
TRIPLET_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 "
TRIPLET_ENCODE = dict(zip(TRIPLET_ALPHABET, TRIPLETS))
TRIPLET_DECODE = {value: key for key, value in TRIPLET_ENCODE.items()}


def dna_triplet_encode(text, errors="strict"):
    source = ensure_str(text)
    try:
        result = "".join(TRIPLET_ENCODE[char] for char in source)
    except KeyError as error:
        raise ValueError("dna-triplet supports ASCII letters, digits and spaces") from error
    return result, len(source)


def dna_triplet_decode(text, errors="strict"):
    source = re.sub(r"\s+", "", ensure_str(text)).upper()
    if len(source) % 3 or re.fullmatch(r"[ACGT]*", source) is None:
        raise ValueError("dna-triplet requires A/C/G/T groups of three")
    try:
        result = "".join(TRIPLET_DECODE[source[index:index + 3]] for index in range(0, len(source), 3))
    except KeyError as error:
        raise ValueError("unsupported dna-triplet group %s" % error.args[0]) from error
    return result, len(source)


add_map("dna", ENCMAP, intype="bin", pattern=r"dna[-_]?([1-8])$", entropy=2., printables_rate=1., expansion_factor=4.)
add("dna_triplet", dna_triplet_encode, dna_triplet_decode, r"^dna[-_](?:triplet|genetic|ctf)$",
    aliases=["dna-triplet"])

