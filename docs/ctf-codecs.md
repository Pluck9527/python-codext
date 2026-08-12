# CTF-oriented codecs

This fork adds codecs required by the Chinese CTF Misc workflow while preserving CodExt's registry and chaining model.

| Codec | Example name | Notes |
|---|---|---|
| Base92 | `base92` | Compatible with thenoviceoof/base92; `flag` encodes to `F#S<I`. |
| Base1024 / Ecoji | `base1024`, `ecoji` | Apache-licensed Ecoji Base1024 repertoire; `flag` encodes to `👪😑🌟🙋`. |
| Base2048 | `base2048` | Uses qntm's Base2048 repertoire. |
| Base65536 | `base65536`, `base65535` | Uses qntm's repertoire; `base65535` is a guide-compatible alias. |
| Base64 padding steganography | `base64-stego`, `hide_base64_padding(...)` | Round-trip generated carriers plus caller-supplied Base64 carrier lines; decoded carrier bytes remain unchanged. |
| Custom-alphabet Base64 | `add_custom_base64(alphabet, name)` | Registers a named codec from exactly 64 unique non-padding, non-whitespace characters. |
| MD5 CTF helpers | `md5-16[-upper]`, `md5-upper`, `crack-md5` | 16/32-character case variants plus built-in or caller-supplied dictionary lookup through `crack_md5(...)`. |
| Zero-width steganography | `zero-width` | U+200B/U+200C bits separated by U+200D. |
| Hill | `hill-3,3,2,5`, `hill-GYBNQKURP` | Any invertible square matrix from 2x2 through 6x6, supplied as integers or letters. |
| Gronsfeld | `gronsfeld-31415` | Numeric repeating key. |
| Music symbols | `music-symbol` | Offline CTF music-symbol mapping with its `§=` terminator. |
| Vigenere arbitrary key | `vigenere-key-h687474703a2f2f...`, `add_vigenere_codec(...)` | Hex parameter/runtime registration accepts URL keys; punctuation is ignored and ASCII letters form the key stream. |
| Cloud shadow | `cloud-shadow` | Also registered as `yunying`. |
| XXencode | `xxencode` | Binary-to-text encoding with 45-byte lines. |
| PGP word list | `pgp-word-list` | Enforces alternating even/odd word lists. |
| Core values | `core-values` | Chinese socialist core-values hexadecimal mapping. |
| Chinese Telegraph Code | `chinese-telegraph[-mainland|-taiwan]` | Fixed `zhtelecode==0.1.0` codebooks. |
| Enigma I | `enigma-iv.ii.i-c-lfp-hrq-hr.qp.fz.sw.eu` | Rotors, reflector, positions, rings and plugboard are encoded in the name. |
| Text encoding brute force | `text-encoding-brute-force` | Recursive breadth-first repair (depth 3); returns ranked JSON with the full conversion path. |
| Mojibake repair | `mojibake-gbk` | Reverses common UTF-8-as-GB18030 mojibake, including the `锟斤拷` replacement symptom. |
| Quoted-Printable | `quoted-printable`, `qp` | UTF-8 payloads through Python's MIME-compatible Quoted-Printable implementation. |
| Unicode escapes | `unicode-escape` | Supports `\\u`, `\\U`, `\\x`, `U+`, `+U`, decimal and hexadecimal HTML entities. |
| Brainfuck / Ook! | `brainfuck`, `ook`, `short-ook` | Bounded interpreter, bracket validation and standard/short Ook token pairs. |
| AAEncode | `aaencode` | Emits executable AAEncoded JavaScript and decodes it without evaluating JavaScript. |
| Decabit | `decabit` | Complete 0-126 ten-pulse table; `DECA` matches the guide example. |
| DNA | `dna1` through `dna8`, `dna-triplet` | Eight complementary-pairing maps plus the guide's three-nucleotide 63-character table. |
| SMS PDU | `sms-pdu[-DESTINATION]`, `sms-pdu-gsm7-DESTINATION`, `sms-pdu-8bit-DESTINATION`, `sms-pdu-info` | SUBMIT/DELIVER/status-report, GSM-7/8-bit/UCS-2, 8/16-bit concatenation, application ports, national-shift UDH metadata and multipart reassembly. |
| Differential Manchester | `differential-manchester[-inverted]` | Start-of-bit rule plus mandatory mid-bit transition validation. |
| SNOW whitespace steganography | `snow`, `snow-compressed`, `snow-compressed-p-h70617373` | stegsnow-compatible bit order, `-C` Huffman and `-p` ICE-CFB password mode. |
| Whitespace language | `whitespace-lang`, `whitespace-lang-input-h41` | Bounded interpreter with stack, arithmetic, heap, flow-control and byte/number input. |
| AES / DES / 3DES | `aes-cbc-hKEY-hIV-b64-pkcs7` | ECB/CBC, hex/Base64, PKCS#7/zero/no padding; keys and IVs use hex parameters. |
| RC4 | `rc4-hKEY-b64` | Keyed RC4 with hex or Base64 ciphertext. |
| SM2 / SM3 / SM4 / SM9 | `sm3`, `sm4-ecb-hKEY-hex-none`, `add_sm2_codec(...)` | SM3, SM4, SM2 encryption plus SM2 and identity-based SM9 key generation, signing and verification helpers/codecs. |
| Rabbit | `rabbit-hKEY-hIV-hex`, `rabbit-pbe-hPASSWORD` | Raw Rabbit plus CryptoJS/OpenSSL `Salted__` passphrase envelopes. |
| Emoji-AES | `emoji-aes-hPASSWORD[-ROTATION]` | Compatible with the original CryptoJS Emoji-AES alphabet and optional rotation. |
| ADFGX / ADFGVX | `adfgx-german`, `adfgvx-german` | Guide default squares; optional custom square as `h<UTF-8-hex>`. |
| Substitution analysis | `frequency-analysis`, `quipqiup`, `substitution-hALPHABET` | English quadgram simulated annealing, ranked local candidates and explicit monoalphabetic keys; no service call. |
| Key recovery | `crack-vigenere`, `hill-crack`, `hill-recover-3`, `enigma-crack[-CRIB]` | Vigenere frequency recovery, exhaustive 2x2 Hill, known-plaintext NxN Hill and bounded Enigma rotor-position search. |
| Keyboard encodings | `keyboard-coordinates`, `keyboard-qwe`, `keyboard-symbol-shift`, `phone-26`, `phone-t9-coordinate` | Coordinates, QWE remapping, repeated-symbol vertical movement, 26-key conversion and both T9 token conventions. |
| Numeric tap code | `tap-numeric` | Accepts and emits guide-style `5,2 3,1 ...` row/column pairs. |
| Chinese ASCII | `chinese-ascii`, `unicode-decimal` | Decimal Unicode code points and decimal/hex HTML entities. |
| Chinese niche encodings | `pinyin-tone`, `pawnshop`, `chinese-strokes` | Tone-derived ASCII, pawnshop digits and the guide's 1-12 stroke table. |
| VBE | `vbe` | Microsoft Script Encoder-compatible encoding and multi-block decoding without script execution. |
| Twitter Secret Messages | `twitter-secret` | Compatible Unicode homoglyph steganography; helpers accept separate cover and secret strings. |
| Spammimic | `spammimic`, `spammimic-online` | Deterministic UTF-8/CRC-protected offline spam cover; the separately named online adapter remains for the official proprietary grammar. |

```python
import codext

alphabet = "/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
codext.add_custom_base64(alphabet, "base64-ctf")
plaintext = codext.decode("i5qMi/==", "base64-ctf")
```

All codecs work through `codext.encode`, `codext.decode`, the CLI registry and codec chains. Chinese Telegraph Code uses Mainland/Taiwan codebooks derived from Unicode Unihan mappings.

Examples for the new CTF batch:

```python
import json
import codext

candidates = json.loads(codext.decode("涓枃", "text-encoding-brute-force"))
assert any(candidate["text"] == "中文" for candidate in candidates)

pdu = codext.encode("你好flag", "sms-pdu-13800138000")
assert codext.decode(pdu, "sms-pdu") == "你好flag"

carrier = codext.encode("flag{SNOW}", "snow-compressed")
assert codext.decode(carrier, "snow-compressed") == "flag{SNOW}"

aes = "aes-cbc-h30313233343536373839616263646566-h66656463626139383736353433323130-b64-pkcs7"
assert codext.decode(codext.encode("flag{AES}", aes), aes) == "flag{AES}"

hidden = codext.hide_twitter_secret("This is a sufficiently long ASCII cover. " * 4, "flag-test")
assert codext.reveal_twitter_secret(hidden) == "flag-test"

assert codext.decode("5,2 3,1 3,1 3,2", "tap-numeric") == "wllm"
assert codext.decode("ooo yyy ii", "phone-26") == "you"
assert codext.decode("20013 25991", "chinese-ascii") == "中文"

private_key, public_key = codext.generate_sm2_signing_keypair()
signature = codext.sm2_sign("flag{SM2}", private_key)
assert codext.sm2_verify("flag{SM2}", signature, public_key)

master_secret, master_public, user_key = codext.generate_sm9_signing_keys("alice@example.com")
signature = codext.sm9_sign("flag{SM9}", "alice@example.com", master_public, user_key)
assert codext.sm9_verify("flag{SM9}", signature, "alice@example.com", master_public)
```

`snow-compressed` corresponds to SNOW's `-C` mode. Password-bearing names append `-p-h<password bytes in hex>`. `whitespace-lang` executes at most 1,000,000 instructions; the plain codec supplies an empty input channel and the `-input-h...` form supplies exact input bytes. Dynamic crypto parameters deliberately use `h<hex>` so URLs, punctuation and binary keys remain unambiguous.

Sources: thenoviceoof/base92 (MIT), Ecoji (Apache-2.0), qntm/base2048 and qntm/base65536 (MIT), the PGPfone word list, zhtelecode 0.1.0 (MIT), gmalg (MIT), 3GPP TS 23.038/23.040, the original AAEncode implementation, Ascetics/ctfkit's reverse-engineered CTF music map, dCode's Decabit table, stegsnow's Apache-2.0 whitespace/Huffman/ICE implementation, CryptoJS Rabbit/AES formats, the Emoji-AES project, Didier Stevens' public-domain VBE decoder and Twitter Secret Messages' published homoglyph table. The local English quadgram model is derived from Project Gutenberg eBook 11, which is public domain in the United States.
