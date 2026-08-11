# CTF-oriented codecs

This fork adds codecs required by the Chinese CTF Misc workflow while preserving CodExt's registry and chaining model.

| Codec | Example name | Notes |
|---|---|---|
| Base92 | `base92` | Compatible with thenoviceoof/base92; `flag` encodes to `F#S<I`. |
| Base2048 | `base2048` | Uses qntm's Base2048 repertoire. |
| Base65536 | `base65536`, `base65535` | Uses qntm's repertoire; `base65535` is a guide-compatible alias. |
| Base64 padding steganography | `base64-stego` | Decode-only because encoding requires independent carrier lines. |
| Custom-alphabet Base64 | `add_custom_base64(alphabet, name)` | Registers a named codec from exactly 64 unique non-padding, non-whitespace characters. |
| Zero-width steganography | `zero-width` | U+200B/U+200C bits separated by U+200D. |
| Hill | `hill-3,3,2,5` | 2x2 matrix key encoded in the codec name. |
| Gronsfeld | `gronsfeld-31415` | Numeric repeating key. |
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
| SMS PDU | `sms-pdu[-DESTINATION]`, `sms-pdu-gsm7-DESTINATION`, `sms-pdu-batch` | SMS-SUBMIT/DELIVER, numeric/alphanumeric addresses, GSM-7 extensions, UCS-2 and UDH multipart reassembly. |
| Differential Manchester | `differential-manchester[-inverted]` | Start-of-bit rule plus mandatory mid-bit transition validation. |
| SNOW whitespace steganography | `snow`, `snow-compressed`, `snow-compressed-p-h70617373` | stegsnow-compatible bit order, `-C` Huffman and `-p` ICE-CFB password mode. |
| Whitespace language | `whitespace-lang`, `whitespace-lang-input-h41` | Bounded interpreter with stack, arithmetic, heap, flow-control and byte/number input. |
| AES / DES / 3DES | `aes-cbc-hKEY-hIV-b64-pkcs7` | ECB/CBC, hex/Base64, PKCS#7/zero/no padding; keys and IVs use hex parameters. |
| RC4 | `rc4-hKEY-b64` | Keyed RC4 with hex or Base64 ciphertext. |
| SM2 / SM3 / SM4 | `sm3`, `sm4-ecb-hKEY-hex-none`, `add_sm2_codec(...)` | SM3 hash, SM4 ECB/CBC and runtime SM2 public/private key registration. |
| Rabbit | `rabbit-hKEY-hIV-hex`, `rabbit-pbe-hPASSWORD` | Raw Rabbit plus CryptoJS/OpenSSL `Salted__` passphrase envelopes. |
| Emoji-AES | `emoji-aes-hPASSWORD[-ROTATION]` | Compatible with the original CryptoJS Emoji-AES alphabet and optional rotation. |
| ADFGX / ADFGVX | `adfgx-german`, `adfgvx-german` | Guide default squares; optional custom square as `h<UTF-8-hex>`. |
| Substitution analysis | `frequency-analysis`, `quipqiup`, `substitution-hALPHABET` | JSON statistics, offline hill-climbing and explicit monoalphabetic keys. |
| Keyboard encodings | `keyboard-coordinates`, `phone-t9`, `dvorak`, `qwertz`, `azerty`, `colemak` | PC coordinates, phone multi-tap and physical-layout conversion. |
| Chinese niche encodings | `pinyin-tone`, `pawnshop`, `chinese-strokes` | Tone-derived ASCII, pawnshop digits and the guide's 1-12 stroke table. |
| VBE | `vbe` | Microsoft Script Encoder decoder; extracts one or more `#@~^...^#~@` blocks without execution. |
| Twitter Secret Messages | `twitter-secret` | Compatible Unicode homoglyph steganography; helpers accept separate cover and secret strings. |
| Spammimic | `spammimic-online` | Explicit fixed-host adapter for the proprietary official grammar; invoked on demand and bounded to 64 KiB. |

```python
import codext

alphabet = "/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
codext.add_custom_base64(alphabet, "base64-ctf")
plaintext = codext.decode("i5qMi/==", "base64-ctf")
```

All codecs work through `codext.encode`, `codext.decode`, the CLI registry and codec chains. Base64 padding steganography is intentionally one-way. Chinese Telegraph Code uses Mainland/Taiwan codebooks derived from Unicode Unihan mappings.

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
```

`snow-compressed` corresponds to SNOW's `-C` mode. Password-bearing names append `-p-h<password bytes in hex>`. `whitespace-lang` executes at most 1,000,000 instructions; the plain codec supplies an empty input channel and the `-input-h...` form supplies exact input bytes. Dynamic crypto parameters deliberately use `h<hex>` so URLs, punctuation and binary keys remain unambiguous.

Sources: thenoviceoof/base92 (MIT), qntm/base2048 and qntm/base65536 (MIT), the PGPfone word list, zhtelecode 0.1.0 (MIT), the original AAEncode implementation, dCode's Decabit table, stegsnow's Apache-2.0 whitespace/Huffman/ICE implementation, CryptoJS Rabbit/AES formats, the Emoji-AES project, Didier Stevens' public-domain VBE decoder and Twitter Secret Messages' published homoglyph table.
