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
| Cloud shadow | `cloud-shadow` | Also registered as `yunying`. |
| XXencode | `xxencode` | Binary-to-text encoding with 45-byte lines. |
| PGP word list | `pgp-word-list` | Enforces alternating even/odd word lists. |
| Core values | `core-values` | Chinese socialist core-values hexadecimal mapping. |
| Chinese Telegraph Code | `chinese-telegraph[-mainland|-taiwan]` | Fixed `zhtelecode==0.1.0` codebooks. |
| Enigma I | `enigma-iv.ii.i-c-lfp-hrq-hr.qp.fz.sw.eu` | Rotors, reflector, positions, rings and plugboard are encoded in the name. |
| Text encoding brute force | `text-encoding-brute-force` | Decode-only; returns ranked JSON candidates with source/target encodings. |
| Mojibake repair | `mojibake-gbk` | Reverses common UTF-8-as-GB18030 mojibake, including the `锟斤拷` replacement symptom. |
| Quoted-Printable | `quoted-printable`, `qp` | UTF-8 payloads through Python's MIME-compatible Quoted-Printable implementation. |
| Unicode escapes | `unicode-escape` | Supports `\\u`, `\\U`, `\\x`, `U+`, `+U`, decimal and hexadecimal HTML entities. |
| Brainfuck / Ook! | `brainfuck`, `ook`, `short-ook` | Bounded interpreter, bracket validation and standard/short Ook token pairs. |
| AAEncode | `aaencode` | Emits executable AAEncoded JavaScript and decodes it without evaluating JavaScript. |
| Decabit | `decabit` | Complete 0-126 ten-pulse table; `DECA` matches the guide example. |
| SMS PDU | `sms-pdu[-DESTINATION]` | Decodes SMS-SUBMIT/DELIVER and emits UCS-2 SMS-SUBMIT PDUs. |
| Differential Manchester | `differential-manchester[-inverted]` | Start-of-bit rule plus mandatory mid-bit transition validation. |
| SNOW whitespace steganography | `snow`, `snow-compressed` | Compatible trailing whitespace bit order; compressed mode uses the original `-C` Huffman table. |
| Whitespace language | `whitespace-lang` | Encoder plus bounded interpreter for stack, arithmetic, heap, flow-control and I/O instructions. |

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
```

`snow-compressed` corresponds to SNOW's `-C` mode. `whitespace-lang` executes at most 1,000,000 instructions; its codec input channel is empty, so input instructions store `-1` while output, stack, heap and control-flow behavior remains deterministic.

Sources: thenoviceoof/base92 (MIT), qntm/base2048 and qntm/base65536 (MIT), the PGPfone word list, zhtelecode 0.1.0 (MIT), the original AAEncode implementation, dCode's Decabit table, and stegsnow's Apache-2.0 whitespace/Huffman implementation.
