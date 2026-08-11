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

```python
import codext

alphabet = "/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
codext.add_custom_base64(alphabet, "base64-ctf")
plaintext = codext.decode("i5qMi/==", "base64-ctf")
```

All codecs work through `codext.encode`, `codext.decode`, the CLI registry and codec chains. Base64 padding steganography is intentionally one-way. Chinese Telegraph Code uses Mainland/Taiwan codebooks derived from Unicode Unihan mappings.

Sources: thenoviceoof/base92 (MIT), qntm/base2048 and qntm/base65536 (MIT), the PGPfone word list, and zhtelecode 0.1.0 (MIT).
