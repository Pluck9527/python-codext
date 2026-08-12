# -*- coding: UTF-8 -*-
"""AAEncode JavaScript emoticon encoding without executing JavaScript."""
from ..__common__ import add, ensure_str


DIGITS = (
    "(c^_^o)", "(ﾟΘﾟ)", "((o^_^o) - (ﾟΘﾟ))", "(o^_^o)",
    "(ﾟｰﾟ)", "((ﾟｰﾟ) + (ﾟΘﾟ))", "((o^_^o) +(o^_^o))", "((ﾟｰﾟ) + (o^_^o))",
    "((ﾟｰﾟ) + (ﾟｰﾟ))", "((ﾟｰﾟ) + (ﾟｰﾟ) + (ﾟΘﾟ))", "(ﾟДﾟ) .ﾟωﾟﾉ", "(ﾟДﾟ) .ﾟΘﾟﾉ",
    "(ﾟДﾟ) ['c']", "(ﾟДﾟ) .ﾟｰﾟﾉ", "(ﾟДﾟ) .ﾟДﾟﾉ", "(ﾟДﾟ) [ﾟΘﾟ]",
)
PREFIX = "ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); "
HEADER = "(ﾟДﾟ)[ﾟoﾟ]+ "
BLOCK = "(ﾟДﾟ)[ﾟεﾟ]+"
HEX = "(oﾟｰﾟo)+ "
SUFFIX = "(ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');"
RUNTIME = (
    "(ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);"
    "(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ﾟωﾟﾉ==3) +'_') [ﾟΘﾟ] "
    ",ﾟｰﾟﾉ :(ﾟωﾟﾉ+ '_')[o^_^o -(ﾟΘﾟ)] "
    ",ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];"
    "(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];"
    "(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];"
    "(ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + "
    "((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+"
    "((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+"
    "((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ (ﾟДﾟ) ['o']+"
    "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];"
    "(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟДﾟ) .ﾟДﾟﾉ+"
    "((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+"
    "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟωﾟﾉ +'_') [ﾟΘﾟ]; "
    "(ﾟｰﾟ)+=(ﾟΘﾟ); (ﾟДﾟ)[ﾟεﾟ]='\\\\'; "
    "(ﾟДﾟ).ﾟΘﾟﾉ=(ﾟДﾟ+ ﾟｰﾟ)[o^_^o -(ﾟΘﾟ)];"
    "(oﾟｰﾟo)=(ﾟωﾟﾉ +'_')[c^_^o];"
    "(ﾟДﾟ) [ﾟoﾟ]='\"';"
    "(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+"
)


def aaencode(text, errors="strict"):
    blocks = []
    encoded = ensure_str(text).encode("utf-16-be", errors)
    for index in range(0, len(encoded), 2):
        codepoint = int.from_bytes(encoded[index:index + 2], "big")
        radix, marker = (8, "") if codepoint <= 127 else (16, HEX)
        blocks.append(BLOCK + marker + "".join(DIGITS[int(digit, radix)] + "+ " for digit in format(codepoint, "o" if radix == 8 else "x")))
    result = PREFIX + RUNTIME + HEADER + "".join(blocks) + SUFFIX
    return result, len(ensure_str(text))


def aadecode(text, errors="strict"):
    value = ensure_str(text).replace("/*´∇｀*/", "")
    start, end = value.find(HEADER), value.rfind(SUFFIX)
    if start < 0 or end < 0 or end < start:
        raise ValueError("input is not AAEncoded")
    data = value[start + len(HEADER):end]
    result = bytearray()
    for encoded in data.split(BLOCK)[1:]:
        radix = 16 if encoded.startswith(HEX) else 8
        encoded = encoded[len(HEX):] if radix == 16 else encoded
        number, position = "", 0
        ordered = sorted(enumerate(DIGITS), key=lambda item: len(item[1]), reverse=True)
        while position < len(encoded):
            while position < len(encoded) and encoded[position] in "+ \r\n\t":
                position += 1
            if position == len(encoded):
                break
            match = next(((digit, token) for digit, token in ordered if encoded.startswith(token, position)), None)
            if match is None:
                raise ValueError("invalid AAEncode digit expression")
            number += format(match[0], "x")
            position += len(match[1])
        if not number:
            raise ValueError("empty AAEncode character block")
        result.extend(int(number, radix).to_bytes(2, "big"))
    return result.decode("utf-16-be", errors), len(value)


add("aaencode", aaencode, aadecode, r"^(?:aa[-_]?encode|aa[-_]?codec)$")
