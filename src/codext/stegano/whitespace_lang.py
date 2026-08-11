# -*- coding: UTF-8 -*-
"""Whitespace esoteric-language encoder and bounded interpreter."""
from ..__common__ import add, b, ensure_str


S, T, L = " ", "\t", "\n"


def _number(value):
    sign = S if value >= 0 else T
    bits = format(abs(value), "b").replace("0", S).replace("1", T)
    return sign + bits + L


def whitespace_lang_encode(text, errors="strict"):
    result = "".join(S + S + _number(byte) + T + L + S + S for byte in b(text)) + L + L + L
    return result, len(b(text))


def _parse(program):
    code = "".join(char for char in program if char in (S, T, L))
    instructions, cursor = [], 0

    def argument(position, signed=True):
        end = code.find(L, position)
        if end < 0:
            raise ValueError("unterminated Whitespace argument")
        raw = code[position:end]
        if not raw:
            return 0, end + 1
        sign = -1 if signed and raw[0] == T else 1
        digits = raw[1:] if signed else raw
        value = int(digits.replace(S, "0").replace(T, "1") or "0", 2)
        return sign * value, end + 1

    while cursor < len(code):
        if code.startswith(S + S, cursor):
            value, cursor = argument(cursor + 2)
            instructions.append(("push", value))
            continue
        stack_ops = {S + L + S: "dup", S + L + T: "swap", S + L + L: "discard"}
        operation = next(((prefix, name) for prefix, name in stack_ops.items() if code.startswith(prefix, cursor)), None)
        if operation:
            instructions.append((operation[1], None))
            cursor += len(operation[0])
            continue
        if code.startswith(S + T + S, cursor):
            value, cursor = argument(cursor + 3)
            instructions.append(("copy", value))
            continue
        if code.startswith(S + T + L, cursor):
            value, cursor = argument(cursor + 3)
            instructions.append(("slide", value))
            continue
        arithmetic = {
            T + S + S + S: "add", T + S + S + T: "sub", T + S + S + L: "mul",
            T + S + T + S: "div", T + S + T + T: "mod",
        }
        operation = next(((prefix, name) for prefix, name in arithmetic.items() if code.startswith(prefix, cursor)), None)
        if operation:
            instructions.append((operation[1], None))
            cursor += len(operation[0])
            continue
        heap_ops = {T + T + S: "store", T + T + T: "retrieve"}
        operation = next(((prefix, name) for prefix, name in heap_ops.items() if code.startswith(prefix, cursor)), None)
        if operation:
            instructions.append((operation[1], None))
            cursor += len(operation[0])
            continue
        flow = {
            L + S + S: "label", L + S + T: "call", L + S + L: "jump",
            L + T + S: "zero", L + T + T: "negative",
        }
        operation = next(((prefix, name) for prefix, name in flow.items() if code.startswith(prefix, cursor)), None)
        if operation:
            value, cursor = argument(cursor + len(operation[0]), signed=False)
            instructions.append((operation[1], value))
            continue
        fixed = {
            L + T + L: "return", L + L + L: "end",
            T + L + S + S: "outchar", T + L + S + T: "outnum",
            T + L + T + S: "readchar", T + L + T + T: "readnum",
        }
        operation = next(((prefix, name) for prefix, name in fixed.items() if code.startswith(prefix, cursor)), None)
        if operation:
            instructions.append((operation[1], None))
            cursor += len(operation[0])
            continue
        raise ValueError("unknown Whitespace instruction at symbol %d" % cursor)
    return instructions


def whitespace_lang_decode(text, errors="strict"):
    instructions = _parse(ensure_str(text))
    labels = {value: index for index, (name, value) in enumerate(instructions) if name == "label"}
    stack, calls, heap, output = [], [], {}, bytearray()
    cursor, steps = 0, 0
    while cursor < len(instructions):
        steps += 1
        if steps > 1_000_000:
            raise RuntimeError("Whitespace step limit exceeded")
        name, value = instructions[cursor]
        cursor += 1
        if name == "push":
            stack.append(value)
        elif name == "dup":
            stack.append(stack[-1])
        elif name == "swap":
            stack[-2], stack[-1] = stack[-1], stack[-2]
        elif name == "discard":
            stack.pop()
        elif name == "copy":
            stack.append(stack[-1 - value])
        elif name == "slide":
            top = stack.pop()
            if value > 0:
                del stack[-value:]
            stack.append(top)
        elif name in ("add", "sub", "mul", "div", "mod"):
            right, left = stack.pop(), stack.pop()
            if name == "add":
                stack.append(left + right)
            elif name == "sub":
                stack.append(left - right)
            elif name == "mul":
                stack.append(left * right)
            elif name == "div":
                stack.append(int(left / right))
            elif name == "mod":
                stack.append(left % right)
        elif name == "store":
            stored, address = stack.pop(), stack.pop()
            heap[address] = stored
        elif name == "retrieve":
            stack.append(heap[stack.pop()])
        elif name == "call":
            calls.append(cursor)
            cursor = labels[value] + 1
        elif name == "jump":
            cursor = labels[value] + 1
        elif name == "zero":
            cursor = labels[value] + 1 if stack.pop() == 0 else cursor
        elif name == "negative":
            cursor = labels[value] + 1 if stack.pop() < 0 else cursor
        elif name == "return":
            cursor = calls.pop()
        elif name == "end":
            break
        elif name == "outchar":
            output.append(stack.pop() % 256)
        elif name == "outnum":
            output.extend(str(stack.pop()).encode())
        elif name in ("readchar", "readnum"):
            heap[stack.pop()] = -1
    return bytes(output), len(ensure_str(text))


add("whitespace_lang", whitespace_lang_encode, whitespace_lang_decode,
    r"^(?:whitespace[-_]?(?:lang|language|esolang|program)|ws[-_]?lang)$", aliases=["whitespace-lang"])
