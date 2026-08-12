# -*- coding: UTF-8 -*-
"""Brainfuck and Ook! interpreters/codecs for CTF payloads."""
import re

from ..__common__ import add, b, ensure_str


COMMANDS = "><+-.,[]"
OOK = {
    ">": ".?", "<": "?.", "+": "..", "-": "!!",
    ".": "!.", ",": ".!", "[": "!?", "]": "?!",
}


def brainfuck_encode(text, errors="strict"):
    value, cell, program = b(text), 0, []
    for byte in value:
        delta = (byte - cell) % 256
        reverse = (cell - byte) % 256
        program.append(("+" * delta if delta <= reverse else "-" * reverse) + ".")
        cell = byte
    result = "".join(program)
    return result, len(value)


def _brainfuck_run(program, errors="strict"):
    code = "".join(char for char in program if char in COMMANDS)
    stack, pairs = [], {}
    for index, command in enumerate(code):
        if command == "[":
            stack.append(index)
        if command == "]":
            if not stack:
                raise ValueError("unmatched Brainfuck closing bracket")
            opening = stack.pop()
            pairs[opening] = index
            pairs[index] = opening
    if stack:
        raise ValueError("unmatched Brainfuck opening bracket")
    tape, pointer, cursor, steps, output = [0] * 30000, 0, 0, 0, bytearray()
    while cursor < len(code):
        steps += 1
        if steps > 1_000_000:
            raise RuntimeError("Brainfuck step limit exceeded")
        command = code[cursor]
        if command == ">":
            pointer += 1
            if pointer == len(tape):
                tape.append(0)
        if command == "<":
            if pointer == 0:
                raise ValueError("Brainfuck pointer moved before cell zero")
            pointer -= 1
        if command == "+":
            tape[pointer] = (tape[pointer] + 1) % 256
        if command == "-":
            tape[pointer] = (tape[pointer] - 1) % 256
        if command == ".":
            output.append(tape[pointer])
        if command == ",":
            tape[pointer] = 0
        if command == "[" and tape[pointer] == 0:
            cursor = pairs[cursor]
        if command == "]" and tape[pointer] != 0:
            cursor = pairs[cursor]
        cursor += 1
    return bytes(output)


def brainfuck_decode(text, errors="strict"):
    return _brainfuck_run(ensure_str(text), errors), len(ensure_str(text))


def ook_encode(short=False):
    def encode(text, errors="strict"):
        program = brainfuck_encode(text, errors)[0]
        result = " ".join(OOK[command] if short else "Ook%s Ook%s" % tuple(OOK[command]) for command in program)
        return result, len(ensure_str(text))
    return encode


def ook_decode(short=False):
    def decode(text, errors="strict"):
        value = ensure_str(text)
        if short:
            symbols = "".join(char for char in value if char in ".!?")
        else:
            tokens = re.findall(r"Ook\s*([.!?])", value, re.I)
            symbols = "".join(tokens)
        if len(symbols) % 2:
            raise ValueError("Ook! input contains an incomplete token pair")
        inverse = {pair: command for command, pair in OOK.items()}
        program = "".join(inverse.get(symbols[index:index + 2], "]" if symbols[index:index + 2] == "??" else "")
                          for index in range(0, len(symbols), 2))
        if len(program) != len(symbols) // 2:
            raise ValueError("unknown Ook! token pair")
        return _brainfuck_run(program, errors), len(value)
    return decode


add("brainfuck", brainfuck_encode, brainfuck_decode, r"^(?:brainf(?:uck|\*\*\*)|bf)$")
add("ook", ook_encode(False), ook_decode(False), r"^ook!?$")
add("short_ook", ook_encode(True), ook_decode(True), r"^(?:short[-_]?ook|ook[-_]?short)$", aliases=["short-ook"])
