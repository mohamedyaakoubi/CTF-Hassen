M = 0xffffffff
def rol(x, n): n &= 31; return ((x << n) | (x >> (32-n))) & M
C1 = 0xa3c59ac3
C2 = 0xcf1bbcdd

def h(inp):
    r0 = 0x7e4a1c3b
    r1 = 0x2d5f8e11
    for i, b in enumerate(inp):
        r0 = (rol((r0 ^ b) & M, 11) * C1 + i) & M
        r1 = (rol(((r0 >> 16) * C2 + r1) & M, 7) ^ b) & M
    return r0, r1

if __name__ == '__main__':
    import sys
    for s in ['', 'A', 'SecurinetsENIT{test}', 'SecurinetsENIT{']:
        r0, r1 = h(s.encode())
        print(f"{s!r:30} -> r0={r0:#010x} r1={r1:#010x}")
    print("target                           r0=0xa5219537 r1=0xc19b6387")
