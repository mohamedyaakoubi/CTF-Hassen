import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

path = sys.argv[1]
start = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
end = int(sys.argv[3], 16) if len(sys.argv) > 3 else None

data = open(path, 'rb').read()
with open(path, 'rb') as f:
    elf = ELFFile(f)
    secs = {s.name: (s['sh_addr'], s['sh_offset'], s['sh_size']) for s in elf.iter_sections()}

PLT = {0x400370: 'puts', 0x400380: 'fread', 0x400390: 'strlen', 0x4003a0: 'memset', 0x4003b0: 'memcpy'}

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.skipdata = True

def dump(name):
    addr, off, size = secs[name]
    code = data[off:off+size]
    print(f"\n===== {name} {addr:#x}..{addr+size:#x} =====")
    for ins in md.disasm(code, addr):
        if start is not None and ins.address < start:
            continue
        if end is not None and ins.address >= end:
            break
        extra = ''
        if ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x'):
            t = int(ins.op_str, 16)
            if t in PLT:
                extra = f'   ; <{PLT[t]}>'
        print(f"{ins.address:#08x}: {ins.bytes.hex():<24} {ins.mnemonic:8} {ins.op_str}{extra}")

if start is None:
    dump('.plt')
dump('.text')

if start is None:
    addr, off, size = secs['.rodata']
    print(f"\n===== .rodata {addr:#x} =====")
    ro = data[off:off+size]
    for i in range(0, len(ro), 16):
        chunk = ro[i:i+16]
        print(f"{addr+i:#08x}: {chunk.hex(' '):<48} {''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)}")
    addr, off, size = secs['.data']
    print(f"\n===== .data {addr:#x} =====")
    print(data[off:off+size].hex(' '))
