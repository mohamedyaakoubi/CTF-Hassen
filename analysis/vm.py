import sys
from elftools.elf.elffile import ELFFile

path = sys.argv[1]
with open(path, 'rb') as f:
    elf = ELFFile(f)
    secs = {s.name: (s['sh_addr'], s['sh_offset'], s['sh_size']) for s in elf.iter_sections()}
data = open(path, 'rb').read()

def vaddr_to_off(va):
    for name,(a,o,sz) in secs.items():
        if a <= va < a+sz and name not in ('',):
            return o + (va-a)
    return None

# Handler address -> mnemonic (from manual analysis of disasm)
HANDLERS = {
    0x400710: ('PUSH', 4),       # push 32-bit LE immediate
    0x4007c0: ('LDIN', 0),       # pop idx, push input[idx] (0 if oob)
    0x400860: ('PUSHLEN', 0),    # push input length
    0x4008a0: ('ADD', 0),
    0x400920: ('SUB', 0),        # a-b (b=top)
    0x4009b0: ('XOR', 0),
    0x400a30: ('MUL', 0),
    0x400ab0: ('ROL', 0),        # a rol b
    0x400b30: ('SHR', 0),        # a shr b
    0x400bb0: ('AND', 0),
    0x400c30: ('DUP', 0),
    0x400c70: ('SWAP', 0),
    0x400cb0: ('DROP', 0),
    0x400ce0: ('EQ', 0),
    0x400d80: ('JZ', 2),         # pop v; if v==0 jump abs16
    0x400fa0: ('JMP', 2),        # jump abs16
    0x400e20: ('HALT', 0),       # result=(pop()==1), halt
    0x400e60: ('STREG', 1),      # pop -> reg[b]
    0x400f00: ('LDREG', 1),      # push reg[b]
    0x400f80: ('ERR', 0),
}

# Parse main's dispatch-table setup: instructions of form 48 c7 05 <disp32> <imm32>
text_a, text_o, text_sz = secs['.text']
TABLE = 0x404060
opmap = {}   # opcode -> handler addr
i = text_o
end = text_o + text_sz
while i < end-11:
    if data[i]==0x48 and data[i+1]==0xc7 and data[i+2]==0x05:
        disp = int.from_bytes(data[i+3:i+7],'little',signed=True)
        imm  = int.from_bytes(data[i+7:i+11],'little',signed=True) & 0xffffffff
        va = text_a + (i - text_o)
        rip = va + 11
        tgt = (rip + disp) & 0xffffffffffffffff
        if TABLE <= tgt < TABLE+256*8 and (tgt-TABLE)%8==0:
            op = (tgt-TABLE)//8
            opmap[op] = imm
        i += 11
    else:
        i += 1

print("== Opcode map ==")
for op in sorted(opmap):
    h = opmap[op]
    name = HANDLERS.get(h, ('?%x'%h,0))[0]
    print(f"  0x{op:02x} -> {name} ({h:#x})")

# decode program
prog_a = 0x4022e0
prog_len = 0x75
po = vaddr_to_off(prog_a)
prog = data[po:po+prog_len]
print(f"\n== Program ({prog_len} bytes) ==")
print(prog.hex(' '))

# build opcode -> (name, operandlen)
op2info = {}
for op,h in opmap.items():
    op2info[op] = HANDLERS.get(h, ('?',0))

print("\n== Disassembly ==")
ip = 0
# find jump targets for labels
while ip < len(prog):
    op = prog[ip]
    name, olen = op2info.get(op, ('UNK',0))
    operand_bytes = prog[ip+1:ip+1+olen]
    s = f"{ip:3d}: {op:02x} {name:8}"
    if name == 'PUSH':
        val = int.from_bytes(operand_bytes,'little')
        s += f" 0x{val:08x} ({val})"
    elif name in ('JZ','JMP'):
        tgt = int.from_bytes(operand_bytes,'little')
        s += f" -> {tgt}"
    elif name in ('STREG','LDREG'):
        s += f" r{operand_bytes[0]}"
    print(s)
    ip += 1 + olen
