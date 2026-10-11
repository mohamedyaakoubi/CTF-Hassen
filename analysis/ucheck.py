import sys
from unicorn import *
from unicorn.x86_const import *
from elftools.elf.elffile import ELFFile

BIN = sys.argv[1]
with open(BIN,'rb') as f:
    elf = ELFFile(f)
    loads = [(s.header.p_vaddr, s.header.p_offset, s.header.p_filesz) for s in elf.iter_segments() if s.header.p_type=='PT_LOAD']
data = open(BIN,'rb').read()

MAIN=0x4003c0
HALT_H=0x400e20
PLT={0x400370:'puts',0x400380:'fread',0x400390:'strlen',0x4003a0:'memset',0x4003b0:'memcpy'}
STACK=0x7f0000; STACK_SZ=0x30000
ARGV=0x500000
INP=0x510000
SENTINEL=0x600000

MM=0xffffffff
def rolp(x,n): n&=31; return ((x<<n)|(x>>(32-n)))&MM
def emu_h(s):
    r0=0x7e4a1c3b;r1=0x2d5f8e11
    for i,b in enumerate(s):
        r0=(rolp((r0^b)&MM,11)*0xa3c59ac3+i)&MM
        r1=(rolp(((r0>>16)*0xcf1bbcdd+r1)&MM,7)^b)&MM
    return r0,r1

def run(inp: bytes):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(0x400000,0x8000)          # code+rodata+data+bss
    uc.mem_map(STACK & ~0xfff, STACK_SZ)
    uc.mem_map(ARGV,0x1000)
    uc.mem_map(INP,0x2000)
    uc.mem_map(SENTINEL & ~0xfff,0x1000)
    for va,off,fsz in loads:
        uc.mem_write(va, data[off:off+fsz])
    # input string (null terminated)
    uc.mem_write(INP, inp + b"\x00")
    # argv array: argv[0]->"prog", argv[1]->INP
    uc.mem_write(ARGV, (0x400000).to_bytes(8,'little') + INP.to_bytes(8,'little'))
    rsp = STACK + STACK_SZ - 0x1000
    rsp &= ~0xf
    rsp -= 8
    uc.mem_write(rsp, SENTINEL.to_bytes(8,'little'))  # return address for main's ret
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RDI, 2)         # argc
    uc.reg_write(UC_X86_REG_RSI, ARGV)      # argv

    result={'puts':None,'regs':None}
    def hook_code(uc,address,size,ud):
        if address in PLT:
            name=PLT[address]
            rdi=uc.reg_read(UC_X86_REG_RDI);rsi=uc.reg_read(UC_X86_REG_RSI);rdx=uc.reg_read(UC_X86_REG_RDX)
            if name=='strlen':
                n=0
                while uc.mem_read(rdi+n,1)!=b"\x00": n+=1
                uc.reg_write(UC_X86_REG_RAX,n)
            elif name=='memcpy':
                uc.mem_write(rdi, bytes(uc.mem_read(rsi,rdx))); uc.reg_write(UC_X86_REG_RAX,rdi)
            elif name=='memset':
                uc.mem_write(rdi, bytes([rsi&0xff])*rdx); uc.reg_write(UC_X86_REG_RAX,rdi)
            elif name=='puts':
                s=b"";k=0
                while True:
                    c=uc.mem_read(rdi+k,1)
                    if c==b"\x00": break
                    s+=c;k+=1
                result['puts']=s
            elif name=='fread':
                uc.reg_write(UC_X86_REG_RAX,0)
            # simulate ret
            sp=uc.reg_read(UC_X86_REG_RSP); ret=int.from_bytes(uc.mem_read(sp,8),'little')
            uc.reg_write(UC_X86_REG_RSP,sp+8); uc.reg_write(UC_X86_REG_RIP,ret)
            return
        if address==HALT_H:
            rdi=uc.reg_read(UC_X86_REG_RDI)
            reg0=int.from_bytes(uc.mem_read(rdi+0x404,4),'little')
            reg1=int.from_bytes(uc.mem_read(rdi+0x408,4),'little')
            result['regs']=(reg0,reg1)
    uc.hook_add(UC_HOOK_CODE, hook_code)
    try:
        uc.emu_start(MAIN, SENTINEL)
    except UcError as e:
        result['err']=str(e)+f" @rip={uc.reg_read(UC_X86_REG_RIP):#x}"
    return result

if __name__=='__main__':
    tests=[b'A', b'SecurinetsENIT{test}', b'hello', b'SecurinetsENIT{', b'abcdefghij', b'\x01\x02\x7f\x80\xff']
    allok=True
    for t in tests:
        r=run(t)
        e=emu_h(t)
        uc_regs=r.get('regs')
        verdict=r.get('puts')
        match = (uc_regs==e)
        allok &= match
        print(f"inp={t!r:28} unicorn_regs={tuple(hex(x) for x in uc_regs) if uc_regs else None} py={tuple(hex(x) for x in e)} match={match} verdict={verdict} {r.get('err','')}")
    print("MODEL VALIDATED" if allok else "MISMATCH!")
