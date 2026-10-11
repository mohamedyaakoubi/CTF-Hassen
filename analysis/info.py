import sys, re
from elftools.elf.elffile import ELFFile

path = sys.argv[1]
data = open(path, 'rb').read()

with open(path, 'rb') as f:
    elf = ELFFile(f)
    print("Entry:", hex(elf.header.e_entry))
    print("\n== Segments ==")
    for seg in elf.iter_segments():
        h = seg.header
        print(f"{h.p_type:15} off={h.p_offset:#07x} vaddr={h.p_vaddr:#010x} filesz={h.p_filesz:#07x} memsz={h.p_memsz:#07x} flags={h.p_flags}")
    print("\n== Sections ==")
    for s in elf.iter_sections():
        print(f"{s.name:22} addr={s['sh_addr']:#010x} off={s['sh_offset']:#07x} size={s['sh_size']:#07x} type={s['sh_type']}")
    dynsym = elf.get_section_by_name('.dynsym')
    if dynsym:
        print("\n== Dynamic symbols ==")
        for sym in dynsym.iter_symbols():
            if sym.name:
                print(f"  {sym.name:30} value={sym['st_value']:#x}")
    for relname in ('.rela.plt', '.rela.dyn'):
        rel = elf.get_section_by_name(relname)
        if rel:
            symtab = elf.get_section(rel['sh_link'])
            print(f"\n== {relname} ==")
            for r in rel.iter_relocations():
                sym = symtab.get_symbol(r['r_info_sym'])
                print(f"  offset={r['r_offset']:#x} sym={sym.name} type={r['r_info_type']}")

print("\n== Strings (>=4) ==")
for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
    print(f"{m.start():#07x}: {m.group().decode()}")
