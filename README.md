# layerup — Securinets ENIT reversing challenge (work-in-progress handoff)

> **Flag format:** `SecurinetsENIT{...}`
> **Status:** Binary fully reverse-engineered and the check is a *bit-exact validated*
> custom hash. Remaining work is a **meet-in-the-middle preimage search** that needs
> more RAM/compute than the original machine had. Everything needed to finish is here.

This README is a complete handoff so a fresh session (or teammate) can finish without
re-deriving anything. If you only read one section, read **[Where it stands](#where-it-stands)**.

---

## The binary

`layerup` — ELF 64-bit LSB PIE-ish executable, x86-64, dynamically linked, **stripped**.
Imports only `puts, fread, strlen, memset, memcpy`. Prints `Correct!` or `Wrong.`.
(`layerup` and `layerup(1)` are the same file, sha256 `20ddbc6e…a09a7f`.)

It reads one line of input (from `argv[1]` if given, else `stdin` via `fread`, trailing
`\n` stripped) and runs it through a tiny **stack-VM bytecode interpreter**, then checks
two 32-bit accumulators against hard-coded targets.

## VM architecture (what `main` @ `0x4003c0` does)

1. Builds a **256-entry dispatch table** at `0x404060` (one function pointer per possible
   opcode byte). Every slot defaults to an **error handler** `0x400f80`; `main` then
   overwrites 19 slots with real opcode handlers.
2. Sets up a VM state struct on the stack and runs the fetch/dispatch loop:
   `opcode = bytecode[ip]; ip++; handlers[opcode](state);` until the **running** flag
   clears or `ip` reaches the end.
3. Accepts iff **error flag == 0 and result flag == 1**.

**VM state struct layout** (offsets from the struct base passed in `rdi`):

| offset | field |
|-------:|-------|
| `+0x000` | `stack[256]` (int32 each) |
| `+0x400` | `sp` (stack pointer) |
| `+0x404` | `regs[8]` (int32 each → `+0x404..+0x420`) |
| `+0x428` | bytecode pointer (= `0x4022e0`) |
| `+0x430` | bytecode length (= `0x75` = 117) |
| `+0x434` | `ip` (instruction pointer) |
| `+0x438` | input pointer |
| `+0x440` | input length |
| `+0x444` | running flag (1=run, cleared to halt) |
| `+0x448` | error flag (set by the error handler / any fault) |
| `+0x44c` | result flag (1 = accept) |

### Opcode map (handler → mnemonic), recovered from `main`'s table setup

| op | mnemonic | effect |
|---:|----------|--------|
| `0x3c` | `PUSH imm32` | push little-endian 4-byte immediate (operand) |
| `0x9a` | `LDIN` | pop idx, push `input[idx]` (0 if idx ≥ len) |
| `0x5e` | `PUSHLEN` | push input length |
| `0x71` | `ADD` | pop b,a push a+b |
| `0x24` | `SUB` | pop b,a push a−b |
| `0xb8` | `XOR` | pop b,a push a^b |
| `0x4d` | `MUL` | pop b,a push a*b |
| `0xe2` | `ROL` | pop cnt,val push `rol32(val,cnt)` |
| `0x53` | `SHR` | pop cnt,val push `val >> cnt` (logical) |
| `0x2f` | `AND` | pop b,a push a&b |
| `0x17` | `DUP` | duplicate top |
| `0xca` | `SWAP` | swap top two |
| `0x66` | `DROP` | pop/discard |
| `0x8f` | `EQ` | pop b,a push (a==b)?1:0 |
| `0xd3` | `JZ abs16` | pop v; if v==0 jump to absolute 2-byte target |
| `0x1b` | `JMP abs16` | unconditional jump |
| `0x7b` | `HALT` | `result = (pop()==1)`, clear running (accept check) |
| `0x42` | `STREG r` | pop → `regs[operand]` (operand 1 byte, 0..7) |
| `0xae` | `LDREG r` | push `regs[operand]` |
| `0x400f80` | *(default)* | error handler: sets error flag, halts |

All arithmetic is **mod 2³²** (`imul r32`, `rol r32,cl`, etc.).

### The bytecode program (117 bytes @ `0x4022e0`) — disassembled

```
r0 = 0x7e4a1c3b        ; reg0
r1 = 0x2d5f8e11        ; reg1
i  = 0                 ; reg2  (loop counter)
loop:
    if i == len: goto end
    b = input[i]                               ; reg3
    r0 = (rol32(r0 ^ b, 11) * 0xa3c59ac3 + i) & 0xffffffff
    r1 = (rol32(((r0 >> 16) * 0xcf1bbcdd + r1) & 0xffffffff, 7) ^ b) & 0xffffffff
    i += 1
    goto loop
end:
    accept = (r0 == 0xa5219537) * (r1 == 0xc19b6387)   ; HALT requires product == 1
```

`analysis/vm.py` regenerates the opcode map + this disassembly directly from the binary.

## The check (this is the whole challenge)

```python
def h(inp: bytes):
    M = 0xffffffff
    rol = lambda x, n: ((x << (n & 31)) | (x >> (32 - (n & 31)))) & M
    r0, r1 = 0x7e4a1c3b, 0x2d5f8e11
    for i, b in enumerate(inp):
        r0 = (rol((r0 ^ b) & M, 11) * 0xa3c59ac3 + i) & M
        r1 = (rol(((r0 >> 16) * 0xcf1bbcdd + r1) & M, 7) ^ b) & M
    return r0, r1
# Correct!  iff  h(inp) == (0xa5219537, 0xc19b6387)
```

**Constants** (all verified): init `r0=0x7e4a1c3b`, `r1=0x2d5f8e11`; multipliers
`C1=0xa3c59ac3`, `C2=0xcf1bbcdd`; targets `T0=0xa5219537`, `T1=0xc19b6387`.
`C1⁻¹ mod 2³² = 0x0d8465eb`, `C2` is also odd (both invertible ⇒ the step is invertible).

### This model is bit-exact — proven, not assumed
`analysis/ucheck.py` emulates the **real ELF** with Unicorn (hooking the 5 libc calls),
feeds inputs, and reads `reg0/reg1` out of VM memory at `HALT`. The Python `h()` matches
the binary for every tested input (printable and non-printable). Re-run to re-confirm:
```
python analysis/ucheck.py ./layerup
```

## Why this is hard / why the obvious tools fail
- `r0` depends only on the input bytes + index; `r1` chains off the *new* `r0`.
- Each step is invertible, **but** a backward step only yields `r0_i ⊕ b_i` — it can't
  separate the state byte from the input byte, so backward recovery still branches 256×
  per byte. No cheap unique inversion exists.
- **z3 / bit-blasting cannot do it:** the chained 32-bit multiplies by `C1,C2` defeat the
  SAT backend — even recovering a *known* 7-char middle times out at 120 s. Don't waste
  time on z3.
- Therefore: **meet-in-the-middle** (forward from the known prefix, backward from the
  target). Cost is `charset^(secret_len/2)` in RAM for the plain version.

## The solver — `layerup_solver.py`
Validated streaming MITM (`tests/test_solver.py` passes: modes A/B, underscores,
mixed-case, symbols, and sharded runs). It **stores the smaller half sorted in RAM and
streams the larger half in batches**, so memory is bounded by the stored half while the
streamed half is time-bound — this is what lets 16 GB reach long secrets.

Two interpretations of "the input", both supported:
- **mode A** — the hashed input is the whole flag: `SecurinetsENIT{` + secret + `}`.
- **mode B** — the hashed input is only the secret; flag = `SecurinetsENIT{secret}`.
  (The binary does **not** check for the prefix, so either is possible — try both.)

```bash
# one exact config (N = length of the HASHED input)
python layerup_solver.py one  A low_us 27 5          # store_k=5
# auto-pick store_k from RAM budget
python layerup_solver.py auto A low_us 27
# sweep a length band
python layerup_solver.py sweep A low_us 25 29
# tunable via env: STORE_CAP BATCH_CAP STREAM_CAP TIME_CAP SHARD NSHARDS
```
On success it prints `FLAG_FOUND: …`, appends to `FOUND.txt`, and prints a `VERIFIED` line.

## Running it at scale — GitHub Actions (free, 16 GB, ~20 parallel)
- **`.github/workflows/solve.yml`** — auto matrix sweep over (mode × charset × length
  band). Runs on push (and manual dispatch). Covers the high-probability region.
- **`.github/workflows/solve-heavy.yml`** — `workflow_dispatch` that **shards one heavy
  config** across N runners (`SHARD`/`NSHARDS`), for long secrets.

Retrieve a hit:
```bash
gh run list --workflow solve-sweep
gh run view <run-id> --log | grep -E "FLAG_FOUND|VERIFIED|::notice"
gh run download <run-id>        # pulls any found-*/FOUND.txt artifacts
```

## Where it stands
**Confirmed:** full RE + bit-exact check model (above). Dictionary of themed guesses
(`layerup`, `boxic`, `l4y3r_up`, …) in modes A/B/upper: **no hit**.

**Searched locally with no hit** (mode A, prefix `SecurinetsENIT{`, suffix `}`):
| charset | secret length covered |
|---|---|
| lowercase + `_` (27) | up to **10** |
| + digits (37) | up to **8** |
| + uppercase (63) | up to **8** |
| + `-` (38) | up to **8** |

Local RAM (1.6 GB free) capped the tables there. **The entropy budget (two 32-bit
targets ⇒ ~64 bits) suggests the intended secret is ~10–14 chars**, i.e. just past what
was reachable locally — exactly what the Actions matrix + streaming solver is built to cover.

### Suggested next moves (in priority order)
1. Push triggers `solve.yml`; watch it. It covers mode A/B across charsets for the
   ~6–13 char band with 16 GB runners.
2. If no hit, dispatch `solve-heavy.yml` for the top candidates at larger lengths, e.g.
   `mode=A cs=low_us N=30` (secret 14), `mode=A cs=low_dig_us N=29` (secret 13),
   `nshards=20`. Then the same for `cs=low`, `cs=leet_sym`, and mode B equivalents.
3. Widen charset only if needed (`printable`, `leet_sym`) — bigger charset ⇒ shorter
   reachable length, so prefer the smallest plausible charset first.
4. Sanity: the secret could contain characters outside the tried sets (e.g. `{}`, `.`,
   case mix). `leet_sym` and `printable` cover these at shorter lengths.

## Repro / tooling
```bash
pip install capstone unicorn pyelftools numpy   # z3-solver optional (not needed)
python analysis/info.py  ./layerup     # headers, imports, strings, .rodata
python analysis/disas.py ./layerup     # raw capstone disassembly
python analysis/vm.py    ./layerup     # opcode map + bytecode disassembly
python analysis/ucheck.py ./layerup    # Unicorn: prove the Python model == binary
python tests/test_solver.py            # solver self-tests
```

## Files
```
layerup, layerup(1)        the challenge binary (identical)
layerup_solver.py          validated streaming meet-in-the-middle solver (+ CLI)
tests/test_solver.py       solver self-tests (known-preimage recovery, sharding)
analysis/info.py           ELF headers / imports / strings / .rodata dump
analysis/disas.py          full capstone disassembly
analysis/disas.txt         saved disassembly
analysis/vm.py             opcode-table parser + bytecode disassembler
analysis/emu.py            reference Python hash
analysis/ucheck.py         Unicorn harness proving model == binary
.github/workflows/solve.yml        auto matrix sweep
.github/workflows/solve-heavy.yml  sharded heavy dispatch
```
