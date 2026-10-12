#!/usr/bin/env python3
"""
Readable-candidate (word/phrase) preimage search for the layerup VM hash.
Hashes plausible flag contents directly (no MITM), so it handles ANY length
for word-based flags. Covers single words, leet/case variants, digit affixes,
and 2-word combos with separators, in both modes (A=full flag, B=inner only).

Usage:
  python phrase_search.py <words_file> <common_file> [shard] [nshards]
Env/args pick which candidate families to run (singles always; pairs sharded).
"""
import sys, itertools

MM = 0xffffffff
C1 = 0xa3c59ac3; C2 = 0xcf1bbcdd; T0 = 0xa5219537; T1 = 0xc19b6387
def rol(x, n): n &= 31; return ((x << n) | (x >> (32 - n))) & MM
def h(s):
    r0, r1 = 0x7e4a1c3b, 0x2d5f8e11
    for i, b in enumerate(s):
        r0 = (rol((r0 ^ b) & MM, 11) * C1 + i) & MM
        r1 = (rol(((r0 >> 16) * C2 + r1) & MM, 7) ^ b) & MM
    return r0, r1

PRE = b'SecurinetsENIT{'; SUF = b'}'
def check(inner_bytes, hits):
    # mode A: whole flag hashed
    if h(PRE + inner_bytes + SUF) == (T0, T1):
        hits.append(('A', inner_bytes))
        print("FLAG_FOUND A:", ('SecurinetsENIT{' + inner_bytes.decode('latin1') + '}'), flush=True)
    # mode B: only inner hashed
    if h(inner_bytes) == (T0, T1):
        hits.append(('B', inner_bytes))
        print("FLAG_FOUND B:", ('SecurinetsENIT{' + inner_bytes.decode('latin1') + '}'), flush=True)

LEET = str.maketrans({'a':'4','e':'3','i':'1','o':'0','s':'5','t':'7','l':'1','b':'8','g':'9'})
LEET_LITE = str.maketrans({'a':'4','e':'3','i':'1','o':'0','s':'5'})
def variants(w):
    w = w.strip().lower()
    if not w or not w.isalpha(): return
    out = {w, w.title(), w.upper(), w.translate(LEET), w.translate(LEET_LITE),
           w.title().translate(LEET_LITE)}
    return out

AFFIX = ['', '1', '2', '!', '42', '123', '_', '2024', '2025', '69', '1337']
SEPS = ['_', '', '-', '.']

def run(words_file, common_file, shard=0, nshards=1):
    words = [w.strip() for w in open(words_file, encoding='utf-8', errors='ignore') if 2 <= len(w.strip()) <= 22]
    common = [w.strip() for w in open(common_file, encoding='utf-8', errors='ignore') if 2 <= len(w.strip()) <= 14 and w.strip().isalpha()]
    hits = []

    # ---- family 1: single words + variants + affixes (only shard 0 runs these; they're cheap) ----
    if shard == 0:
        print(f"[singles] {len(words)} words", flush=True)
        n = 0
        for w in words:
            vs = variants(w)
            if not vs: continue
            for v in vs:
                for a in AFFIX:
                    check((v + a).encode('latin1', 'ignore'), hits)
            n += 1
            if n % 50000 == 0: print(f"  singles {n}/{len(words)} hits={len(hits)}", flush=True)

    # ---- family 2: themed phrases (always, cheap) ----
    if shard == 0:
        theme = ['layer','layers','layered','layerup','onion','onions','boxic','auth',
                 'vm','stack','bytecode','interpreter','machine','shipped','thursday',
                 'friday','night','vacation','docs','undocumented','nodocs','forgot',
                 'remember','built','binary','secret','key','up','down','deep','peel',
                 'reverse','keygen','obfuscated','hidden','the','of','and','no','never']
        for a, b, c in itertools.product(theme, repeat=3):
            for s in SEPS:
                check((a + s + b + s + c).encode(), hits)
                check((a + s + b + s + c).translate(LEET_LITE).encode(), hits)

    # ---- family 3: 2-word combos from common list (sharded over first word) ----
    cw = common
    print(f"[pairs] {len(cw)} common words, shard {shard}/{nshards}", flush=True)
    for idx, w1 in enumerate(cw):
        if idx % nshards != shard: continue
        for w2 in cw:
            base = [w1 + s + w2 for s in SEPS]
            for b in base:
                check(b.encode(), hits)
                check(b.translate(LEET_LITE).encode(), hits)
        if idx % 200 == 0: print(f"  pairs w1#{idx} hits={len(hits)}", flush=True)

    print("DONE hits:", len(hits), flush=True)
    if hits:
        open('FOUND.txt', 'a').write('\n'.join('SecurinetsENIT{' + i.decode('latin1') + '}' for _, i in hits) + '\n')
    return hits

if __name__ == '__main__':
    wf = sys.argv[1]; cf = sys.argv[2]
    shard = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    nshards = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    run(wf, cf, shard, nshards)
