#!/usr/bin/env python3
"""
Vectorized readable-phrase preimage search for the layerup VM hash.
Sweeps 2-word combinations from a common-word list (both modes, separators,
light leetspeak), numpy-batched (~1M cand/s). Shardable over the first word.
Covers readable word/underscore/leet phrases of ANY length.

Usage: python phrase_vec.py <common_file> [shard] [nshards]
"""
import sys, numpy as np

MM = np.uint64(0xffffffff); C1 = np.uint64(0xa3c59ac3); C2 = np.uint64(0xcf1bbcdd)
T0 = 0xa5219537; T1 = 0xc19b6387
PRE = b'SecurinetsENIT{'; SUF = b'}'

def rol(x, n):
    n = np.uint64(n & 31)
    return x & MM if n == 0 else ((x << n) | (x >> np.uint64(32) - n)) & MM

def hbatch(B):  # B: (M,L) uint8
    M = B.shape[0]
    r0 = np.full(M, 0x7e4a1c3b, np.uint64); r1 = np.full(M, 0x2d5f8e11, np.uint64)
    for i in range(B.shape[1]):
        b = B[:, i].astype(np.uint64)
        r0 = (rol((r0 ^ b) & MM, 11) * C1 + np.uint64(i)) & MM
        r1 = (rol((((r0 >> np.uint64(16)) * C2) + r1) & MM, 7) ^ b) & MM
    return r0, r1

LEET = str.maketrans({'a':'4','e':'3','i':'1','o':'0','s':'5'})
SEPS = ['_', '', '-', '.']

def check_group(cands, mode, hits):
    """cands: list[str] inner. Group by hashed-length, batch, check."""
    if not cands: return
    bychar = {}
    for c in cands:
        raw = (PRE + c.encode('latin1','ignore') + SUF) if mode == 'A' else c.encode('latin1','ignore')
        bychar.setdefault(len(raw), []).append((raw, c))
    for L, items in bychar.items():
        B = np.frombuffer(b''.join(r for r, _ in items), np.uint8).reshape(len(items), L)
        r0, r1 = hbatch(B)
        m = (r0 == T0) & (r1 == T1)
        for idx in np.nonzero(m)[0]:
            inner = items[int(idx)][1]
            flag = 'SecurinetsENIT{' + inner + '}'
            hits.append((mode, inner))
            print(f"FLAG_FOUND {mode}: {flag}", flush=True)

def run(common_file, shard, nshards):
    cw = [w.strip() for w in open(common_file, encoding='utf-8', errors='ignore')
          if 2 <= len(w.strip()) <= 14 and w.strip().isalpha()]
    print(f"[phrase_vec] {len(cw)} words, shard {shard}/{nshards}", flush=True)
    hits = []
    import time; t0 = time.time()
    for idx, w1 in enumerate(cw):
        if idx % nshards != shard:
            continue
        cands = []
        for w2 in cw:
            for s in SEPS:
                base = w1 + s + w2
                cands.append(base)
                lv = base.translate(LEET)
                if lv != base:
                    cands.append(lv)
        check_group(cands, 'A', hits)
        check_group(cands, 'B', hits)
        if idx % (nshards * 25) == shard % (nshards * 25) or idx % 500 < nshards:
            print(f"  w1#{idx} ({w1}) done hits={len(hits)} t={time.time()-t0:.0f}s", flush=True)
    print(f"DONE shard {shard} hits={len(hits)} t={time.time()-t0:.0f}s", flush=True)
    if hits:
        with open('FOUND.txt', 'a') as fh:
            for mode, inner in hits:
                fh.write(f"SecurinetsENIT{{{inner}}} [{mode}]\n")
    return hits

if __name__ == '__main__':
    cf = sys.argv[1]
    shard = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    nshards = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    run(cf, shard, nshards)
