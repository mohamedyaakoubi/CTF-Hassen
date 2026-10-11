#!/usr/bin/env python3
"""
Meet-in-the-middle preimage solver for the 'layerup' CTF VM hash.

Hash (validated bit-exact against the real ELF via Unicorn):
    r0 = 0x7e4a1c3b ; r1 = 0x2d5f8e11
    for i, b in enumerate(input_bytes):
        r0 = (rol(r0 ^ b, 11) * 0xa3c59ac3 + i) & 0xffffffff
        r1 = (rol(((r0 >> 16) * 0xcf1bbcdd + r1) & 0xffffffff, 7) ^ b) & 0xffffffff
    accept iff r0 == 0xa5219537 and r1 == 0xc19b6387

Each step is invertible (C1,C2 odd => invertible mod 2^32) so we meet in the
middle. Streaming MITM: store the forward half (sorted) in RAM, stream the
backward half in batches -> memory bounded by the stored half, time ~ big half.

Modes:
  A: hashed input is the full flag  "SecurinetsENIT{" + secret + "}"
  B: hashed input is only the secret (flag = SecurinetsENIT{secret})

CLI:
  python layerup_solver.py one <mode> <charset> <N> <store_k> [batch_cap]
"""
import sys, time, itertools

T0 = 0xa5219537
T1 = 0xc19b6387
R0_INIT = 0x7e4a1c3b
R1_INIT = 0x2d5f8e11
C1 = 0xa3c59ac3
C2 = 0xcf1bbcdd
C1INV = pow(C1, -1, 1 << 32)
MASK = 0xffffffff

def _rol(x, n): n &= 31; return ((x << n) | (x >> (32 - n))) & MASK
def _ror(x, n): return _rol(x, 32 - (n & 31))
def hsh(inp):
    r0, r1 = R0_INIT, R1_INIT
    for i, b in enumerate(inp):
        r0 = (_rol((r0 ^ b) & MASK, 11) * C1 + i) & MASK
        r1 = (_rol(((r0 >> 16) * C2 + r1) & MASK, 7) ^ b) & MASK
    return r0, r1
def sfwd(st, b, i):
    r0, r1 = st
    r0 = (_rol((r0 ^ b) & MASK, 11) * C1 + i) & MASK
    r1 = (_rol(((r0 >> 16) * C2 + r1) & MASK, 7) ^ b) & MASK
    return (r0, r1)
def sbwd(st, b, i):
    r0p, r1p = st
    r0 = _ror(((r0p - i) & MASK) * C1INV & MASK, 11) ^ b
    r1 = (_ror((r1p ^ b) & MASK, 7) - ((r0p >> 16) * C2)) & MASK
    return (r0, r1)

CHARSETS = {
    'low_us':     b'abcdefghijklmnopqrstuvwxyz_',
    'low_dig_us': b'abcdefghijklmnopqrstuvwxyz0123456789_',
    'low_dig':    b'abcdefghijklmnopqrstuvwxyz0123456789',
    'low':        b'abcdefghijklmnopqrstuvwxyz',
    'alnum_us':   b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_',
    'alnum':      b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'printable':  bytes(range(0x20, 0x7f)),
    'leet_sym':   b'abcdefghijklmnopqrstuvwxyz0123456789_-!?.',
}
MODES = {'A': (b'SecurinetsENIT{', b'}'), 'B': (b'', b'')}

def _np():
    import numpy as np
    return np

def _vec_fwd(np, R0, R1, B, i, c1, c2, M):
    i = np.uint64(i)
    def rol(x, n):
        n &= 31
        return x & M if n == 0 else ((x << np.uint64(n)) | (x >> np.uint64(32 - n))) & M
    R0 = (rol((R0 ^ B) & M, 11) * c1 + i) & M
    R1 = (rol((((R0 >> np.uint64(16)) * c2) + R1) & M, 7) ^ B) & M
    return R0, R1

def _vec_bwd(np, R0p, R1p, B, i, c1inv, c2, M):
    i = np.uint64(i)
    def ror(x, n):
        n &= 31
        return x & M if n == 0 else ((x >> np.uint64(n)) | (x << np.uint64(32 - n))) & M
    R0 = ror(((R0p - i) & M) * c1inv & M, 11) ^ B
    R1 = (ror((R1p ^ B) & M, 7) - ((R0p >> np.uint64(16)) * c2)) & M
    return R0, R1

def run_stream(mode, charset_name, N, store_k, batch_cap=80_000_000, verbose=True,
               shard=0, nshards=1, time_cap=None):
    np = _np()
    M = np.uint64(MASK); c1 = np.uint64(C1); c2 = np.uint64(C2); c1inv = np.uint64(C1INV)
    PRE, SUF = MODES[mode]
    charset = CHARSETS[charset_name]
    C = len(charset)
    m = N - len(PRE) - len(SUF)
    if m < 0 or store_k < 0 or store_k > m:
        return []
    p = len(PRE)
    last_mid = N - 1 - len(SUF)
    # anchors
    st_pre = (R0_INIT, R1_INIT)
    for i, b in enumerate(PRE):
        st_pre = sfwd(st_pre, b, i)
    st_suf = (T0, T1)
    for j, b in enumerate(SUF[::-1]):
        st_suf = sbwd(st_suf, b, N - 1 - j)

    cs = np.frombuffer(charset, dtype=np.uint8).astype(np.uint64)
    ar = np.arange(C, dtype=np.uint64)

    # ---- build forward store: left indices p .. p+store_k-1 ----
    R0 = np.array([st_pre[0]], np.uint64); R1 = np.array([st_pre[1]], np.uint64); CODE = np.array([0], np.uint64)
    for i in range(p, p + store_k):
        n = R0.shape[0]
        R0 = np.repeat(R0, C); R1 = np.repeat(R1, C); CODE = np.repeat(CODE, C)
        B = np.tile(cs, n); dig = np.tile(ar, n)
        R0, R1 = _vec_fwd(np, R0, R1, B, i, c1, c2, M)
        CODE = CODE * np.uint64(C) + dig
    store_state = (R0 << np.uint64(32)) | R1
    store_code = CODE
    del R0, R1, CODE
    order = np.argsort(store_state, kind='stable')
    store_state = store_state[order]; store_code = store_code[order]
    if verbose:
        print(f"[store] mode={mode} cs={charset_name} N={N} m={m} store_k={store_k} "
              f"store_size={store_state.shape[0]:,} right_count={m-store_k}", flush=True)

    right_count = m - store_k
    right_idx_desc = list(range(last_mid, p + store_k - 1, -1))  # processed order (high->low)
    # choose outer bytes so inner batch <= batch_cap
    o = 0
    while C ** (right_count - o) > batch_cap:
        o += 1
    # if sharding, ensure enough outer combos to split across shards
    if nshards > 1:
        while C ** o < nshards and o < right_count:
            o += 1
    inner = right_count - o
    outer_idx = right_idx_desc[:o]          # processed first (highest indices)
    inner_idx = right_idx_desc[o:]          # processed after
    if verbose:
        print(f"[stream] right_count={right_count} outer={o} (iters={C**o:,}) inner={inner} (batch={C**inner:,})", flush=True)

    found = []
    def recover(store_code_val, outer_combo, inner_code_val):
        idx2byte = {}
        # left bytes: most-significant digit = index p
        v = int(store_code_val)
        digs = []
        for _ in range(store_k): digs.append(v % C); v //= C
        digs = digs[::-1]
        for t, d in enumerate(digs): idx2byte[p + t] = charset[d]
        # outer bytes: outer_combo[t] at index outer_idx[t]
        for t, by in enumerate(outer_combo): idx2byte[outer_idx[t]] = by
        # inner bytes: most-significant digit = inner_idx[0]
        v = int(inner_code_val); digs = []
        for _ in range(inner): digs.append(v % C); v //= C
        digs = digs[::-1]
        for t, d in enumerate(digs): idx2byte[inner_idx[t]] = charset[d]
        mid = bytes(idx2byte[i] for i in range(p, last_mid + 1))
        hashed = PRE + mid + SUF
        if hsh(hashed) == (T0, T1):
            full = (b'SecurinetsENIT{' + mid + b'}') if mode == 'B' else hashed
            return full
        return None

    t0 = time.time()
    outer_iter = itertools.product(cs.tolist(), repeat=o) if o > 0 else [()]
    cnt = 0
    stopped = False
    for oc_index, outer_combo_u in enumerate(outer_iter):
        if nshards > 1 and (oc_index % nshards) != shard:
            continue
        if time_cap is not None and (time.time() - t0) > time_cap:
            print(f"[timecap] stopping after {time.time()-t0:.0f}s at outer {oc_index}/{C**o}", flush=True)
            stopped = True
            break
        cnt += 1
        st = st_suf
        for t, bu in enumerate(outer_combo_u):
            st = sbwd(st, int(bu), outer_idx[t])
        # vectorized inner backward from scalar st
        R0 = np.array([st[0]], np.uint64); R1 = np.array([st[1]], np.uint64); CODE = np.array([0], np.uint64)
        for i in inner_idx:
            n = R0.shape[0]
            R0 = np.repeat(R0, C); R1 = np.repeat(R1, C); CODE = np.repeat(CODE, C)
            B = np.tile(cs, n); dig = np.tile(ar, n)
            R0, R1 = _vec_bwd(np, R0, R1, B, i, c1inv, c2, M)
            CODE = CODE * np.uint64(C) + dig
        SR = (R0 << np.uint64(32)) | R1
        # match SR against sorted store_state
        pos = np.searchsorted(store_state, SR)
        pos_ok = pos < store_state.shape[0]
        hit = np.zeros(SR.shape[0], dtype=bool)
        hit[pos_ok] = store_state[pos[pos_ok]] == SR[pos_ok]
        if hit.any():
            hidx = np.where(hit)[0]
            for hi in hidx:
                sidx = int(pos[hi])
                outer_combo = tuple(int(x) for x in outer_combo_u)
                full = recover(store_code[sidx], outer_combo, int(CODE[hi]))
                if full and full not in found:
                    found.append(full)
                    print("FLAG_FOUND:", full.decode('latin1'), flush=True)
        if verbose and o > 0 and cnt % max(1, (C ** o) // 20) == 0:
            print(f"[progress] {cnt}/{C**o} outer ({100*cnt/(C**o):.0f}%) {time.time()-t0:.0f}s found={len(found)}", flush=True)
    if verbose:
        print(f"[done] mode={mode} cs={charset_name} N={N} store_k={store_k} time={time.time()-t0:.1f}s found={len(found)}", flush=True)
    return found

def pick_store_k(C, m, store_cap):
    """Largest k <= m with C**k <= store_cap (bounds build-RAM of the stored half)."""
    k = 0
    while k < m and C ** (k + 1) <= store_cap:
        k += 1
    return k

def run_auto(mode, charset_name, N, store_cap=150_000_000, batch_cap=50_000_000,
             stream_cap=None, shard=0, nshards=1, time_cap=None):
    """Pick store_k automatically from RAM budget, then run streaming MITM."""
    C = len(CHARSETS[charset_name])
    PRE, SUF = MODES[mode]
    m = N - len(PRE) - len(SUF)
    if m < 1:
        return []
    k = pick_store_k(C, m, store_cap)
    right_total = C ** (m - k)
    print(f"[auto] mode={mode} cs={charset_name} N={N} m={m} C={C} store_k={k} "
          f"store={C**k:,} stream_total={right_total:,} shards={nshards}", flush=True)
    if stream_cap is not None and right_total > stream_cap:
        print(f"[auto] SKIP: stream_total {right_total:,} > stream_cap {stream_cap:,} (too slow)", flush=True)
        return []
    return run_stream(mode, charset_name, N, k, batch_cap=batch_cap, verbose=True,
                      shard=shard, nshards=nshards, time_cap=time_cap)

def _env_int(name, default):
    import os
    v = os.environ.get(name)
    return int(float(v)) if v else default

if __name__ == '__main__':
    import os
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    store_cap = _env_int('STORE_CAP', 150_000_000)
    batch_cap = _env_int('BATCH_CAP', 50_000_000)
    stream_cap = _env_int('STREAM_CAP', 200_000_000_000)
    time_cap = _env_int('TIME_CAP', 0) or None
    shard = _env_int('SHARD', 0)
    nshards = _env_int('NSHARDS', 1)
    all_found = []
    if cmd == 'one':
        mode, cname, N, sk = sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
        all_found = run_stream(mode, cname, N, sk, batch_cap=batch_cap, shard=shard,
                               nshards=nshards, time_cap=time_cap)
    elif cmd == 'auto':
        mode, cname, N = sys.argv[2], sys.argv[3], int(sys.argv[4])
        all_found = run_auto(mode, cname, N, store_cap, batch_cap, stream_cap, shard, nshards, time_cap)
    elif cmd == 'sweep':
        mode, cname, nmin, nmax = sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
        for N in range(nmin, nmax + 1):
            r = run_auto(mode, cname, N, store_cap, batch_cap, stream_cap, shard, nshards, time_cap)
            all_found.extend(r)
    else:
        print(__doc__); sys.exit(0)
    print("RESULT:", [f.decode('latin1') for f in all_found], flush=True)
    if all_found:
        with open('FOUND.txt', 'a') as fh:
            for f in all_found:
                fh.write(f.decode('latin1') + "\n")
        # verify once more and emit a loud marker
        for f in set(all_found):
            mid = f[len(b'SecurinetsENIT{'):-1]
            print(f"VERIFIED full={hsh(f)==(T0,T1)} inner={hsh(mid)==(T0,T1)} :: {f.decode('latin1')}", flush=True)
