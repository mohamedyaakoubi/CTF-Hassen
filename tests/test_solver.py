"""Self-tests for layerup_solver: streaming MITM must recover known preimages,
and sharded runs must collectively cover the same space."""
import importlib.util, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location('L', os.path.join(ROOT, 'layerup_solver.py'))
L = importlib.util.module_from_spec(spec); spec.loader.exec_module(L)

def check(mode, cs, known, store_k, shards=1):
    t0, t1 = L.hsh(known); L.T0 = t0; L.T1 = t1
    N = len(known)
    exp = known if mode == 'A' else (b'SecurinetsENIT{' + known + b'}')
    allfound = []
    for s in range(shards):
        allfound += L.run_stream(mode, cs, N, store_k, batch_cap=3_000_000,
                                 verbose=False, shard=s, nshards=shards)
    ok = exp in allfound
    print(f"mode={mode} cs={cs} known={known.decode()} shards={shards} OK={ok} found={[f.decode() for f in allfound]}")
    return ok

def main():
    allok = True
    allok &= check('A', 'low',        b'SecurinetsENIT{abcdefghij}', 5)        # m=10
    allok &= check('A', 'low_us',     b'SecurinetsENIT{a_c_e_g_i}', 4)         # m=9 w/ underscores
    allok &= check('A', 'alnum',      b'SecurinetsENIT{Ab3Df6Hi}', 4)          # m=8 mixed
    allok &= check('A', 'printable',  b'SecurinetsENIT{aB!d}', 2)              # m=4 symbols
    allok &= check('B', 'low',        b'onionlayer', 4)                        # mode B, m=10
    allok &= check('A', 'low',        b'SecurinetsENIT{abcdefghi}', 4, shards=3)  # sharding coverage
    print("ALL_VALID" if allok else "VALIDATION_FAILED")
    sys.exit(0 if allok else 1)

if __name__ == '__main__':
    main()
