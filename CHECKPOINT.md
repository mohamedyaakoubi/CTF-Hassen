# CHECKPOINT — live solve state (safe to resume after a restart)

> **The search runs on GitHub Actions (server-side). A PC restart does NOT stop it.**
> Runs keep going and upload artifacts to GitHub. Only local watch processes die;
> re-arm them after restart. `gh` auth (OS keyring) and git config survive restart.
> Snapshot time: 2026-10-12 ~01:35 UTC.

## TL;DR of where we are
- Binary fully reversed; the check is a **bit-exact-validated 64-bit two-accumulator hash** (see `README.md`). This part is DONE and correct.
- Remaining task = find the **intended (readable) preimage**. The hash is only 64-bit, so there are many preimages ("collisions"). Every short config tried so far yields only **random** collisions (all wrong). The planted flag is a **readable** string — recognizable by eye — at a longer length.
- Strategy: brute meet-in-the-middle (`layerup_solver.py`) across (mode × charset × length), collect ALL preimages, and pick the one that **reads like words**. Free on public-repo Actions.

## Preimages found so far — ALL WRONG / random (do NOT resubmit)
| string (full flag form) | config | verdict |
|---|---|---|
| `SecurinetsENIT{reilk78u4n_h}` | A, low_dig_us/leet, inner 12 | **submitted → WRONG** |
| `SecurinetsENIT{3hwx60tnoe8j}` | B, low_dig_us/leet, inner 12 | **submitted → WRONG** |
| `SecurinetsENIT{5ff2inb723nm}` | A, leet_sym, inner 12 | random collision (untested, skip) |
| `SecurinetsENIT{cY;Vi[6g7U}`  | A, printable, inner 10 | random collision |
| `SecurinetsENIT{5.EaA7?UAU}`  | A, printable, inner 10 | random collision |

"Mode A" = the whole flag `SecurinetsENIT{...}` is hashed. "Mode B" = only the inner is hashed (flag = wrap it). Both are possible; the binary doesn't check the prefix.

## Configs already EXCLUDED (searched, only noise)
- mode A: low_us ≤13, low ≤12, low_dig(_us) ≤12, leet_sym ≤12, alnum(_us) ≤10, printable ≤10
- mode B: low_us ≤13, low_dig_us ≤12, leet_sym ≤12, alnum ≤10, printable ≤10
(= the first sweep run `38173625361` + heavy runs that returned only random/empty.)

## In-flight runs at snapshot (run-ID → config). THESE CONTINUE DURING RESTART.
Batch 2 (created ~00:40 UTC):
| run id | config | inner len |
|---|---|---|
| 38188918383 | A low_dig_us 29 | 13 |
| 38188920898 | A printable 26 | 10 (done: only collisions) |
| 38188923480 | B printable 10 | 10 |
| 38188925747 | A alnum_us 27 | 11 |

Batch 3 (created ~01:31 UTC) — the most promising (readable lowercase/leet, inner 13–14):
| run id | config | inner len |
|---|---|---|
| 38192196512 | A low_us 30 | 14 |
| 38192199448 | A leet_sym 29 | 13 |
| 38192202174 | A leet_sym 30 | 14 |
| 38192204705 | B low_us 14 | 14 |
| 38192207339 | B leet_sym 13 | 13 |
| 38192209975 | B leet_sym 14 | 14 |

## HOW TO RESUME AFTER RESTART
```bash
cd "/path/to/CTF hassen"          # repo root (git + gh auth already set up)
GH=gh                              # or full path to gh.exe on Windows

# 1) See which runs finished / are still going
$GH run list --workflow solve-heavy --limit 20

# 2) List every preimage found (artifacts survive 90 days)
$GH api repos/mohamedyaakoubi/CTF-Hassen/actions/artifacts --paginate \
   --jq '.artifacts[]|select(.name|startswith("found"))|"\(.workflow_run.id) \(.name)"' | sort -u

# 3) Download + read any found artifact (replace RUNID)
$GH run download RUNID -D out && find out -type f -exec cat {} \;

# 4) THE WIN CONDITION: a preimage whose inner text READS LIKE WORDS
#    (English / leetspeak / theme: layer, onion, boxic, auth, vm, stack...).
#    Random-looking strings are collisions — ignore them.

# 5) Re-arm a watch (optional): poll artifacts every ~90s for new found-*.
```

## DECISION TREE / NEXT STEPS
1. When batch 3 finishes: download all `found-*`, look for a **readable** inner.
   - If found → that's the flag. Submit (prefer mode A spelling first).
2. If batch 3 is all noise → the inner is **>14 chars** (free 16 GB runners can't
   brute-MITM past ~14 lowercase/leet, ~11 alnum, ~10 printable — concurrency/RAM bound).
   Then pivot:
   - Ask the CTF page / author for the **flag length** (biggest unblock).
   - Run a **word/phrase forward search** (wordlist combos + separators + leet),
     hashing candidates directly — extend `analysis/` wordlist approach on CI.
   - Or use a paid larger runner to push MITM to inner 15–18.
3. To launch more MITM configs (free): 
   `gh workflow run solve-heavy.yml -f mode=A -f cs=low_us -f N=31 -f nshards=20`
   (N = 16+inner for mode A, = inner for mode B; cs ∈ low_us, low, leet_sym, alnum_us, printable).

## KEY FACTS (so a fresh session needs nothing else)
- hash: `r0=0x7e4a1c3b; r1=0x2d5f8e11; for i,b: r0=(rol(r0^b,11)*0xa3c59ac3+i)&M; r1=(rol(((r0>>16)*0xcf1bbcdd+r1)&M,7)^b)&M`
- targets: `r0==0xa5219537 and r1==0xc19b6387`. Verify any candidate with `layerup_solver.py` (`hsh`).
- solver + workflows + full writeup already in this repo (`README.md`, `layerup_solver.py`, `.github/workflows/`).
