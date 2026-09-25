"""Use the verified 'follow' pairing rule — tries every byte order + every operation.

Pairing rule (matches hint): (r, c) → (8-r, (c mod 8)+1), with row 4 and row 8 self-pairing.

Generates 32 ordered pairs:
  Row 5 starters (pair with row 3):
    (33,18),(34,19),(35,20),(36,21),(37,22),(38,23),(39,24),(40,17)
  Row 6 starters (pair with row 2):
    (41,10),(42,11),(43,12),(44,13),(45,14),(46,15),(47,16),(48,9)
  Row 7 starters (pair with row 1):
    (49,2),(50,3),(51,4),(52,5),(53,6),(54,7),(55,8),(56,1)
  Row 4 self-pairs: (25,26),(27,28),(29,30),(31,32)
  Row 8 self-pairs: (57,58),(59,60),(61,62),(63,64)

Exhaust byte orderings × operations × area metrics.
"""
import sys, hashlib
sys.stdout.reconfigure(encoding='utf-8')
from collections import defaultdict
import ecdsa

TARGET = bytes.fromhex('06c84797d2441393513e2169338e00cf2e755c8c')
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def h160(b): return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()
def priv_hashes(priv):
    n = int.from_bytes(priv, 'big')
    if n == 0 or n >= SECP_N: return None, None
    sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    xy = sk.verifying_key.to_string()
    x, y = xy[:32], xy[32:]
    prefix = b'\x03' if (y[-1] & 1) else b'\x02'
    return h160(prefix + x), h160(b'\x04' + xy)

def check(key):
    if len(key) != 32: return None
    b = bytes(key)
    hc, hu = priv_hashes(b)
    if hc == TARGET: return 'compressed'
    if hu == TARGET: return 'uncompressed'
    return None

# Build the 32 canonical pairs (ordered: starter first)
PAIRS_CANON = []
def linear(r, c): return (r-1)*8 + c

# Row 5 pairs with row 3 (starter = row 5)
for c in range(1, 9):
    s = linear(5, c)
    f_c = (c % 8) + 1
    f = linear(3, f_c)
    PAIRS_CANON.append((s, f))

# Row 6 pairs with row 2 (starter = row 6)
for c in range(1, 9):
    s = linear(6, c)
    f_c = (c % 8) + 1
    f = linear(2, f_c)
    PAIRS_CANON.append((s, f))

# Row 7 pairs with row 1 (starter = row 7)
for c in range(1, 9):
    s = linear(7, c)
    f_c = (c % 8) + 1
    f = linear(1, f_c)
    PAIRS_CANON.append((s, f))

# Row 4 self: (25,26), (27,28), (29,30), (31,32)
for c in range(1, 9, 2):
    PAIRS_CANON.append((linear(4, c), linear(4, c+1)))

# Row 8 self: (57,58), (59,60), (61,62), (63,64)
for c in range(1, 9, 2):
    PAIRS_CANON.append((linear(8, c), linear(8, c+1)))

print(f"Canonical pairs: {len(PAIRS_CANON)}")
print(f"First few: {PAIRS_CANON[:10]}")
print(f"  #40 pair: {[p for p in PAIRS_CANON if 40 in p]}")
print(f"  #53 pair: {[p for p in PAIRS_CANON if 53 in p]}")

# Verify all 64 rects covered once
all_rects = []
for a, b in PAIRS_CANON:
    all_rects.extend([a, b])
assert sorted(all_rects) == list(range(1, 65)), "Coverage failed!"
print(f"Coverage verified: all 1..64 ✓")

# Load areas
variants = {}
for name in ['noLine', 'plus', 'minus', 'multiply']:
    rows = []
    with open(f'{name}_A.csv') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) != 3: continue
            rows.append(tuple(int(x) for x in parts))
    variants[name] = rows

# Byte orderings: 32 orderings of PAIRS_CANON
def orderings():
    yield 'canon', list(range(32))
    # Reverse
    yield 'rev', list(range(31, -1, -1))
    # By min-index of pair (ascending)
    idx_min = sorted(range(32), key=lambda i: min(PAIRS_CANON[i]))
    yield 'by_min_idx', idx_min
    # By max-index of pair
    idx_max = sorted(range(32), key=lambda i: max(PAIRS_CANON[i]))
    yield 'by_max_idx', idx_max
    # By sum of pair
    idx_sum = sorted(range(32), key=lambda i: sum(PAIRS_CANON[i]))
    yield 'by_sum', idx_sum
    # Reverse reading of rects 1..64 (pair containing rect 1 first, then 2, etc.)
    order = []
    seen = set()
    for n in range(1, 65):
        for i, p in enumerate(PAIRS_CANON):
            if n in p and i not in seen:
                order.append(i); seen.add(i); break
    yield 'by_rect_order', order

def ops():
    yield ('sum256', lambda a,b: (a+b) % 256)
    yield ('sumM1', lambda a,b: (a+b-1) % 256)
    yield ('sumP64', lambda a,b: (a+b+64) % 256)
    yield ('sumM64', lambda a,b: (a+b-64) % 256)
    yield ('diff256', lambda a,b: (a-b) % 256)
    yield ('absdiff', lambda a,b: abs(a-b) % 256)
    yield ('xor', lambda a,b: (a^b) & 0xFF)
    yield ('prod256', lambda a,b: (a*b) % 256)
    yield ('sum_x8', lambda a,b: ((a+b)*8) % 256)
    yield ('sumM1_x8', lambda a,b: ((a+b-1)*8) % 256)
    yield ('sum_div64', lambda a,b: ((a+b) // 64) & 0xFF)
    yield ('sum_div16', lambda a,b: ((a+b) // 16) & 0xFF)
    yield ('sum_mod64', lambda a,b: (a+b) % 64)
    yield ('sum_mod64_x4', lambda a,b: ((a+b) % 64) * 4 & 0xFF)
    yield ('sum_xor64', lambda a,b: ((a+b) ^ 64) & 0xFF)
    yield ('s_rshift4', lambda a,b: ((a+b) >> 4) & 0xFF)
    yield ('s_rshift6', lambda a,b: ((a+b) >> 6) & 0xFF)
    yield ('s_rshift8', lambda a,b: ((a+b) >> 8) & 0xFF)
    yield ('negS_p64', lambda a,b: (-(a+b)+64) % 256)
    yield ('s_minus_17', lambda a,b: (a+b-17) % 256)
    yield ('s_minus_6', lambda a,b: (a+b-6) % 256)
    yield ('s_xor17', lambda a,b: ((a+b) ^ 17) & 0xFF)
    yield ('s_xor6', lambda a,b: ((a+b) ^ 6) & 0xFF)
    yield ('avgR', lambda a,b: ((a+b) // 2) % 256)
    yield ('avg_minus1', lambda a,b: ((a+b)//2 - 1) % 256)

hits = []
tried = 0
for vname, rows in variants.items():
    for midx in range(3):
        vec = [r[midx] for r in rows]
        mname = ['outer', 'inner', 'shell'][midx]
        for flip in [False, True]:
            pair_list = [(b, a) if flip else (a, b) for (a, b) in PAIRS_CANON]
            # Raw streams (apply each op over 32 raw pairs in canon order)
            for opname, op in ops():
                raw_canon = [op(vec[a-1], vec[b-1]) for (a, b) in pair_list]
                for oname, idx_list in orderings():
                    seq = [raw_canon[i] for i in idx_list]
                    tried += 1
                    res = check(seq)
                    if res:
                        print(f"!!! {vname}/{mname} flip={flip} op={opname} order={oname} → {res}")
                        print(f"    privkey = {bytes(seq).hex()}")
                        hits.append((vname, mname, flip, opname, oname, res, bytes(seq).hex()))

print(f"\nTotal tried: {tried}")
print(f"Hits: {len(hits)}")
