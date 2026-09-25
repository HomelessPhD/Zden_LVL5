"""Focused final round on Zden LVL5:
Base: iW_sum (and close variants) on verified 'follow' pairing.
Transformations:
  - XOR with various masks (09111819 11122111 as 4/8/32 byte masks, rotated, reversed)
  - Byte permutations (reverse, by_min, by_max, row-major, column-major, snake, etc.)
  - Base metric variants (iW+iH, iW*2+iH, etc.)
"""
import sys, json, hashlib, itertools
sys.stdout.reconfigure(encoding='utf-8')
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
    hc, hu = priv_hashes(bytes(key))
    if hc == TARGET: return 'compressed'
    if hu == TARGET: return 'uncompressed'
    return None

def linear(r, c): return (r-1)*8 + c
PAIRS = []
for c in range(1, 9): PAIRS.append((linear(5, c), linear(3, (c%8)+1)))
for c in range(1, 9): PAIRS.append((linear(6, c), linear(2, (c%8)+1)))
for c in range(1, 9): PAIRS.append((linear(7, c), linear(1, (c%8)+1)))
for c in range(1, 9, 2): PAIRS.append((linear(4, c), linear(4, c+1)))
for c in range(1, 9, 2): PAIRS.append((linear(8, c), linear(8, c+1)))

rects = json.load(open('rects.json'))
iW = [r['inner_W'] for r in rects]
iH = [r['inner_H'] for r in rects]
W  = [r['W'] for r in rects]
H  = [r['H'] for r in rects]

# --- Metrics to try as "byte = f(rect)" or "byte = f(rect_a) + f(rect_b)"
metric_fns = {
    'iW': lambda i: iW[i-1],
    'iH': lambda i: iH[i-1],
    'iW_iH': lambda i: iW[i-1] + iH[i-1],
    'iW+iH': lambda i: iW[i-1] + iH[i-1],
    'iW*iH': lambda i: iW[i-1] * iH[i-1],
    'W': lambda i: W[i-1],
    'H': lambda i: H[i-1],
    'W_iW': lambda i: W[i-1] - iW[i-1],    # border thickness horiz
    'H_iH': lambda i: H[i-1] - iH[i-1],    # border thickness vert
    '2iW_iH': lambda i: 2*iW[i-1] + iH[i-1],
    'iW_2iH': lambda i: iW[i-1] + 2*iH[i-1],
}

def build_base(metric_name, combine='sum', flip=False):
    fn = metric_fns[metric_name]
    out = []
    for (a, b) in PAIRS:
        va = fn(a); vb = fn(b)
        if flip: va, vb = vb, va
        if combine == 'sum': v = va + vb
        elif combine == 'diff': v = va - vb
        elif combine == 'absdiff': v = abs(va - vb)
        elif combine == 'xor': v = va ^ vb
        elif combine == 'prod': v = va * vb
        elif combine == 'starter_only': v = va
        elif combine == 'concat_dec': v = va * 100 + vb
        out.append(v % 256)
    return out

# --- XOR masks derived from 09111819 FIX 11122111 ---
def mask_variants():
    # 8-byte tiled over 32
    m8 = bytes([0x09, 0x11, 0x18, 0x19, 0x11, 0x12, 0x21, 0x11])
    yield 'tile8_fwd', (m8 * 4)
    yield 'tile8_rev', (m8[::-1] * 4)
    # Single constant repeated
    for c in [0x09, 0x11, 0x18, 0x19, 0x12, 0x21, 0x64, 0x77, 0x40, 0x35, 0x80]:
        yield f'const_{c:02x}', bytes([c]*32)
    # Decimal interpretation: each number is one byte, 8 total
    m8_dec = bytes([9, 11, 18, 19, 11, 12, 21, 11])
    yield 'tile8_dec', m8_dec * 4
    # No mask
    yield 'identity', bytes(32)
    # Mask = 0 everywhere except specific positions with specific values
    m = bytearray(32)
    for i, v in enumerate([0x09, 0x11, 0x18, 0x19]):
        m[i] = v
    for i, v in enumerate([0x11, 0x12, 0x21, 0x11]):
        m[28+i] = v
    yield 'endpoint_only', bytes(m)

# --- Permutations ---
def permutations():
    yield 'canon', list(range(32))
    yield 'rev', list(range(31, -1, -1))
    yield 'by_min',  sorted(range(32), key=lambda i: min(PAIRS[i]))
    yield 'by_max',  sorted(range(32), key=lambda i: max(PAIRS[i]))
    yield 'by_start', sorted(range(32), key=lambda i: PAIRS[i][0])
    yield 'by_fol',   sorted(range(32), key=lambda i: PAIRS[i][1])
    yield 'by_sum',   sorted(range(32), key=lambda i: sum(PAIRS[i]))
    # Swap halves
    yield 'halves', list(range(16, 32)) + list(range(0, 16))
    # Transpose as 4x8
    yield 'trans_4x8', [r*4 + c for c in range(4) for r in range(8)]  # might be 32
    yield 'trans_8x4', [r*8 + c for c in range(8) for r in range(4)]
    # Snake order of canon pairs
    order = []
    for r in range(4):
        seg = list(range(r*8, r*8+8))
        if r % 2 == 1: seg.reverse()
        order.extend(seg)
    yield 'snake', order

def apply(base, mask, order):
    out = [base[i] ^ mask[i] for i in range(32)]
    return [out[i] for i in order]

hits = []
tried = 0
metric_names = list(metric_fns.keys())
combine_ops = ['sum', 'diff', 'absdiff', 'xor', 'starter_only', 'prod', 'concat_dec']

for mname in metric_names:
    for combine in combine_ops:
        for flip in [False, True]:
            base = build_base(mname, combine, flip)
            for mask_name, mask in mask_variants():
                if len(mask) != 32: continue
                mixed = [(base[i] ^ mask[i]) & 0xFF for i in range(32)]
                for pname, perm in permutations():
                    if len(perm) != 32: continue
                    seq = [mixed[i] for i in perm]
                    tried += 1
                    res = check(seq)
                    if res:
                        print(f"!!! {mname}/{combine} flip={flip} mask={mask_name} perm={pname} → {res}")
                        print(f"    privkey = {bytes(seq).hex()}")
                        hits.append((mname, combine, flip, mask_name, pname, res, bytes(seq).hex()))

print(f"\nTotal tried: {tried}")
print(f"Hits: {len(hits)}")
for h in hits: print(h)
