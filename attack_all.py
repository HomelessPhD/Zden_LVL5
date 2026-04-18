"""FOCUSED final attack on Zden LVL5 with 4 fresh hypotheses.

Base: verified 'follow' pairing. iW_sum has 0x77 at position 17 (Zden's hint).

H1: Trithemian/Vigenere tableau lookup — transform iW_sum bytes via key
H2: (64,32) linear code — pair sum as parity check, not direct byte
H3: Bit/nibble/endian reversal on iW_sum and related bases
H4: 09111819 / 11122111 as tableau offsets (key for Vigenere)
H5: New measurements — aspect ratios, corner positions, diagonals
"""
import sys, json, hashlib
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
    hc, hu = priv_hashes(bytes(key))
    if hc == TARGET: return 'compressed'
    if hu == TARGET: return 'uncompressed'
    return None

def linear(r,c): return (r-1)*8+c
PAIRS = []
for c in range(1,9): PAIRS.append((linear(5,c), linear(3,(c%8)+1)))
for c in range(1,9): PAIRS.append((linear(6,c), linear(2,(c%8)+1)))
for c in range(1,9): PAIRS.append((linear(7,c), linear(1,(c%8)+1)))
for c in range(1,9,2): PAIRS.append((linear(4,c), linear(4,c+1)))
for c in range(1,9,2): PAIRS.append((linear(8,c), linear(8,c+1)))

rects = json.load(open('rects.json'))
iW = [r['inner_W'] for r in rects]
iH = [r['inner_H'] for r in rects]
W = [r['W'] for r in rects]
H = [r['H'] for r in rects]
cx = [r['x'] + r['W']/2 for r in rects]
cy = [r['y'] + r['H']/2 for r in rects]

variants = {}
for name in ['noLine', 'plus', 'minus', 'multiply']:
    rows = []
    with open(f'{name}_A.csv') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) != 3: continue
            rows.append(tuple(int(x) for x in parts))
    variants[name] = rows

hits = []
tried = 0

# ===== H1: Trithemian tableau (Vigenere) =====
# Vigenere: cipher[i] = (plain[i] + key[i % keylen]) mod 26 (or 256 for bytes)
# Apply to iW_sum with various keys
print("=== H1: Vigenere tableau on iW_sum ===")
iW_sum = [(iW[a-1]+iW[b-1]) % 256 for (a,b) in PAIRS]

# Key candidates
keys = [
    ('LXIV', b'LXIV'),
    ('lxiv', b'lxiv'),
    ('ZDEN', b'ZDEN'),
    ('Zd3N', b'Zd3N'),
    ('crypto5', b'crypto5'),
    ('satori', b'satori'),
    ('haluska', b'haluska'),
    ('1crypto', b'1crypto'),
    # Hint digits as bytes
    ('h09111819', bytes([0x09,0x11,0x18,0x19])),
    ('h11122111', bytes([0x11,0x12,0x21,0x11])),
    ('h_both', bytes([0x09,0x11,0x18,0x19,0x11,0x12,0x21,0x11])),
    ('h_decimal', bytes([9,11,18,19,11,12,21,11])),
    # The 17 and 6 line lengths
    ('h176', bytes([17,6])),
    ('h17', bytes([17])),
    ('h6', bytes([6])),
    # 64 as key
    ('h64', bytes([64])),
]

for keyname, key in keys:
    for shift_op in ['add', 'sub', 'xor']:
        seq = []
        for i, b in enumerate(iW_sum):
            k = key[i % len(key)]
            if shift_op == 'add': v = (b + k) % 256
            elif shift_op == 'sub': v = (b - k) % 256
            elif shift_op == 'xor': v = b ^ k
            seq.append(v)
        tried += 1
        res = check(seq)
        if res:
            hits.append(('H1_vigenere', keyname, shift_op, res, bytes(seq).hex()))
            print(f"  !!! {keyname}/{shift_op}: {res} → {bytes(seq).hex()}")

# Also try Beaufort: key - plain mod 256
for keyname, key in keys:
    seq = [(key[i % len(key)] - iW_sum[i]) % 256 for i in range(32)]
    tried += 1
    res = check(seq)
    if res: hits.append(('H1_beaufort', keyname, res, bytes(seq).hex())); print(f"  !!! Beaufort {keyname}: {res}")

# ===== H2: Linear code (64,32) parity interpretation =====
# Maybe each pair defines a PARITY EQUATION: byte_i = rect_{2i-1} XOR rect_{2i}
# Or: use all 64 rects as codeword, extract 32 data bytes via syndrome/decoder
print("\n=== H2: Linear-code (64,32) interpretation ===")
# Try: XOR reduce pairs — already done, but with more base metrics
for base_name, base in [
    ('iW', iW), ('iH', iH), ('W', W), ('H', H),
    ('W+H', [w+h for w,h in zip(W,H)]),
    ('iW+iH', [w+h for w,h in zip(iW,iH)]),
    ('W-iW', [w-x for w,x in zip(W,iW)]),  # border thickness horiz
    ('H-iH', [h-x for h,x in zip(H,iH)]),  # border thickness vert
    ('outer', [r[0] for r in variants['noLine']]),
    ('inner', [r[1] for r in variants['noLine']]),
    ('shell', [r[2] for r in variants['noLine']]),
]:
    # Hadamard / parity-check style: byte = rect_a XOR rect_b
    seq_xor = [(base[a-1] ^ base[b-1]) & 0xFF for (a,b) in PAIRS]
    tried += 1
    res = check(seq_xor)
    if res: hits.append(('H2_xor', base_name, res, bytes(seq_xor).hex())); print(f"  !!! XOR {base_name}: {res}")

    # Sum mod 256
    seq_sum = [(base[a-1] + base[b-1]) % 256 for (a,b) in PAIRS]
    tried += 1
    res = check(seq_sum)
    if res: hits.append(('H2_sum', base_name, res, bytes(seq_sum).hex())); print(f"  !!! SUM {base_name}: {res}")

# ===== H3: Bit/nibble/endian tricks on iW_sum =====
print("\n=== H3: Bit/nibble/endian tricks ===")
def bit_reverse(b): return int(f'{b:08b}'[::-1], 2)
def nibble_swap(b): return ((b & 0xF) << 4) | ((b >> 4) & 0xF)

for base_name, base in [
    ('iW_sum', iW_sum),
    ('iH_sum', [(iH[a-1]+iH[b-1]) % 256 for (a,b) in PAIRS]),
    ('iW_iH_sum', [(iW[a-1]+iH[a-1]+iW[b-1]+iH[b-1]) % 256 for (a,b) in PAIRS]),
    ('iW_xor', [(iW[a-1]^iW[b-1]) & 0xFF for (a,b) in PAIRS]),
    ('iW_mul_256', [(iW[a-1]*iW[b-1]) % 256 for (a,b) in PAIRS]),
]:
    for tname, tfn in [
        ('raw', lambda b: b),
        ('bit_rev', bit_reverse),
        ('nib_swap', nibble_swap),
        ('bit_rev_nib_swap', lambda b: nibble_swap(bit_reverse(b))),
    ]:
        transformed = [tfn(b) for b in base]
        # Also try byte-order swap (reverse the 32 bytes)
        for reverse_seq in [False, True]:
            seq = transformed[::-1] if reverse_seq else transformed
            tried += 1
            res = check(seq)
            if res:
                hits.append(('H3_bits', base_name, tname, reverse_seq, res, bytes(seq).hex()))
                print(f"  !!! {base_name}/{tname}/rev={reverse_seq}: {res}")

# ===== H4: 09111819 / 11122111 as Vigenere key =====  (already covered in H1)

# ===== H5: New measurements =====
print("\n=== H5: New measurements ===")
# Aspect ratios (integer-ized)
ar_o = [W[i]*100//H[i] if H[i] else 0 for i in range(64)]
ar_i = [iW[i]*100//iH[i] if iH[i] else 0 for i in range(64)]
# Absolute pixel corner positions
tlx = [r['x'] for r in rects]
tly = [r['y'] for r in rects]
# Diagonal of outer rect
import math
diag_o = [int(math.hypot(W[i], H[i])) for i in range(64)]
diag_i = [int(math.hypot(iW[i], iH[i])) for i in range(64)]

for base_name, base in [
    ('ar_outer', ar_o), ('ar_inner', ar_i),
    ('tlx', tlx), ('tly', tly),
    ('diag_o', diag_o), ('diag_i', diag_i),
    # Cx, Cy as centers (int)
    ('cx', [int(c) for c in cx]), ('cy', [int(c) for c in cy]),
    # Border thickness (separate horiz vert)
    ('border_h', [(W[i]-iW[i])//2 for i in range(64)]),
    ('border_v', [(H[i]-iH[i])//2 for i in range(64)]),
]:
    for op_name, op in [
        ('sum256', lambda a,b: (a+b) % 256),
        ('xor', lambda a,b: (a^b) & 0xFF),
        ('diff', lambda a,b: (a-b) % 256),
        ('absdiff', lambda a,b: abs(a-b) % 256),
        ('prod', lambda a,b: (a*b) % 256),
    ]:
        seq = [op(base[a-1], base[b-1]) for (a,b) in PAIRS]
        tried += 1
        res = check(seq)
        if res:
            hits.append(('H5', base_name, op_name, res, bytes(seq).hex()))
            print(f"  !!! {base_name}/{op_name}: {res}")
        # Also check 0x77 presence as proxy for "right track"
        if 0x77 in seq:
            cnt77 = seq.count(0x77)
            printable = sum(1 for v in seq if 32 <= v < 127)
            if printable >= 20 or cnt77 >= 2:
                print(f"  -- {base_name}/{op_name}: 0x77×{cnt77}, printable={printable}")

print(f"\n=== FINAL === tried: {tried}, hits: {len(hits)}")
for h in hits: print(h)
