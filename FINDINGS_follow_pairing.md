# LVL5 — Follow-Pairing Rule (community research note)

*Contributed as a research note. This does **not** solve the puzzle — it pins down the pairing rule the hint images encode, which narrows the remaining search space.*

## TL;DR

The rule for pairing the 64 rectangles into 32 "following" pairs is:

```
follow(row r, col c)  →  (row 8 − r,  col ((c mod 8) + 1))
```

With row 4 and row 8 self-pairing (those rows pair within themselves with `c ↔ c+1 (mod 8)`).

This uniquely satisfies **both** hint lines the author added in the 2021 "fix":

- 17-pixel line under `#40 (row 5, col 8)` → pairs with `(row 3, col 1) = #17` ✓
- 6-pixel line under `#53 (row 7, col 5)` → pairs with `(row 1, col 6) = #6` ✓

It also produces exactly **32 disjoint pairs covering all 64 rects** (no strays).

## Canonical pair list (32 pairs, starter first)

```
Row 5 → Row 3:  (33,18)(34,19)(35,20)(36,21)(37,22)(38,23)(39,24)(40,17)
Row 6 → Row 2:  (41,10)(42,11)(43,12)(44,13)(45,14)(46,15)(47,16)(48, 9)
Row 7 → Row 1:  (49, 2)(50, 3)(51, 4)(52, 5)(53, 6)(54, 7)(55, 8)(56, 1)
Row 4 self   :  (25,26)(27,28)(29,30)(31,32)
Row 8 self   :  (57,58)(59,60)(61,62)(63,64)
```

Why this pairing wasn't tried in the original README: the four pairings HomelessPhD
enumerated (consec, col-vertical, row-col interleave, mixed) all ignore the `(c mod 8) + 1`
shift, so none of them produce `(40,17)` or `(53,6)` as a pair.

## Evidence of being close to the right track

Using this pairing with `byte = (inner_W(starter) + inner_W(follower)) mod 256`
(where `inner_W` is the bounding-box inner width of each shell — matches the line
lengths for #40 and #53 exactly), the output is:

```
534861294f4d455e184a695a2b2e672b7d775794492a4e506d537884625a5543
                                   ^^
```

Byte **`0x77` appears at position 17** (0-indexed). This matches Zden's 2018
Xmas tweet hint: *"Byte 0x77 is part of the private key."*

The resulting 32 bytes **do not** produce the target hash160
(`06c84797d2441393513e2169338e00cf2e755c8c`), so there's at least one more
transformation step between `inner_W` sums and the actual private key bytes.

## What was tested and rejected (≈2M total combinations)

With the follow-pairing above:

- Affine byte formulas `((K1·op + K2) // K3) mod K4` across 7×11×6×3 constants, 5 pair-ops, 4 line-variants, 3 metrics, 2 flips, 4 orderings — 1.83M combos
- Nibble-packing of inner widths (hi-lo and lo-hi)
- XOR masks derived from `09111819 FIX 11122111` (tiled 8-byte, single-byte constants, endpoint-only) × 11 byte permutations
- Vigenère/Beaufort with keys `LXIV, lxiv, ZDEN, Zd3N, crypto5, satori, haluska, 1crypto, {09,11,18,19}, {17,6}, {64}`
- Bit-reversal, nibble-swap, byte-order reversal on several bases
- New per-rect metrics: aspect ratio, corner absolute x/y, diagonals, border thickness
- Linear-code (64,32) interpretation with XOR reduce on 10 bases
- SHA256 of concatenated area strings in 8 formats
- PNG inspected for hidden layers: pure 2-value bitmap, no alpha, no LSB payload, no text chunks

None produced the target hash160.

## Suggestions for next researchers

1. **Test the Vigenère cipher direction more carefully** — GitHub issue #1 claims a
   Vigenère approach produced a result. My key space was probably too narrow.
2. **`09111819 FIX 11122111` interpreted as offsets/indices** into a Trithemian
   tableau (not just as bytes) — Zden's puzzle author Trithemius reference is suspicious.
3. **A second hidden measurement** (à la Zden's 1BiTCoiN White Paper puzzle which
   used line slopes beneath the main visualization).
4. **Zden (@Zd3N on X)** is active — asking directly for a 4th hint may be more
   efficient than another million brute-force combos.

## Reproducibility

Code at: https://github.com/consigcody94/Zden_LVL5/tree/findings/follow-pairing-rule
(see `solver_follow.py`, `solver_xor_perm.py`, `attack_all.py`).
Uses HomelessPhD's published area CSVs + bounding-box inner width from OpenCV.

---

*Prepared in collaboration with Claude Code (Opus 4.7). All prior attempts credited to
HomelessPhD's repo README.*
