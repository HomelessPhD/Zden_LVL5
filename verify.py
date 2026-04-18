"""Helper: verify candidate private keys against target address, with both compressed and uncompressed P2PKH."""
import sys, hashlib
sys.stdout.reconfigure(encoding='utf-8')
import ecdsa
import base58

TARGET = '1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7'
TARGET_HASH160 = base58.b58decode(TARGET)[1:-4]   # strip version byte & checksum
print(f"Target hash160: {TARGET_HASH160.hex()}")
print(f"Target hash160 len: {len(TARGET_HASH160)}")

SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def privkey_to_hashes(priv32: bytes):
    """Return (hash160_compressed, hash160_uncompressed)."""
    pk_int = int.from_bytes(priv32, 'big')
    if pk_int == 0 or pk_int >= SECP_N:
        return None, None
    sk = ecdsa.SigningKey.from_string(priv32, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    xy = vk.to_string()
    x = xy[:32]; y = xy[32:]
    prefix = b'\x03' if (y[-1] & 1) else b'\x02'
    pub_c = prefix + x
    pub_u = b'\x04' + xy

    def h160(b):
        return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()
    return h160(pub_c), h160(pub_u)

def check_key(hex_str: str):
    """Return (compressed_match, uncompressed_match, addr_c_or_None)."""
    if len(hex_str) != 64:
        return False, False, None
    try:
        b = bytes.fromhex(hex_str)
    except ValueError:
        return False, False, None
    h_c, h_u = privkey_to_hashes(b)
    if h_c is None: return False, False, None
    return (h_c == TARGET_HASH160), (h_u == TARGET_HASH160), None

if __name__ == '__main__':
    # Sanity: a random key shouldn't match
    print(check_key('00' * 31 + '01'))
