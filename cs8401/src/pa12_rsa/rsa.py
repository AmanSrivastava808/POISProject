"""
PA#12 — Textbook RSA + PKCS#1 v1.5
Depends on: PA#13 (gen_prime, _square_and_multiply)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa13_miller_rabin.miller_rabin import gen_prime, _square_and_multiply


# ── Extended Euclidean Algorithm ──────────────────────────────────────────────

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1


def mod_inverse(a: int, m: int) -> int:
    """Modular inverse of a mod m using extended Euclidean algorithm."""
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"No modular inverse: gcd({a}, {m}) = {gcd}")
    return x % m


# ── RSA Key Generation ────────────────────────────────────────────────────────

class RSA_KeyPair:
    """RSA key pair container."""
    def __init__(self, n, e, d, p, q):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        # CRT components for PA#14
        self.dp = d % (p - 1)
        self.dq = d % (q - 1)
        self.q_inv = mod_inverse(q, p)

    @property
    def public_key(self):
        return (self.n, self.e)

    @property
    def private_key(self):
        return (self.n, self.d)


def rsa_keygen(bits: int = 512) -> RSA_KeyPair:
    """
    Generate RSA key pair.
    n = p*q, phi = (p-1)*(q-1), e = 65537, d = e^{-1} mod phi.
    """
    e = 65537
    half = bits // 2
    while True:
        p = gen_prime(half)
        q = gen_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        try:
            d = mod_inverse(e, phi)
        except ValueError:
            continue
        return RSA_KeyPair(n, e, d, p, q)


# ── RSA Encryption / Decryption ───────────────────────────────────────────────

def rsa_enc(pk: tuple, m: int) -> int:
    """Textbook RSA encryption: c = m^e mod n."""
    n, e = pk
    assert 0 < m < n, "Message must be in (0, n)"
    return _square_and_multiply(m, e, n)


def rsa_dec(sk: tuple, c: int) -> int:
    """Textbook RSA decryption: m = c^d mod n."""
    n, d = sk
    return _square_and_multiply(c, d, n)


# ── PKCS#1 v1.5 Padding ───────────────────────────────────────────────────────

def pkcs1_v15_pad(m: bytes, n_bytes: int) -> bytes:
    """
    PKCS#1 v1.5 encryption padding.
    Format: 0x00 || 0x02 || PS || 0x00 || M
    PS is random non-zero bytes, minimum 8 bytes.
    """
    if len(m) > n_bytes - 11:
        raise ValueError("Message too long for PKCS#1 v1.5 padding")
    ps_len = n_bytes - len(m) - 3
    if ps_len < 8:
        raise ValueError("Key too small for message")
    # PS: random non-zero bytes
    ps = b''
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b != b'\x00':
            ps += b
    return b'\x00\x02' + ps + b'\x00' + m


def pkcs1_v15_unpad(padded: bytes) -> bytes:
    """
    PKCS#1 v1.5 unpadding. Returns ⊥ (raises ValueError) on malformed padding.
    """
    if len(padded) < 11:
        raise ValueError("⊥: padded message too short")
    if padded[0] != 0x00 or padded[1] != 0x02:
        raise ValueError("⊥: invalid PKCS#1 header")
    # Find 0x00 separator after PS (minimum 8 bytes of PS)
    sep_idx = padded.find(b'\x00', 2)
    if sep_idx < 10:  # 2 header + at least 8 PS bytes
        raise ValueError("⊥: PS too short or no separator")
    return padded[sep_idx + 1:]


def rsa_enc_pkcs1(pk: tuple, m: bytes) -> int:
    """RSA encryption with PKCS#1 v1.5 padding."""
    n, e = pk
    n_bytes = (n.bit_length() + 7) // 8
    padded = pkcs1_v15_pad(m, n_bytes)
    m_int = int.from_bytes(padded, 'big')
    return rsa_enc(pk, m_int)


def rsa_dec_pkcs1(sk: tuple, c: int) -> bytes:
    """RSA decryption with PKCS#1 v1.5 unpadding."""
    n, d = sk
    n_bytes = (n.bit_length() + 7) // 8
    m_int = rsa_dec(sk, c)
    padded = m_int.to_bytes(n_bytes, 'big')
    return pkcs1_v15_unpad(padded)


# ── Bleichenbacher Oracle (simplified) ───────────────────────────────────────

class BleichenbacherOracle:
    """
    Simplified Bleichenbacher padding oracle for 512-bit N.
    Returns True if decrypted ciphertext has valid PKCS#1 v1.5 padding.
    """

    def __init__(self, sk: tuple):
        self.sk = sk
        self.n, self.d = sk
        self.n_bytes = (self.n.bit_length() + 7) // 8

    def is_pkcs_conformant(self, c: int) -> bool:
        """Oracle: returns True if decryption of c has valid PKCS#1 padding."""
        m_int = rsa_dec(self.sk, c)
        padded = m_int.to_bytes(self.n_bytes, 'big')
        try:
            pkcs1_v15_unpad(padded)
            return True
        except ValueError:
            return False

    def demo_attack(self, pk: tuple, ciphertext: int) -> None:
        """
        Demonstrate the Bleichenbacher attack concept.
        Full implementation would use binary search with oracle queries.
        """
        print("\n  [Bleichenbacher Oracle Demo]")
        conformant = self.is_pkcs_conformant(ciphertext)
        print(f"  Original ciphertext is PKCS-conformant: {conformant}")
        # Multiply by 2^e mod n (homomorphic property: enc(2m))
        e = pk[1]
        factor = rsa_enc(pk, 2)
        modified_c = (ciphertext * factor) % pk[0]
        conformant2 = self.is_pkcs_conformant(modified_c)
        print(f"  Modified ciphertext (2m) is PKCS-conformant: {conformant2}")
        print(f"  Full Bleichenbacher attack uses oracle queries to recover plaintext!")


# ── Determinism attack demo ───────────────────────────────────────────────────

def demo_determinism_attack(pk: tuple, sk: tuple) -> None:
    """Textbook RSA: same plaintext → same ciphertext (deterministic)."""
    print("\n[Determinism Attack]")
    m = 12345
    c1 = rsa_enc(pk, m)
    c2 = rsa_enc(pk, m)
    print(f"  rsa_enc(pk, {m}) twice:")
    print(f"  c1 == c2: {c1 == c2}  ← INSECURE: ciphertext reveals message identity")

    # PKCS#1 v1.5: randomized padding defeats this
    m_bytes = b"secret"
    c1_pkcs = rsa_enc_pkcs1(pk, m_bytes)
    c2_pkcs = rsa_enc_pkcs1(pk, m_bytes)
    print(f"\n  PKCS#1 v1.5 encryptions of same message:")
    print(f"  c1 == c2: {c1_pkcs == c2_pkcs}  ← Randomized padding prevents this")


if __name__ == "__main__":
    print("=== PA#12: Textbook RSA + PKCS#1 v1.5 ===\n")

    print("[Generating 512-bit RSA key pair...]")
    kp = rsa_keygen(bits=512)
    pk = kp.public_key
    sk = kp.private_key

    print(f"  n = {str(kp.n)[:30]}...")
    print(f"  e = {kp.e}")
    print(f"  d = {str(kp.d)[:30]}...")

    # Textbook RSA
    print("\n[Textbook RSA]")
    m = 42
    c = rsa_enc(pk, m)
    m_dec = rsa_dec(sk, c)
    print(f"  enc({m}) = {str(c)[:20]}...")
    print(f"  dec(c) = {m_dec}")
    print(f"  correct: {m == m_dec}")

    # PKCS#1 v1.5
    print("\n[PKCS#1 v1.5]")
    m_bytes = b"Hello RSA"
    c_pkcs = rsa_enc_pkcs1(pk, m_bytes)
    m_dec_pkcs = rsa_dec_pkcs1(sk, c_pkcs)
    print(f"  encrypt({m_bytes!r}) = {str(c_pkcs)[:20]}...")
    print(f"  decrypt = {m_dec_pkcs!r}")
    print(f"  correct: {m_bytes == m_dec_pkcs}")

    demo_determinism_attack(pk, sk)

    # Bleichenbacher
    oracle = BleichenbacherOracle(sk)
    m_test = b"test"
    c_test = rsa_enc_pkcs1(pk, m_test)
    oracle.demo_attack(pk, c_test)

    # CRT components for PA#14
    print(f"\n[CRT components for PA#14]")
    print(f"  dp  = d mod (p-1) = {str(kp.dp)[:20]}...")
    print(f"  dq  = d mod (q-1) = {str(kp.dq)[:20]}...")
    print(f"  q_inv = q^(-1) mod p = {str(kp.q_inv)[:20]}...")
