"""
PA#15 — Digital Signatures (RSA + DLP Hash)
Depends on: PA#12 (RSA), PA#8 (DLP_Hash)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa12_rsa.rsa import rsa_keygen, rsa_enc, rsa_dec, RSA_KeyPair
from pa08_dlp_crhf.dlp_crhf import DLP_Hash
from pa13_miller_rabin.miller_rabin import _square_and_multiply


# ── RSA Digital Signature ─────────────────────────────────────────────────────

class RSA_Signature:
    """
    RSA digital signature with DLP hash.
    Sign(sk, m) = H(m)^d mod n
    Verify(pk, m, sigma) = (sigma^e mod n == H(m))
    """

    def __init__(self, kp: RSA_KeyPair, hash_fn: DLP_Hash):
        self.kp = kp
        self.H = hash_fn
        self.n_bytes = (kp.n.bit_length() + 7) // 8

    def _hash_to_int(self, m: bytes) -> int:
        """Hash message and convert to integer, reduced mod n."""
        h = self.H.hash(m)
        return int.from_bytes(h, 'big') % self.kp.n

    def Sign(self, sk: tuple, m: bytes) -> int:
        """Sign message m. Returns signature sigma = H(m)^d mod n."""
        n, d = sk
        h_int = self._hash_to_int(m)
        sigma = _square_and_multiply(h_int, d, n)
        return sigma

    def Verify(self, pk: tuple, m: bytes, sigma: int) -> bool:
        """Verify signature. Returns True iff sigma^e ≡ H(m) (mod n)."""
        n, e = pk
        recovered = _square_and_multiply(sigma, e, n)
        h_int = self._hash_to_int(m)
        return recovered == h_int


# ── Multiplicative Homomorphism Forgery (raw RSA without hashing) ─────────────

def demo_multiplicative_forgery(kp: RSA_KeyPair) -> None:
    """
    Raw RSA signing (no hash) is vulnerable to multiplicative forgery.
    If we have sigma_1 = m1^d and sigma_2 = m2^d,
    then sigma_1 * sigma_2 ≡ (m1 * m2)^d (mod n).
    """
    print("\n[Raw RSA Forgery (no hash)]")

    def raw_sign(m_int: int) -> int:
        return _square_and_multiply(m_int, kp.d, kp.n)

    def raw_verify(m_int: int, sigma: int) -> bool:
        recovered = _square_and_multiply(sigma, kp.e, kp.n)
        return recovered == m_int

    m1 = 100
    m2 = 200
    sigma_1 = raw_sign(m1)
    sigma_2 = raw_sign(m2)

    # Forged signature for m1*m2 without knowing d
    m_forged = (m1 * m2) % kp.n
    sigma_forged = (sigma_1 * sigma_2) % kp.n

    valid = raw_verify(m_forged, sigma_forged)
    print(f"  Sign({m1}) and Sign({m2}) obtained from oracle")
    print(f"  Forged signature for {m_forged} = {m1}*{m2}: valid = {valid}")
    print(f"  Hashing prevents this: H(m1)*H(m2) ≠ H(m1*m2) in general")


# ── EUF-CMA Game ──────────────────────────────────────────────────────────────

def euf_cma_signature(sig: RSA_Signature, pk: tuple, sk: tuple, queries: int = 50) -> dict:
    """
    EUF-CMA game for signatures.
    Adversary gets signing oracle, tries to forge signature on new message.
    """
    signed = {}
    for _ in range(queries):
        m = os.urandom(16)
        s = sig.Sign(sk, m)
        signed[m] = s

    forgeries = 0
    for _ in range(10):
        m_new = os.urandom(16)
        if m_new in signed:
            continue
        # Adversary tries random signature
        sigma_guess = int.from_bytes(os.urandom(sig.n_bytes), 'big') % sig.kp.n
        if sig.Verify(pk, m_new, sigma_guess):
            forgeries += 1

    return {'queries': queries, 'forgeries': forgeries}


if __name__ == "__main__":
    print("=== PA#15: Digital Signatures ===\n")

    print("[Building components...]")
    kp = rsa_keygen(bits=512)
    dlp = DLP_Hash(bits=32)
    sig = RSA_Signature(kp, dlp)

    # Sign/verify
    print("\n[Sign and Verify]")
    pk = kp.public_key
    sk = kp.private_key
    for m in [b"Hello", b"Sign this message", b"A" * 100]:
        sigma = sig.Sign(sk, m)
        v = sig.Verify(pk, m, sigma)
        # Tamper
        sigma_bad = (sigma + 1) % kp.n
        v_bad = sig.Verify(pk, m, sigma_bad)
        print(f"  Sign({m[:20]!r}): verify={v}, tampered_verify={v_bad}")

    # Wrong message
    sigma_test = sig.Sign(sk, b"message A")
    v_wrong = sig.Verify(pk, b"message B", sigma_test)
    print(f"\n  Sign(A), Verify(B): {v_wrong} (expected False)")

    demo_multiplicative_forgery(kp)

    result = euf_cma_signature(sig, pk, sk, queries=50)
    print(f"\n[EUF-CMA game] {result}")
