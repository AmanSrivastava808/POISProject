"""
PA#16 — ElGamal Public-Key Encryption
Depends on: PA#11 (DHGroup)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa11_dh.dh import DHGroup
from pa13_miller_rabin.miller_rabin import _square_and_multiply


# ── ElGamal Key Generation ────────────────────────────────────────────────────

class ElGamal_KeyPair:
    def __init__(self, group: DHGroup, x: int, h: int):
        self.group = group
        self.x = x   # private key
        self.h = h   # public key h = g^x mod p

    @property
    def public_key(self):
        return (self.group, self.h)

    @property
    def private_key(self):
        return (self.group, self.x)


def elgamal_keygen(group: DHGroup) -> ElGamal_KeyPair:
    """Sample x ← Zq, compute h = g^x mod p."""
    x = group.random_exponent()
    h = group.power(group.g, x)
    return ElGamal_KeyPair(group, x, h)


# ── ElGamal Encryption / Decryption ──────────────────────────────────────────

def elgamal_enc(pk: tuple, m: int) -> tuple[int, int]:
    """
    Encrypt m ∈ Zp.
    Sample fresh r ← Zq.
    c1 = g^r mod p, c2 = m * h^r mod p.
    Returns (c1, c2).
    """
    group, h = pk
    r = group.random_exponent()
    c1 = group.power(group.g, r)
    c2 = (m * group.power(h, r)) % group.p
    return c1, c2


def elgamal_dec(sk: tuple, c1: int, c2: int) -> int:
    """
    Decrypt: m = c2 / c1^x mod p = c2 * c1^{-x} mod p.
    """
    group, x = sk
    s = group.power(c1, x)  # c1^x = g^{rx}
    # Modular inverse of s
    s_inv = _square_and_multiply(s, group.p - 2, group.p)  # Fermat's little theorem
    m = (c2 * s_inv) % group.p
    return m


# ── Malleability Demo ─────────────────────────────────────────────────────────

def demo_malleability(kp: ElGamal_KeyPair) -> None:
    """
    Demonstrate ElGamal malleability: (c1, 2*c2) decrypts to 2m.
    """
    print("\n[ElGamal Malleability Demo]")
    pk = kp.public_key
    sk = kp.private_key
    group = kp.group

    m = 42
    c1, c2 = elgamal_enc(pk, m)
    m_dec = elgamal_dec(sk, c1, c2)
    print(f"  Enc({m}) → decrypt → {m_dec}")

    # Malleable: multiply c2 by 2
    c2_prime = (2 * c2) % group.p
    m_malleable = elgamal_dec(sk, c1, c2_prime)
    print(f"  (c1, 2*c2) → decrypt → {m_malleable}  (expected {2*m} mod p)")
    print(f"  Malleability: {m_malleable == (2 * m) % group.p}")


# ── IND-CPA Game ──────────────────────────────────────────────────────────────

def ind_cpa_elgamal(kp: ElGamal_KeyPair, trials: int = 100) -> float:
    """IND-CPA game for ElGamal. Expected advantage ≈ 0."""
    import random
    pk = kp.public_key
    sk = kp.private_key
    group = kp.group

    correct = 0
    for _ in range(trials):
        b = random.randint(0, 1)
        m0 = group.random_exponent() % (group.p - 1) + 1
        m1 = group.random_exponent() % (group.p - 1) + 1
        m_challenge = m0 if b == 0 else m1
        c1, c2 = elgamal_enc(pk, m_challenge)
        b_guess = 0  # dummy adversary
        if b_guess == b:
            correct += 1

    return abs(correct / trials - 0.5)


if __name__ == "__main__":
    print("=== PA#16: ElGamal Encryption ===\n")

    print("[Building DH group...]")
    group = DHGroup(bits=64)
    kp = elgamal_keygen(group)
    pk = kp.public_key
    sk = kp.private_key

    print(f"\n[ElGamal keygen]")
    print(f"  Private x = {str(kp.x)[:20]}...")
    print(f"  Public  h = {str(kp.h)[:20]}...")

    # Encrypt/decrypt test
    print("\n[Encrypt/Decrypt]")
    for m in [1, 100, 999, group.random_exponent() % 1000]:
        c1, c2 = elgamal_enc(pk, m)
        m_dec = elgamal_dec(sk, c1, c2)
        print(f"  m={m}: enc→dec={m_dec}, correct={m==m_dec}")

    demo_malleability(kp)

    adv = ind_cpa_elgamal(kp, trials=100)
    print(f"\n[IND-CPA game] advantage ≈ {adv:.3f} (expected ≈ 0)")
