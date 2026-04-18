"""
PA#11 — Diffie-Hellman Key Exchange
Depends on: PA#13 (gen_safe_prime, _square_and_multiply)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa13_miller_rabin.miller_rabin import gen_safe_prime, _square_and_multiply, is_prime


class DHGroup:
    """
    Diffie-Hellman group parameters: safe prime p = 2q+1, generator g of order q.
    """

    def __init__(self, bits: int = 128):
        print(f"  [DH] Generating {bits}-bit safe prime...")
        self.p, self.q = gen_safe_prime(bits)
        # Find a generator of the prime-order subgroup
        h = 2
        self.g = _square_and_multiply(h, 2, self.p)
        assert self.g != 1
        self.bits = bits
        print(f"  [DH] p={self.p.bit_length()}-bit ready")

    def random_exponent(self) -> int:
        """Sample a uniform random exponent from Zq."""
        return int.from_bytes(os.urandom((self.q.bit_length() + 7) // 8), 'big') % self.q

    def power(self, base: int, exp: int) -> int:
        """Modular exponentiation in the group."""
        return _square_and_multiply(base, exp, self.p)


# ── DH Key Exchange Protocol ──────────────────────────────────────────────────

def dh_alice_step1(group: DHGroup) -> tuple[int, int]:
    """
    Alice step 1: sample secret a, compute A = g^a mod p.
    Returns (a_secret, A_public).
    """
    a = group.random_exponent()
    A = group.power(group.g, a)
    return a, A


def dh_bob_step1(group: DHGroup) -> tuple[int, int]:
    """
    Bob step 1: sample secret b, compute B = g^b mod p.
    Returns (b_secret, B_public).
    """
    b = group.random_exponent()
    B = group.power(group.g, b)
    return b, B


def dh_alice_step2(group: DHGroup, a: int, B: int) -> int:
    """Alice step 2: compute shared key K_A = B^a mod p."""
    return group.power(B, a)


def dh_bob_step2(group: DHGroup, b: int, A: int) -> int:
    """Bob step 2: compute shared key K_B = A^b mod p."""
    return group.power(A, b)


# ── MITM Adversary ────────────────────────────────────────────────────────────

class Eve_MITM:
    """
    Eve performs a Man-in-the-Middle attack on DH.
    Intercepts A and B, substitutes her own g^e, relays modified messages.
    """

    def __init__(self, group: DHGroup):
        self.group = group
        self.e = group.random_exponent()
        self.E = group.power(group.g, self.e)
        self.key_with_alice = None
        self.key_with_bob = None

    def intercept_alice(self, A: int) -> int:
        """Intercept Alice's public key, compute key with Alice, return g^e to Bob."""
        self.key_with_alice = group.power(A, self.e) if hasattr(self, 'group') else None
        self.key_with_alice = self.group.power(A, self.e)
        return self.E  # send Eve's key to Bob

    def intercept_bob(self, B: int) -> int:
        """Intercept Bob's public key, compute key with Bob, return g^e to Alice."""
        self.key_with_bob = self.group.power(B, self.e)
        return self.E  # send Eve's key to Alice


# ── CDH Hardness Demo ─────────────────────────────────────────────────────────

def demo_cdh_hardness(group: DHGroup, a: int, A: int, B: int) -> None:
    """
    Demonstrate CDH hardness at small parameters by timing brute-force.
    """
    import time
    print("\n[CDH Hardness Demo — brute-force for small parameters]")
    print(f"  Trying to find a such that g^a = A (mod p), p is {group.p.bit_length()}-bit")
    t0 = time.time()
    found = None
    for candidate in range(min(100000, group.q)):
        if _square_and_multiply(group.g, candidate, group.p) == A:
            found = candidate
            break
    elapsed = time.time() - t0
    if found is not None:
        print(f"  Found a={found} in {elapsed:.3f}s (small parameters, brute-force works)")
        print(f"  For real parameters (2048-bit), this is computationally infeasible")
    else:
        print(f"  Not found in 100k attempts ({elapsed:.3f}s) — brute-force fails!")


if __name__ == "__main__":
    print("=== PA#11: Diffie-Hellman Key Exchange ===\n")

    group = DHGroup(bits=64)

    # Honest DH
    print("\n[Honest DH exchange]")
    a, A = dh_alice_step1(group)
    b, B = dh_bob_step1(group)
    KA = dh_alice_step2(group, a, B)
    KB = dh_bob_step2(group, b, A)
    print(f"  A = g^a mod p = {str(A)[:20]}...")
    print(f"  B = g^b mod p = {str(B)[:20]}...")
    print(f"  K_Alice = {str(KA)[:20]}...")
    print(f"  K_Bob   = {str(KB)[:20]}...")
    print(f"  Keys match: {KA == KB}")

    # MITM
    print("\n[Eve's MITM attack]")
    eve = Eve_MITM(group)
    a2, A2 = dh_alice_step1(group)
    b2, B2 = dh_bob_step1(group)

    # Eve intercepts
    A_to_bob = eve.intercept_alice(A2)   # Eve sends E to Bob instead
    B_to_alice = eve.intercept_bob(B2)   # Eve sends E to Alice instead

    # Alice and Bob compute keys with Eve
    KA_mitm = dh_alice_step2(group, a2, B_to_alice)  # actually g^ae
    KB_mitm = dh_bob_step2(group, b2, A_to_bob)       # actually g^be
    print(f"  Eve knows key with Alice: {str(eve.key_with_alice)[:20]}...")
    print(f"  Eve knows key with Bob:   {str(eve.key_with_bob)[:20]}...")
    print(f"  Alice's key == Eve-Alice key: {KA_mitm == eve.key_with_alice}")
    print(f"  Bob's key == Eve-Bob key:     {KB_mitm == eve.key_with_bob}")
    print(f"  Eve can decrypt/re-encrypt all traffic!")

    demo_cdh_hardness(group, a, A, B)
