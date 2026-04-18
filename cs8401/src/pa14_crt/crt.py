"""
PA#14 — Chinese Remainder Theorem + Håstad Broadcast Attack
Depends on: PA#12 (RSA, mod_inverse), PA#13 (gen_prime)
"""

import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa12_rsa.rsa import rsa_keygen, rsa_enc, rsa_dec, extended_gcd, mod_inverse, rsa_enc_pkcs1
from pa13_miller_rabin.miller_rabin import _square_and_multiply


# ── CRT implementation ────────────────────────────────────────────────────────

def crt(residues: list[int], moduli: list[int]) -> int:
    """
    Chinese Remainder Theorem solver.
    Given residues r_i and moduli m_i (pairwise coprime),
    find x such that x ≡ r_i (mod m_i) for all i.
    Returns x in [0, product of moduli).
    """
    assert len(residues) == len(moduli)
    M = 1
    for m in moduli:
        M *= m

    result = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        yi = mod_inverse(Mi, m)
        result += r * Mi * yi

    return result % M


# ── RSA-CRT decryption (Garner's algorithm) ───────────────────────────────────

def rsa_dec_crt(kp, c: int) -> int:
    """
    RSA decryption using CRT (Garner's algorithm). ~3-4x faster.
    m_p = c^dp mod p
    m_q = c^dq mod q
    Combine with CRT to get m.
    """
    m_p = _square_and_multiply(c % kp.p, kp.dp, kp.p)
    m_q = _square_and_multiply(c % kp.q, kp.dq, kp.q)
    # Garner's formula: m = m_q + q * (q_inv * (m_p - m_q) mod p)
    h = (kp.q_inv * (m_p - m_q)) % kp.p
    m = m_q + kp.q * h
    return m % kp.n


def benchmark_crt_speedup(kp, n_trials: int = 200) -> dict:
    """Benchmark CRT vs standard decryption."""
    c = rsa_enc(kp.public_key, 12345)

    t0 = time.time()
    for _ in range(n_trials):
        rsa_dec(kp.private_key, c)
    t_standard = (time.time() - t0) / n_trials

    t0 = time.time()
    for _ in range(n_trials):
        rsa_dec_crt(kp, c)
    t_crt = (time.time() - t0) / n_trials

    return {
        'standard_ms': t_standard * 1000,
        'crt_ms': t_crt * 1000,
        'speedup': t_standard / t_crt if t_crt > 0 else float('inf'),
    }


# ── Integer nth root via Newton's method ─────────────────────────────────────

def integer_nth_root(n: int, e: int) -> tuple[int, bool]:
    """
    Compute integer e-th root of n via Newton's method.
    Returns (root, is_exact).
    """
    if n == 0:
        return 0, True
    if e == 1:
        return n, True

    # Initial guess
    x = n
    while True:
        x1 = ((e - 1) * x + n // (x ** (e - 1))) // e
        if x1 >= x:
            break
        x = x1

    # Verify
    exact = x ** e == n
    return x, exact


# ── Håstad Broadcast Attack ───────────────────────────────────────────────────

def hastad_attack(ciphertexts: list[int], moduli: list[int], e: int) -> tuple[int, bool]:
    """
    Håstad's broadcast attack for small exponent e.
    Given e ciphertexts c_i = m^e mod n_i (same m, different n_i, e=3),
    apply CRT to get m^e mod (n_1 * n_2 * ... * n_e),
    then take integer e-th root to recover m.
    """
    assert len(ciphertexts) == e == len(moduli)
    # CRT to get m^e mod product
    m_e = crt(ciphertexts, moduli)
    # Integer e-th root
    m, is_exact = integer_nth_root(m_e, e)
    return m, is_exact


def demo_hastad_attack(bits: int = 256) -> None:
    """Demonstrate Håstad attack with e=3."""
    print("\n[Håstad Broadcast Attack (e=3)]")
    e = 3
    print(f"  Generating {e} RSA key pairs with e={e}, {bits}-bit moduli...")

    # Generate 3 key pairs
    keypairs = []
    for i in range(e):
        kp = rsa_keygen(bits)
        # Ensure e=3 divides none of phi(n)
        keypairs.append(kp)

    # Choose a small message (must satisfy m^e < product of all n_i)
    # To ensure this, pick m small relative to each n
    n_min = min(kp.n for kp in keypairs)
    max_m = int(n_min ** (1/3)) - 1  # largest m whose cube fits in each n
    if max_m < 2:
        print("  Moduli too small for demonstration — use larger bits")
        return

    m = max_m // 2
    print(f"  Message m = {m}")

    # Each recipient gets same message encrypted under their key
    ciphertexts = [rsa_enc((kp.n, e), m) for kp in keypairs]
    moduli = [kp.n for kp in keypairs]

    # Attack
    m_recovered, is_exact = hastad_attack(ciphertexts, moduli, e)
    print(f"  Recovered m = {m_recovered}")
    print(f"  Attack successful: {m_recovered == m}")
    print(f"  Integer cube root exact: {is_exact}")

    # PKCS#1 v1.5 defeats attack (message expands, m^e > product)
    print(f"\n  PKCS#1 v1.5 defeats Håstad: randomized padding makes m^e >> N")

    # Max message length
    n_bytes = (n_min.bit_length() + 7) // 8
    max_msg = n_bytes - 11
    print(f"  Max message for attack at {bits}-bit moduli: ~{max_m.bit_length()} bits")


if __name__ == "__main__":
    print("=== PA#14: CRT + Håstad Broadcast Attack ===\n")

    # CRT test
    print("[CRT correctness]")
    r = crt([2, 3, 2], [3, 5, 7])
    print(f"  x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7) → x = {r}")
    assert r % 3 == 2 and r % 5 == 3 and r % 7 == 2
    print(f"  Verified: {r} mod 3={r%3}, mod 5={r%5}, mod 7={r%7}")

    # CRT decryption benchmark
    print("\n[CRT vs Standard RSA Decryption Benchmark]")
    for bits in [512, 1024]:
        print(f"  Generating {bits}-bit key pair...")
        kp = rsa_keygen(bits)
        # Verify CRT correctness
        m_test = 42
        c_test = rsa_enc(kp.public_key, m_test)
        m_standard = rsa_dec(kp.private_key, c_test)
        m_crt = rsa_dec_crt(kp, c_test)
        print(f"  Correctness: standard={m_standard}, CRT={m_crt}, match={m_standard==m_crt}")
        result = benchmark_crt_speedup(kp, n_trials=50)
        print(f"  {bits}-bit: standard={result['standard_ms']:.2f}ms, "
              f"CRT={result['crt_ms']:.2f}ms, speedup={result['speedup']:.1f}x")

    demo_hastad_attack(bits=256)
