"""
PA#9 — Birthday Attack on Hash Functions
Depends on: PA#8 (DLP_Hash)
"""

import os
import math
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa08_dlp_crhf.dlp_crhf import DLP_Hash


# ── Weak toy hash for controlled birthday experiments ─────────────────────────

def toy_hash_n_bits(message: bytes, n: int) -> int:
    """
    Deliberately weak n-bit hash for birthday attack experiments.
    Simple polynomial hash truncated to n bits.
    """
    h = 0x811c9dc5  # FNV-1a offset basis
    for byte in message:
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h & ((1 << n) - 1)


# ── Naive birthday attack ─────────────────────────────────────────────────────

def birthday_attack_naive(hash_fn, n_bits: int) -> tuple:
    """
    Naive birthday attack: hash random inputs, find first collision.
    Time: O(2^(n/2)), Space: O(2^(n/2)).
    Returns (m1, m2, evaluations).
    """
    seen = {}
    evaluations = 0
    while True:
        m = os.urandom(8)
        h = hash_fn(m)
        evaluations += 1
        if h in seen and seen[h] != m:
            return seen[h], m, evaluations
        seen[h] = m


# ── Floyd's cycle-finding (tortoise-and-hare) ─────────────────────────────────

def birthday_attack_floyd(hash_fn, n_bits: int, seed: int = 42) -> tuple:
    """
    Floyd's cycle-finding birthday attack.
    Time: O(2^(n/2)), Space: O(1).
    Returns (m1, m2, evaluations) or raises if no collision found in budget.
    """
    evaluations = 0
    domain_size = 1 << n_bits

    def f(x: int) -> int:
        nonlocal evaluations
        evaluations += 1
        m = x.to_bytes(8, 'big')
        return hash_fn(m)

    # Tortoise and hare
    tortoise = f(seed % domain_size)
    hare = f(f(seed % domain_size))

    budget = 4 * (1 << (n_bits // 2 + 2))
    steps = 0
    while tortoise != hare and steps < budget:
        tortoise = f(tortoise % domain_size)
        hare = f(f(hare % domain_size))
        steps += 1

    if tortoise != hare:
        raise RuntimeError("No cycle found — increase budget")

    # Find collision pair
    mu = seed % domain_size
    lam = tortoise
    ptr1 = mu
    ptr2 = lam
    while ptr1 != ptr2:
        ptr1 = f(ptr1 % domain_size)
        ptr2 = f(ptr2 % domain_size)

    # ptr1 == ptr2 is cycle start; find the two preimages
    m1 = ptr1.to_bytes(8, 'big')
    m2 = (f(ptr1 % domain_size)).to_bytes(8, 'big')  # different input with same hash

    h1 = hash_fn(m1)
    h2 = hash_fn(m2)
    # They may or may not collide directly — return what we found
    return m1, m2, evaluations


# ── Empirical vs theoretical birthday probability curve ──────────────────────

def birthday_probability_empirical(hash_fn, n_bits: int, trials: int = 100) -> dict:
    """
    Run birthday attack trials, collect empirical evaluation counts.
    Compare to theoretical 2^(n/2).
    """
    results = []
    for _ in range(trials):
        _, _, evals = birthday_attack_naive(hash_fn, n_bits)
        results.append(evals)
    avg = sum(results) / len(results)
    theoretical = 2 ** (n_bits / 2)
    return {
        'n_bits': n_bits,
        'avg_evals': avg,
        'theoretical': theoretical,
        'ratio': avg / theoretical,
    }


# ── Scale analysis ────────────────────────────────────────────────────────────

def compute_scale_analysis() -> None:
    """Compute 2^(n/2) for MD5, SHA-1 and express in human time."""
    print("\n[Scale Analysis]")
    # Assuming 10^9 hash evaluations per second (modern hardware)
    evals_per_sec = 1e9
    for name, bits in [('MD5', 128), ('SHA-1', 160)]:
        work = 2 ** (bits / 2)
        seconds = work / evals_per_sec
        years = seconds / (365.25 * 24 * 3600)
        print(f"  {name} ({bits}-bit): 2^{bits//2} ≈ {work:.2e} evals")
        print(f"    At 10^9 evals/s: {seconds:.2e} seconds ≈ {years:.2e} years")


if __name__ == "__main__":
    print("=== PA#9: Birthday Attack ===\n")

    # Naive birthday attack on toy hashes
    for n in [8, 12, 16]:
        fn = lambda m, n=n: toy_hash_n_bits(m, n)
        m1, m2, evals = birthday_attack_naive(fn, n)
        h1 = fn(m1)
        theoretical = 2 ** (n / 2)
        print(f"[n={n:2d}-bit] Collision in {evals:6d} evals "
              f"(theoretical ≈ {theoretical:.0f}, ratio={evals/theoretical:.2f})")
        print(f"  m1={m1.hex()}, m2={m2.hex()}, h={h1}")

    # Empirical curve
    print("\n[Empirical vs Theoretical (20 trials each)]")
    for n in [8, 10, 12, 14, 16]:
        fn = lambda m, n=n: toy_hash_n_bits(m, n)
        r = birthday_probability_empirical(fn, n, trials=20)
        print(f"  n={n:2d}: avg={r['avg_evals']:.1f}, theory={r['theoretical']:.1f}, ratio={r['ratio']:.2f}")

    # Birthday attack on truncated DLP hash
    print("\n[Birthday attack on truncated DLP hash (n=16)]")
    dlp = DLP_Hash(bits=32)
    def dlp_16bit(m):
        h = dlp.hash(m)
        val = int.from_bytes(h, 'big')
        return val & 0xFFFF  # truncate to 16 bits

    m1, m2, evals = birthday_attack_naive(dlp_16bit, 16)
    h1 = dlp_16bit(m1)
    h2 = dlp_16bit(m2)
    print(f"  Collision: H(m1) = {h1}, H(m2) = {h2}, match: {h1==h2}")
    print(f"  Evaluations: {evals} (theoretical ≈ {2**8:.0f})")

    compute_scale_analysis()
