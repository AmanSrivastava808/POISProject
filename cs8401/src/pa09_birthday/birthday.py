"""
PA#9 — Birthday Attack on Hash Functions
Depends on: PA#8 (DLP_Hash, find_collision_truncated)

Demonstrates the birthday bound empirically:
  - For a hash with n-bit output, collisions appear in O(2^{n/2}) evaluations.
  - Precise constant: E[trials] ≈ sqrt(π · 2^n / 2)
  - Ratio E[trials] / sqrt(2^n) → sqrt(π/2) ≈ 1.2533 as n grows.

We truncate the full DLP hash to varying bit widths to sweep across
output sizes without re-running expensive safe-prime generation.
"""

import os
import sys
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa08_dlp_crhf.dlp_crhf import DLP_Hash


# ── Core birthday attacker ────────────────────────────────────────────────────

def birthday_attack(dlp: DLP_Hash, n_bits: int, max_attempts: int = None) -> tuple[int | None, int | None, int]:
    """
    Find a collision in the n_bits-truncated output of dlp.

    Returns (m1, m2, evaluations).
    m1/m2 are None if no collision found within max_attempts.

    The birthday bound says we need O(2^{n/2}) queries.
    We cap at 50 × 2^{n/2} to avoid runaway loops.
    """
    if max_attempts is None:
        max_attempts = 50 * (1 << (n_bits // 2))

    trunc_bytes = (n_bits + 7) // 8
    mask = (1 << n_bits) - 1

    seen: dict[int, bytes] = {}
    for i in range(max_attempts):
        # Use 8-byte messages so we have a large enough input space
        m = i.to_bytes(8, 'big')
        h = dlp.hash(m)
        h_int = int.from_bytes(h[-trunc_bytes:], 'big') & mask
        if h_int in seen and seen[h_int] != m:
            return seen[h_int], m, i + 1
        seen[h_int] = m

    return None, None, max_attempts


def run_trials(dlp: DLP_Hash, n_bits: int, num_trials: int = 20) -> dict:
    """
    Run num_trials independent birthday attacks at n_bits output size.
    Returns statistics: mean, min, max evaluations, success rate, theoretical bound.
    """
    theoretical = math.sqrt(math.pi * (1 << n_bits) / 2)
    evals_list = []
    successes = 0

    for _ in range(num_trials):
        _, _, evals = birthday_attack(dlp, n_bits)
        evals_list.append(evals)
        # A "success" means we found a collision (didn't hit the cap)
        cap = 50 * (1 << (n_bits // 2))
        if evals < cap:
            successes += 1

    mean_evals = sum(evals_list) / len(evals_list)
    return {
        'n_bits': n_bits,
        'output_space': 1 << n_bits,
        'theoretical': theoretical,
        'mean': mean_evals,
        'min': min(evals_list),
        'max': max(evals_list),
        'ratio': mean_evals / theoretical,
        'success_rate': successes / num_trials,
        'trials': num_trials,
    }


# ── Paradox explanation ───────────────────────────────────────────────────────

def birthday_paradox_argument() -> str:
    return """
    Birthday Paradox — Formal Argument
    ════════════════════════════════════
    Let H : {0,1}* → {0,1}^n be a random function (ideal hash).

    After k queries, the probability of NO collision is:
      Pr[no collision] = ∏_{i=0}^{k-1} (1 - i/2^n)
                       ≈ exp(-k(k-1) / 2^{n+1})

    Setting this to 1/2 and solving for k:
      k ≈ sqrt(2^n · ln 2) ≈ 0.8326 · 2^{n/2}

    The expected number of queries until the first collision is:
      E[k] = sqrt(π · 2^n / 2) ≈ 1.2533 · 2^{n/2}

    Key consequence:
      - A brute-force preimage attack costs O(2^n) queries.
      - A birthday collision attack costs only O(2^{n/2}) queries.
      - To get 128-bit collision resistance, you need a 256-bit hash
        (e.g., SHA-256 gives only ~128-bit collision security).

    Implication for this PA:
      The DLP-CRHF has full collision resistance (finding collisions requires
      solving DLP). But by truncating to n bits, we artificially reduce the
      output space and make birthday attacks feasible — demonstrating that
      the bound is tight and applies to any hash function regardless of
      its algebraic structure.
    """


# ── ASCII bar chart ───────────────────────────────────────────────────────────

def ascii_chart(results: list[dict]) -> None:
    """
    Print a horizontal bar chart comparing empirical mean evaluations
    to the theoretical birthday bound across different output sizes.
    """
    bar_width = 40
    print("\n  ASCII Chart: Empirical vs Theoretical (mean evaluations)")
    print("  " + "─" * 72)
    print(f"  {'bits':>4}  {'metric':<12} {'bar':<{bar_width}}  value")
    print("  " + "─" * 72)

    max_val = max(max(r['mean'], r['theoretical']) for r in results)

    for r in results:
        n = r['n_bits']
        for label, val, char in [
            ('empirical', r['mean'], '█'),
            ('theoretic', r['theoretical'], '░'),
        ]:
            bar_len = int(val / max_val * bar_width)
            bar = char * bar_len
            print(f"  {n:>4}  {label:<12} {bar:<{bar_width}}  {val:.1f}")
        print()


# ── Single collision demo ─────────────────────────────────────────────────────

def demo_single_collision(dlp: DLP_Hash, n_bits: int = 16) -> None:
    """Show one concrete collision with full diagnostic output."""
    print(f"\n[Single collision demo — {n_bits}-bit truncated output]")
    print(f"  Output space: 2^{n_bits} = {1 << n_bits}")
    print(f"  Theoretical E[trials]: {math.sqrt(math.pi * (1 << n_bits) / 2):.1f}")

    m1, m2, evals = birthday_attack(dlp, n_bits)

    if m1 is None:
        print("  No collision found (increase max_attempts).")
        return

    h1 = dlp.hash(m1)
    h2 = dlp.hash(m2)

    trunc_bytes = (n_bits + 7) // 8
    mask = (1 << n_bits) - 1
    t1 = int.from_bytes(h1[-trunc_bytes:], 'big') & mask
    t2 = int.from_bytes(h2[-trunc_bytes:], 'big') & mask

    print(f"\n  ✓ Collision found after {evals} evaluations")
    print(f"  m1 = {m1.hex()}")
    print(f"  m2 = {m2.hex()}")
    print(f"  H(m1) [full]      = {h1.hex()}")
    print(f"  H(m2) [full]      = {h2.hex()}")
    print(f"  H(m1) [trunc {n_bits}b] = {t1:#0{n_bits//4+2}x}")
    print(f"  H(m2) [trunc {n_bits}b] = {t2:#0{n_bits//4+2}x}")
    print(f"  Truncated match:  {t1 == t2}")
    print(f"  Full hashes differ: {h1 != h2}  (CRHF is secure on full output)")


# ── Sweep across output sizes ─────────────────────────────────────────────────

def sweep_birthday_bound(dlp: DLP_Hash, bit_sizes: list[int], trials_per_size: int = 15) -> None:
    """
    Sweep across multiple truncation sizes and verify that the empirical
    mean tracks the theoretical birthday bound with ratio ≈ 1.0.
    """
    print(f"\n[Birthday bound sweep — {trials_per_size} trials per size]")
    print(f"  Theoretical constant sqrt(π/2) ≈ {math.sqrt(math.pi/2):.4f}\n")

    header = f"  {'bits':>4}  {'2^n':>8}  {'E[theory]':>10}  {'E[empiric]':>10}  {'ratio':>7}  {'success':>7}"
    print(header)
    print("  " + "─" * (len(header) - 2))

    results = []
    for n in bit_sizes:
        stats = run_trials(dlp, n, num_trials=trials_per_size)
        results.append(stats)
        print(
            f"  {stats['n_bits']:>4}  "
            f"{stats['output_space']:>8}  "
            f"{stats['theoretical']:>10.1f}  "
            f"{stats['mean']:>10.1f}  "
            f"{stats['ratio']:>7.3f}  "
            f"{stats['success_rate']:>6.0%}"
        )

    ascii_chart(results)

    # Sanity check: ratios should be O(1) — not growing with n
    ratios = [r['ratio'] for r in results]
    ratio_spread = max(ratios) - min(ratios)
    print(f"\n  Ratio spread (max - min): {ratio_spread:.3f}  "
          f"{'✓ O(1) confirmed' if ratio_spread < 1.0 else '✗ unexpected growth'}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== PA#9: Birthday Attack ===\n")

    # One DLP_Hash instance reused throughout — safe-prime generation is slow.
    # 32-bit full output; we truncate internally to various sizes.
    dlp = DLP_Hash(bits=32)

    # 1. Formal argument
    print(birthday_paradox_argument())

    # 2. Single concrete collision at 16-bit truncation
    demo_single_collision(dlp, n_bits=16)

    # 3. Sweep: 8, 12, 16, 20 bits
    #    20-bit kept manageable: 2^10 = 1024 expected evaluations per trial
    sweep_birthday_bound(dlp, bit_sizes=[8, 12, 16, 20], trials_per_size=15)

    print("\n=== Done ===")