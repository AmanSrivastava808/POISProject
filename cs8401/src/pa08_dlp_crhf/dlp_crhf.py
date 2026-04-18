"""
PA#8 — DLP-based Collision-Resistant Hash Function (CRHF)
Depends on: PA#7 (MerkleDamgard), PA#13 (gen_safe_prime)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa13_miller_rabin.miller_rabin import gen_safe_prime, _square_and_multiply
from pa07_merkle_damgard.merkle_damgard import MerkleDamgard


# ── DLP-based Compression Function ───────────────────────────────────────────

class DLP_Hash:
    """
    DLP-based CRHF via Merkle-Damgård.
    Compression: compress(x, y) = g^x * h^y mod p
    where p = 2q+1 (safe prime), g generates the subgroup of order q,
    h = g^alpha mod p for a randomly discarded alpha.
    """

    def __init__(self, bits: int = 64):
        print(f"  [DLP-Hash] Generating {bits}-bit safe prime...")
        self.p, self.q = gen_safe_prime(bits)
        self.bits = bits
        self.output_size = (bits + 7) // 8  # digest size in bytes
        # MD block_size must be large enough to hold the 8-byte length field.
        # Use max(output_size, 16) so padding arithmetic is always valid.
        self.block_size = max(self.output_size, 16)

        # Generator g: h = 2^2 mod p (squares give subgroup)
        h_base = 2
        self.g = _square_and_multiply(h_base, 2, self.p)
        assert self.g != 1, "g must not be 1"

        # h = g^alpha mod p for random discarded alpha
        alpha = int.from_bytes(os.urandom(self.output_size), 'big') % self.q
        self.h_hat = _square_and_multiply(self.g, alpha, self.p)
        # alpha is discarded: knowing it would allow collision finding

        # IV: fixed constant (padded to block_size)
        self.iv = (1).to_bytes(self.block_size, 'big')

        # Build MD framework
        self._md = MerkleDamgard(self._compress, self.iv, self.block_size)
        print(f"  [DLP-Hash] p={self.p.bit_length()}-bit, ready")

    def _compress(self, cv: bytes, block: bytes) -> bytes:
        """compress(x, y) = g^x * h^y mod p. Output is block_size bytes (padded)."""
        x = int.from_bytes(cv, 'big') % self.q
        y = int.from_bytes(block, 'big') % self.q
        result = (_square_and_multiply(self.g, x, self.p) *
                  _square_and_multiply(self.h_hat, y, self.p)) % self.p
        # Return padded to block_size
        raw = result.to_bytes(self.output_size, 'big')
        return raw.rjust(self.block_size, b'\x00')

    def hash(self, message: bytes) -> bytes:
        """Hash a message of arbitrary length. Returns digest bytes."""
        return self._md.hash(message)

    def __call__(self, message: bytes) -> bytes:
        return self.hash(message)


# ── Brute-force collision finder (toy parameters) ────────────────────────────

def find_collision_brute_force(dlp_hash: DLP_Hash, max_attempts: int = 100000) -> tuple:
    """
    Brute-force birthday collision finder for small (toy) hash.
    Returns (m1, m2) with h(m1) == h(m2) and m1 != m2, or None.
    """
    seen = {}
    for i in range(max_attempts):
        m = i.to_bytes(4, 'big')
        h = dlp_hash.hash(m)
        h_key = h.hex()
        if h_key in seen and seen[h_key] != m:
            return seen[h_key], m
        seen[h_key] = m
    return None


if __name__ == "__main__":
    print("=== PA#8: DLP-CRHF ===\n")

    # Use small parameters for demonstration
    dlp = DLP_Hash(bits=32)

    # Hash various messages
    print("\n[Hashing messages]")
    messages = [
        b"",
        b"Hello",
        b"Hello, World!",
        b"A" * 50,
        b"The quick brown fox jumps over the lazy dog",
    ]
    hashes = set()
    for m in messages:
        h = dlp.hash(m)
        hashes.add(h.hex())
        print(f"  H({m[:20]!r}{'...' if len(m)>20 else ''}) = {h.hex()}")

    print(f"\n  All hashes distinct: {len(hashes) == len(messages)}")

    # Collision finding at toy parameters
    print(f"\n[Brute-force collision finder (toy {dlp.bits}-bit hash)]")
    print(f"  Searching for collisions (theoretical ~2^{dlp.bits//2} work)...")
    result = find_collision_brute_force(dlp, max_attempts=500000)
    if result:
        m1, m2 = result
        h1 = dlp.hash(m1)
        h2 = dlp.hash(m2)
        print(f"  Collision found!")
        print(f"  m1 = {m1.hex()}, H(m1) = {h1.hex()}")
        print(f"  m2 = {m2.hex()}, H(m2) = {h2.hex()}")
        print(f"  H(m1) == H(m2): {h1 == h2}")
    else:
        print(f"  No collision in search space (hash output too large or search too small)")
