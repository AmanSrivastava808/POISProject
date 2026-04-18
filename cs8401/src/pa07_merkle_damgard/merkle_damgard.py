"""
PA#7 — Merkle-Damgård Hash Framework
No crypto dependencies. Generic MD construction with proper padding.
"""

import struct
from typing import Callable


class MerkleDamgard:
    """
    Generic Merkle-Damgård hash construction.
    Given a compression function, IV, and block size, hashes arbitrary messages.
    
    MD-strengthening padding:
      M || 0x80 || 0x00* || <|M|>_64bit_bigendian
    padded to a multiple of block_size bytes.
    """

    def __init__(self, compress_fn: Callable[[bytes, bytes], bytes], iv: bytes, block_size: int):
        """
        compress_fn(chaining_value: bytes, block: bytes) -> bytes
        iv: initial chaining value (must be block_size bytes)
        block_size: in bytes
        """
        self.compress_fn = compress_fn
        self.iv = iv
        self.block_size = block_size

    def _pad(self, message: bytes) -> bytes:
        """
        Apply MD-strengthening (Merkle-Damgård) padding.
        Appends: 0x80 byte, zero bytes to fill, 8-byte big-endian length (in bits).
        Total length is a multiple of block_size.
        """
        msg_len_bits = len(message) * 8
        # Append 0x80
        padded = message + b'\x80'
        # Append zeros until length ≡ block_size - 8 (mod block_size)
        target = (self.block_size - 8) % self.block_size
        while len(padded) % self.block_size != target:
            padded += b'\x00'
        # Append 64-bit big-endian length
        padded += struct.pack('>Q', msg_len_bits)
        assert len(padded) % self.block_size == 0
        return padded

    def hash(self, message: bytes) -> bytes:
        """
        Hash `message` using the Merkle-Damgård construction.
        Returns the final chaining value as bytes.
        """
        padded = self._pad(message)
        cv = self.iv  # current chaining value
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            cv = self.compress_fn(cv, block)
        return cv

    def __call__(self, message: bytes) -> bytes:
        return self.hash(message)


# ── Toy compression functions for testing ────────────────────────────────────

def toy_xor_compress(cv: bytes, block: bytes) -> bytes:
    """XOR-based toy compression: cv XOR block (same length)."""
    assert len(cv) == len(block)
    return bytes(a ^ b for a, b in zip(cv, block))


def build_toy_hash(block_size: int = 16) -> MerkleDamgard:
    """Build a toy hash using XOR compression and zero IV."""
    iv = b'\x00' * block_size
    return MerkleDamgard(toy_xor_compress, iv, block_size)


# ── Length-extension attack demonstration ────────────────────────────────────

def demonstrate_length_extension(md: MerkleDamgard) -> None:
    """
    Show that Merkle-Damgård is vulnerable to length-extension:
    Given H(m), attacker can compute H(m || pad(m) || extra) without knowing m.
    """
    print("\n=== Length-Extension Attack Demo ===")
    m = b"original message"
    extra = b"extended"

    h_m = md.hash(m)
    print(f"  H(m) = {h_m.hex()}")

    # Attacker knows H(m) = final CV, and knows |m|
    # They set the new IV to H(m) and hash extra with correct pre-padding
    padded_m = md._pad(m)
    h_m_extended = md.hash(padded_m + extra)
    print(f"  H(m || pad(m) || extra) via full hash = {h_m_extended.hex()}")

    # Attacker's shortcut: start from H(m) as CV, feed extra with updated length
    attacker_cv = h_m
    fake_md = MerkleDamgard(md.compress_fn, attacker_cv, md.block_size)
    # The attacker must adjust message length for padding: len(padded_m) + len(extra)
    forged_padded = fake_md._pad(extra)
    forged_cv = attacker_cv
    for i in range(0, len(forged_padded), md.block_size):
        block = forged_padded[i:i + md.block_size]
        forged_cv = md.compress_fn(forged_cv, block)
    print(f"  Attacker forged CV      = {forged_cv.hex()}")
    print(f"  Match: {h_m_extended == forged_cv}")


if __name__ == "__main__":
    print("=== PA#7: Merkle-Damgård Framework ===\n")

    md = build_toy_hash(block_size=16)

    # Test cases
    test_cases = [
        (b"", "empty message"),
        (b"A" * 15, "15 bytes (single block - 1)"),
        (b"A" * 16, "16 bytes (exactly one block)"),
        (b"A" * 17, "17 bytes (one block + 1)"),
        (b"A" * 48, "48 bytes (three blocks)"),
        (b"Hello, World!", "arbitrary message"),
    ]

    print("Hash correctness tests:")
    for msg, desc in test_cases:
        h = md.hash(msg)
        print(f"  [{desc}] H({msg[:20]!r}{'...' if len(msg) > 20 else ''}) = {h.hex()}")

    # Determinism
    msg = b"determinism check"
    assert md.hash(msg) == md.hash(msg), "Hash must be deterministic!"
    print(f"\n  Determinism check passed.")

    # Distinct messages → distinct digests (toy hash, best effort)
    messages = [b"a", b"b", b"aa", b"ab", b"ba"]
    hashes = [md.hash(m).hex() for m in messages]
    print(f"\n  Distinct messages → distinct digests: {len(set(hashes)) == len(hashes)}")

    demonstrate_length_extension(md)
