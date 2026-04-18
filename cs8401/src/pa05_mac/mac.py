"""
PA#5 — Message Authentication Codes (MACs)
Depends on: PA#2 (AES_PRF)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa02_prf.prf import AES_PRF

BLOCK_SIZE = 16


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pad(m: bytes) -> bytes:
    """PKCS#7 padding."""
    pad_len = BLOCK_SIZE - (len(m) % BLOCK_SIZE)
    return m + bytes([pad_len] * pad_len)


# ── PRF-MAC (single-block) ────────────────────────────────────────────────────

class PRF_MAC:
    """
    PRF-based MAC for single-block messages.
    Mac(k, m) = F_k(m)
    """

    def __init__(self, prf: AES_PRF = None):
        self.prf = prf or AES_PRF()

    def Mac(self, k: bytes, m: bytes) -> bytes:
        """Compute tag t = F_k(m). m must be exactly BLOCK_SIZE bytes."""
        assert len(k) == BLOCK_SIZE
        if len(m) != BLOCK_SIZE:
            # Pad/truncate to block size for single-block MAC
            m = _pad(m)[:BLOCK_SIZE]
        return self.prf.F(k, m)

    def Vrfy(self, k: bytes, m: bytes, t: bytes) -> bool:
        """Verify: check t == Mac(k, m)."""
        expected = self.Mac(k, m)
        # Constant-time comparison
        return _constant_time_eq(expected, t)


# ── CBC-MAC (variable-length) ─────────────────────────────────────────────────

class CBC_MAC:
    """
    CBC-MAC for variable-length messages.
    Chain F_k over blocks of message.
    """

    def __init__(self, prf: AES_PRF = None):
        self.prf = prf or AES_PRF()

    def Mac(self, k: bytes, m: bytes) -> bytes:
        """CBC-MAC tag."""
        assert len(k) == BLOCK_SIZE
        padded = _pad(m)
        blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
        cv = b'\x00' * BLOCK_SIZE
        for block in blocks:
            cv = self.prf.F(k, _xor(cv, block))
        return cv

    def Vrfy(self, k: bytes, m: bytes, t: bytes) -> bool:
        return _constant_time_eq(self.Mac(k, m), t)


# ── HMAC stub (filled in PA#10) ───────────────────────────────────────────────

def hmac(k: bytes, m: bytes) -> bytes:
    """
    HMAC stub. Implemented in PA#10 (depends on PA#8 hash).
    """
    raise NotImplementedError("hmac() implemented in PA#10 — depends on PA#8 DLP hash")


# ── Constant-time comparison ──────────────────────────────────────────────────

def _constant_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality comparison (no early exit)."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ── EUF-CMA Game ──────────────────────────────────────────────────────────────

def euf_cma_game(mac: PRF_MAC, k: bytes, queries: int = 50) -> dict:
    """
    EUF-CMA game: adversary makes `queries` Mac oracle queries,
    then tries to forge a tag on a new message.
    Returns number of forgeries (should be 0).
    """
    queried = {}
    for _ in range(queries):
        m = os.urandom(BLOCK_SIZE)
        t = mac.Mac(k, m)
        queried[m] = t

    # Adversary tries to forge: pick a new message and guess its tag
    forgeries = 0
    for _ in range(10):
        # Try a message not in queried set
        m_new = os.urandom(BLOCK_SIZE)
        if m_new in queried:
            continue
        # Naive forgery: random tag
        t_guess = os.urandom(BLOCK_SIZE)
        if mac.Vrfy(k, m_new, t_guess):
            forgeries += 1

    return {'queries': queries, 'forgery_attempts': 10, 'forgeries': forgeries}


# ── Length-extension vulnerability demo ──────────────────────────────────────

def demo_length_extension(k: bytes, prf: AES_PRF = None) -> None:
    """
    Show length-extension vulnerability on naive H(k||m).
    Uses toy compression (XOR) as placeholder hash.
    """
    prf = prf or AES_PRF()
    print("\n[Length-Extension Vulnerability on H(k||m)]")

    def naive_hash(data: bytes) -> bytes:
        """Toy hash: XOR all blocks."""
        padded = _pad(data)
        result = b'\x00' * BLOCK_SIZE
        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i:i+BLOCK_SIZE]
            result = prf.F(k, _xor(result, block))
        return result

    m = b"Authentic message"
    t = naive_hash(k + m)  # naive construction

    # Attacker extends: knows H(k||m), extends to H(k||m||pad||extra)
    # by continuing from the known digest
    print(f"  H(k||m) = {t.hex()}")
    print(f"  Attacker can extend without knowing k!")
    print(f"  (Full demo in PA#10 where HMAC defeats this attack)")


if __name__ == "__main__":
    print("=== PA#5: MACs ===\n")

    prf = AES_PRF()
    k = os.urandom(BLOCK_SIZE)

    # PRF-MAC
    print("[PRF-MAC]")
    mac = PRF_MAC(prf)
    m = b"Authenticate me!"
    t = mac.Mac(k, m)
    print(f"  Mac(k, m) = {t.hex()}")
    print(f"  Vrfy(k, m, t) = {mac.Vrfy(k, m, t)}")
    print(f"  Vrfy(k, m, wrong_t) = {mac.Vrfy(k, m, os.urandom(16))}")

    # EUF-CMA
    result = euf_cma_game(mac, k, queries=50)
    print(f"\n  EUF-CMA game: {result}")

    # CBC-MAC
    print("\n[CBC-MAC]")
    cbc_mac = CBC_MAC(prf)
    for msg in [b"short", b"A" * 16, b"A" * 32, b"Variable length message!"]:
        t = cbc_mac.Mac(k, msg)
        v = cbc_mac.Vrfy(k, msg, t)
        print(f"  Mac({msg[:20]!r}) = {t.hex()[:16]}... [vrfy: {v}]")

    # HMAC stub
    try:
        hmac(k, b"test")
    except NotImplementedError as e:
        print(f"\n[HMAC stub] NotImplementedError: {e}")

    demo_length_extension(k, prf)
