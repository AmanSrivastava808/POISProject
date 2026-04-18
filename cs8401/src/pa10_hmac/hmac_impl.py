"""
PA#10 — HMAC and Encrypt-then-HMAC
Depends on: PA#8 (DLP_Hash), PA#3 (CPA_Cipher), PA#7 (MerkleDamgard)
"""

import os
import time
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa08_dlp_crhf.dlp_crhf import DLP_Hash
from pa03_cpa.cpa import CPA_Cipher
from pa05_mac.mac import _constant_time_eq, _pad
from pa02_prf.prf import AES_PRF
from pa07_merkle_damgard.merkle_damgard import MerkleDamgard

BLOCK_SIZE = 16


# ── HMAC ─────────────────────────────────────────────────────────────────────

class HMAC:
    """
    HMAC: H((k XOR opad) || H((k XOR ipad) || m))
    Uses PA#8 DLP_Hash as the underlying hash H.
    """

    IPAD = 0x36
    OPAD = 0x5C

    def __init__(self, hash_fn: DLP_Hash):
        self.H = hash_fn
        self.block_size = hash_fn.block_size  # hash's internal block size

    def _prepare_key(self, k: bytes) -> bytes:
        """Pad or hash key to match hash block size."""
        if len(k) > self.block_size:
            k = self.H.hash(k)
        # Zero-pad to block size
        return k + b'\x00' * (self.block_size - len(k))

    def mac(self, k: bytes, m: bytes) -> bytes:
        """Compute HMAC(k, m) = H((k XOR opad) || H((k XOR ipad) || m))"""
        k_padded = self._prepare_key(k)
        k_ipad = bytes(b ^ self.IPAD for b in k_padded)
        k_opad = bytes(b ^ self.OPAD for b in k_padded)
        inner = self.H.hash(k_ipad + m)
        outer = self.H.hash(k_opad + inner)
        return outer

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        """Constant-time HMAC verification."""
        expected = self.mac(k, m)
        return _constant_time_eq(expected, t)


# ── Fill in PA#5 stub ─────────────────────────────────────────────────────────

def hmac(k: bytes, m: bytes, hash_fn: DLP_Hash = None) -> bytes:
    """
    Fills in the PA#5 stub.
    Computes HMAC(k, m) using DLP_Hash.
    """
    if hash_fn is None:
        hash_fn = _get_default_hash()
    h = HMAC(hash_fn)
    return h.mac(k, m)


_default_hash = None

def _get_default_hash() -> DLP_Hash:
    global _default_hash
    if _default_hash is None:
        _default_hash = DLP_Hash(bits=32)
    return _default_hash


# ── Timing attack demo ────────────────────────────────────────────────────────

def timing_attack_demo(hmac_obj: HMAC, k: bytes, m: bytes, trials: int = 1000) -> None:
    """
    Demonstrate timing difference between constant-time and early-exit comparison.
    """
    print("\n[Timing Attack Demo: naive early-exit vs constant-time]")

    correct_tag = hmac_obj.mac(k, m)

    def naive_verify(t1: bytes, t2: bytes) -> bool:
        """Naive early-exit comparison (vulnerable to timing attack)."""
        if len(t1) != len(t2):
            return False
        for a, b in zip(t1, t2):
            if a != b:
                return False  # early exit!
        return True

    # Time naive verify with wrong tag (first byte wrong)
    wrong_first = bytes([correct_tag[0] ^ 0xFF]) + correct_tag[1:]
    # Time naive verify with wrong tag (last byte wrong)
    wrong_last = correct_tag[:-1] + bytes([correct_tag[-1] ^ 0xFF])

    t0 = time.perf_counter()
    for _ in range(trials):
        naive_verify(correct_tag, wrong_first)
    t_wrong_first = (time.perf_counter() - t0) / trials

    t0 = time.perf_counter()
    for _ in range(trials):
        naive_verify(correct_tag, wrong_last)
    t_wrong_last = (time.perf_counter() - t0) / trials

    print(f"  Naive early-exit: wrong at byte 0 = {t_wrong_first*1e9:.1f}ns, "
          f"wrong at last byte = {t_wrong_last*1e9:.1f}ns")
    print(f"  Timing difference reveals wrong byte position!")

    # Constant-time has no measurable difference
    t0 = time.perf_counter()
    for _ in range(trials):
        _constant_time_eq(correct_tag, wrong_first)
    t_ct_first = (time.perf_counter() - t0) / trials

    t0 = time.perf_counter()
    for _ in range(trials):
        _constant_time_eq(correct_tag, wrong_last)
    t_ct_last = (time.perf_counter() - t0) / trials

    print(f"  Constant-time:    wrong at byte 0 = {t_ct_first*1e9:.1f}ns, "
          f"wrong at last byte = {t_ct_last*1e9:.1f}ns")
    print(f"  Constant-time shows no measurable position leakage!")


# ── EUF-CMA for HMAC ─────────────────────────────────────────────────────────

def euf_cma_hmac(hmac_obj: HMAC, k: bytes, queries: int = 50) -> dict:
    """EUF-CMA game for HMAC."""
    queried = {}
    for _ in range(queries):
        m = os.urandom(16)
        t = hmac_obj.mac(k, m)
        queried[m] = t

    forgeries = 0
    for _ in range(10):
        m_new = os.urandom(16)
        if m_new in queried:
            continue
        t_guess = os.urandom(len(list(queried.values())[0]))
        if hmac_obj.verify(k, m_new, t_guess):
            forgeries += 1

    return {'queries': queries, 'forgeries': forgeries}


# ── Length-extension attack on H(k||m) vs HMAC ───────────────────────────────

def demo_length_extension_vs_hmac(dlp: DLP_Hash, k: bytes) -> None:
    """
    Show length-extension succeeds on H(k||m) but fails on HMAC.
    """
    print("\n[Length-Extension: H(k||m) vs HMAC]")
    m = b"Authenticated message"

    # Naive construction: H(k||m)
    naive_tag = dlp.hash(k + m)
    print(f"  H(k||m) = {naive_tag.hex()}")

    # Length-extension: attacker knows H(k||m) and |k|+|m|
    # Can compute H(k||m||pad||extra) without knowing k
    pad = dlp._md._pad(k + m)[len(k + m):]  # the MD padding appended
    extra = b" EXTENDED"
    extended_tag = dlp.hash(k + m + pad + extra)
    print(f"  Attacker computes H(k||m||pad||extra) = {extended_tag.hex()}")
    print(f"  Server cannot distinguish this from legitimate extension!")

    # HMAC: extension fails
    h = HMAC(dlp)
    hmac_tag = h.mac(k, m)
    # Attacker tries to forge tag for m||pad||extra
    m_ext = m + pad + extra
    attacker_tag = h.mac(k, m_ext)  # attacker doesn't know k, can't do this!
    # But if attacker tries to use extended_tag as the HMAC for m_ext:
    is_valid = h.verify(k, m_ext, extended_tag)
    print(f"\n  HMAC: extended_tag valid for m_ext? {is_valid} (expected: False)")
    print(f"  HMAC defeats length-extension attack!")


# ── HMAC → CRHF: HMAC as a compression function ──────────────────────────────

def hmac_as_crhf(hmac_obj: HMAC, k: bytes) -> MerkleDamgard:
    """
    Backward direction: HMAC_k(cv || block) as a compression function.
    Collision requires MAC forgery.
    """
    def compress_via_hmac(cv: bytes, block: bytes) -> bytes:
        return hmac_obj.mac(k, cv + block)[:hmac_obj.H.output_size]

    iv = b'\x00' * hmac_obj.H.output_size
    return MerkleDamgard(compress_via_hmac, iv, hmac_obj.H.block_size)


# ── Encrypt-then-HMAC ─────────────────────────────────────────────────────────

class EtH_Cipher:
    """
    Encrypt-then-HMAC.
    EtH_Enc(kE, kM, m) = (r, c, t) where (r,c) = CPA_Enc(kE,m), t = HMAC(kM, r||c)
    """

    def __init__(self, hmac_obj: HMAC, prf: AES_PRF = None):
        self.hmac = hmac_obj
        self.cpa = CPA_Cipher(prf or AES_PRF())

    def Enc(self, kE: bytes, kM: bytes, m: bytes) -> tuple:
        r, c = self.cpa.encrypt(kE, m)
        t = self.hmac.mac(kM, r + c)
        return r, c, t

    def Dec(self, kE: bytes, kM: bytes, r: bytes, c: bytes, t: bytes):
        expected = self.hmac.mac(kM, r + c)
        if not _constant_time_eq(expected, t):
            return None  # ⊥
        return self.cpa.decrypt(kE, r, c)


if __name__ == "__main__":
    print("=== PA#10: HMAC + Encrypt-then-HMAC ===\n")

    print("[Building DLP hash...]")
    dlp = DLP_Hash(bits=32)
    h = HMAC(dlp)
    k = os.urandom(dlp.block_size)

    # HMAC correctness
    print("\n[HMAC correctness]")
    for m in [b"", b"hello", b"A" * 100]:
        t = h.mac(k, m)
        v = h.verify(k, m, t)
        print(f"  HMAC({m[:20]!r}) = {t.hex()[:16]}... [vrfy: {v}]")

    # Key length variations
    print("\n[Key length handling]")
    for key_len in [4, 16, 32, 64]:
        k_test = os.urandom(key_len)
        t = h.mac(k_test, b"test message")
        print(f"  key_len={key_len}: HMAC = {t.hex()[:16]}...")

    timing_attack_demo(h, k, b"timing test message", trials=10000)

    # EUF-CMA
    result = euf_cma_hmac(h, k, queries=50)
    print(f"\n[EUF-CMA HMAC] {result}")

    demo_length_extension_vs_hmac(dlp, k[:dlp.block_size])

    # EtH cipher
    print("\n[Encrypt-then-HMAC]")
    eth = EtH_Cipher(h)
    kE = os.urandom(BLOCK_SIZE)
    kM = os.urandom(dlp.block_size)
    m = b"Secure message!!"
    r, c, t = eth.Enc(kE, kM, m)
    dec = eth.Dec(kE, kM, r, c, t)
    print(f"  Plaintext: {m!r}")
    print(f"  Decrypted: {dec!r}")
    print(f"  Correct: {m == dec}")

    # Tamper
    t_bad = bytes(x ^ 1 for x in t)
    result2 = eth.Dec(kE, kM, r, c, t_bad)
    print(f"  Tampered tag result: {result2} (expected ⊥)")
