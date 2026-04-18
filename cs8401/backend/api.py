"""
CS8.401 Backend API Server
Exposes all PA implementations as HTTP endpoints for the React webapp.
Run: uvicorn backend.api:app --reload --port 8000

Install: pip install fastapi uvicorn
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import signal
import threading
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import os as _os

app = FastAPI(title="CS8.401 Cryptographic Primitives API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Lazy-loaded singletons (expensive to initialize) ─────────────────────────
_cache = {}

def get_aes_prf():
    if 'aes_prf' not in _cache:
        from pa02_prf.prf import AES_PRF
        _cache['aes_prf'] = AES_PRF()
    return _cache['aes_prf']

def get_dlp_hash():
    if 'dlp_hash' not in _cache:
        from pa08_dlp_crhf.dlp_crhf import DLP_Hash
        _cache['dlp_hash'] = DLP_Hash(bits=32)
    return _cache['dlp_hash']

def get_dh_group():
    if 'dh_group' not in _cache:
        from pa11_dh.dh import DHGroup
        _cache['dh_group'] = DHGroup(bits=64)
    return _cache['dh_group']

def get_rsa_kp():
    if 'rsa_kp' not in _cache:
        from pa12_rsa.rsa import rsa_keygen
        _cache['rsa_kp'] = rsa_keygen(bits=512)
    return _cache['rsa_kp']

def get_elgamal_kp():
    if 'eg_kp' not in _cache:
        from pa16_elgamal.elgamal import elgamal_keygen
        _cache['eg_kp'] = elgamal_keygen(get_dh_group())
    return _cache['eg_kp']


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "project": "CS8.401 Cryptographic Primitives"}

@app.get("/health")
def health():
    return {"status": "healthy"}


# ── PA#13: Miller-Rabin ───────────────────────────────────────────────────────

class PrimalityRequest(BaseModel):
    n: int
    k: int = 40

class GenPrimeRequest(BaseModel):
    bits: int = 128

@app.post("/pa13/is_prime")
def api_is_prime(req: PrimalityRequest):
    from pa13_miller_rabin.miller_rabin import miller_rabin
    result = miller_rabin(req.n, req.k)
    return {"n": req.n, "is_prime": result, "rounds": req.k}

@app.post("/pa13/gen_prime")
def api_gen_prime(req: GenPrimeRequest):
    from pa13_miller_rabin.miller_rabin import gen_prime
    p = gen_prime(req.bits)
    return {"prime": str(p), "bits": p.bit_length()}

@app.post("/pa13/gen_safe_prime")
def api_gen_safe_prime(req: GenPrimeRequest):
    from pa13_miller_rabin.miller_rabin import gen_safe_prime
    p, q = gen_safe_prime(req.bits)
    return {"p": str(p), "q": str(q), "p_bits": p.bit_length()}

@app.get("/pa13/carmichael_demo")
def api_carmichael():
    from pa13_miller_rabin.miller_rabin import miller_rabin
    numbers = [561, 1105, 1729, 2465, 2821]
    return {
        "carmichael_numbers": [
            {"n": n, "is_prime": miller_rabin(n, 40)} for n in numbers
        ],
        "note": "All should be False despite passing Fermat test"
    }


# ── PA#7: Merkle-Damgård ──────────────────────────────────────────────────────

class HashRequest(BaseModel):
    message_hex: str

@app.post("/pa07/hash")
def api_md_hash(req: HashRequest):
    from pa07_merkle_damgard.merkle_damgard import build_toy_hash
    md = build_toy_hash(16)
    m = bytes.fromhex(req.message_hex)
    h = md.hash(m)
    return {"message_hex": req.message_hex, "digest_hex": h.hex(), "digest_bytes": len(h)}


# ── PA#3: CPA Encryption ──────────────────────────────────────────────────────

class EncryptRequest(BaseModel):
    key_hex: str
    message_hex: str

class DecryptRequest(BaseModel):
    key_hex: str
    nonce_hex: str
    ciphertext_hex: str

@app.post("/pa03/encrypt")
def api_cpa_encrypt(req: EncryptRequest):
    from pa03_cpa.cpa import CPA_Cipher
    k = bytes.fromhex(req.key_hex)
    m = bytes.fromhex(req.message_hex)
    cipher = CPA_Cipher(get_aes_prf())
    r, c = cipher.encrypt(k, m)
    return {"nonce_hex": r.hex(), "ciphertext_hex": c.hex()}

@app.post("/pa03/decrypt")
def api_cpa_decrypt(req: DecryptRequest):
    from pa03_cpa.cpa import CPA_Cipher
    k = bytes.fromhex(req.key_hex)
    r = bytes.fromhex(req.nonce_hex)
    c = bytes.fromhex(req.ciphertext_hex)
    cipher = CPA_Cipher(get_aes_prf())
    m = cipher.decrypt(k, r, c)
    return {"plaintext_hex": m.hex()}

@app.get("/pa03/ind_cpa_game")
def api_ind_cpa():
    from pa03_cpa.cpa import CPA_Cipher, run_ind_cpa_experiment
    cipher = CPA_Cipher(get_aes_prf())
    adv = run_ind_cpa_experiment(cipher, trials=100)
    return {"advantage": adv, "trials": 100, "note": "Expected ≈ 0"}


# ── PA#4: Modes ───────────────────────────────────────────────────────────────

class ModeEncryptRequest(BaseModel):
    mode: str
    key_hex: str
    message_hex: str

@app.post("/pa04/encrypt")
def api_mode_encrypt(req: ModeEncryptRequest):
    from pa04_modes.modes import Encrypt
    k = bytes.fromhex(req.key_hex)
    m = bytes.fromhex(req.message_hex)
    iv, c = Encrypt(req.mode, k, m, get_aes_prf())
    return {"iv_hex": iv.hex(), "ciphertext_hex": c.hex(), "mode": req.mode}

@app.post("/pa04/decrypt")
def api_mode_decrypt(req: DecryptRequest):
    from pa04_modes.modes import Decrypt
    mode = req.nonce_hex[:3].upper()  # hack — real API would include mode
    return {"error": "Use /pa04/encrypt and pass mode explicitly"}


# ── PA#5: MACs ────────────────────────────────────────────────────────────────

class MacRequest(BaseModel):
    key_hex: str
    message_hex: str
    mac_type: str = "prf"

class MacVerifyRequest(BaseModel):
    key_hex: str
    message_hex: str
    tag_hex: str
    mac_type: str = "prf"

@app.post("/pa05/mac")
def api_mac(req: MacRequest):
    k = bytes.fromhex(req.key_hex)
    m = bytes.fromhex(req.message_hex)
    if req.mac_type == "cbc":
        from pa05_mac.mac import CBC_MAC
        mac = CBC_MAC(get_aes_prf())
    else:
        from pa05_mac.mac import PRF_MAC
        mac = PRF_MAC(get_aes_prf())
    t = mac.Mac(k, m)
    return {"tag_hex": t.hex(), "mac_type": req.mac_type}

@app.post("/pa05/verify")
def api_mac_verify(req: MacVerifyRequest):
    k = bytes.fromhex(req.key_hex)
    m = bytes.fromhex(req.message_hex)
    t = bytes.fromhex(req.tag_hex)
    if req.mac_type == "cbc":
        from pa05_mac.mac import CBC_MAC
        mac = CBC_MAC(get_aes_prf())
    else:
        from pa05_mac.mac import PRF_MAC
        mac = PRF_MAC(get_aes_prf())
    return {"valid": mac.Vrfy(k, m, t)}


# ── PA#8: DLP Hash ────────────────────────────────────────────────────────────

@app.post("/pa08/hash")
def api_dlp_hash(req: HashRequest):
    dlp = get_dlp_hash()
    m = bytes.fromhex(req.message_hex)
    h = dlp.hash(m)
    return {"message_hex": req.message_hex, "digest_hex": h.hex()}


# ── PA#10: HMAC ───────────────────────────────────────────────────────────────

@app.post("/pa10/hmac")
def api_hmac(req: MacRequest):
    from pa10_hmac.hmac_impl import HMAC
    dlp = get_dlp_hash()
    h = HMAC(dlp)
    k = bytes.fromhex(req.key_hex)
    m = bytes.fromhex(req.message_hex)
    t = h.mac(k, m)
    return {"tag_hex": t.hex()}

@app.post("/pa10/hmac_verify")
def api_hmac_verify(req: MacVerifyRequest):
    from pa10_hmac.hmac_impl import HMAC
    dlp = get_dlp_hash()
    h = HMAC(dlp)
    k = bytes.fromhex(req.key_hex)
    m = bytes.fromhex(req.message_hex)
    t = bytes.fromhex(req.tag_hex)
    return {"valid": h.verify(k, m, t)}


# ── PA#11: Diffie-Hellman ─────────────────────────────────────────────────────

@app.get("/pa11/dh_exchange")
def api_dh_exchange():
    from pa11_dh.dh import dh_alice_step1, dh_bob_step1, dh_alice_step2, dh_bob_step2
    group = get_dh_group()
    a, A = dh_alice_step1(group)
    b, B = dh_bob_step1(group)
    KA = dh_alice_step2(group, a, B)
    KB = dh_bob_step2(group, b, A)
    return {
        "A": str(A), "B": str(B),
        "shared_key_matches": KA == KB,
        "shared_key_prefix": str(KA)[:20]
    }


# ── PA#12: RSA ────────────────────────────────────────────────────────────────

@app.get("/pa12/keygen")
def api_rsa_keygen():
    kp = get_rsa_kp()
    return {
        "n_bits": kp.n.bit_length(),
        "e": kp.e,
        "n_prefix": str(kp.n)[:30]
    }

@app.post("/pa12/encrypt")
def api_rsa_encrypt(req: EncryptRequest):
    from pa12_rsa.rsa import rsa_enc_pkcs1
    kp = get_rsa_kp()
    m = bytes.fromhex(req.message_hex)
    c = rsa_enc_pkcs1(kp.public_key, m)
    return {"ciphertext": str(c)[:50]}


# ── PA#13 primality endpoint used by PA#12 ────────────────────────────────────

@app.post("/pa13/miller_rabin_rounds")
def api_mr_rounds(req: PrimalityRequest):
    """Run Miller-Rabin and return per-round witness results."""
    from pa13_miller_rabin.miller_rabin import miller_rabin
    results = []
    for i in range(min(req.k, 10)):
        # Run single-round and collect
        r = miller_rabin(req.n, k=1)
        results.append({"round": i + 1, "composite_detected": not r})
    return {"n": req.n, "rounds": results, "final_is_prime": miller_rabin(req.n, req.k)}


# ── PA#18/19/20: MPC ─────────────────────────────────────────────────────────

class OTRequest(BaseModel):
    b: int
    m0: int
    m1: int

@app.post("/pa18/ot")
def api_ot(req: OTRequest):
    from pa18_ot.ot import OT_Receiver_Step1, OT_Sender_Step, OT_Receiver_Step2
    group = get_dh_group()
    pk0, pk1, state = OT_Receiver_Step1(group, req.b)
    C0, C1 = OT_Sender_Step(group, pk0, pk1, req.m0, req.m1)
    m_b = OT_Receiver_Step2(state, C0, C1)
    return {"received": m_b, "b": req.b, "expected": req.m0 if req.b == 0 else req.m1}

class SecureGateRequest(BaseModel):
    a: int
    b: int

@app.post("/pa19/secure_and")
def api_secure_and(req: SecureGateRequest):
    from pa19_secure_and.secure_and import Secure_AND
    group = get_dh_group()
    result = Secure_AND(group, req.a % 2, req.b % 2)
    return {"a": req.a % 2, "b": req.b % 2, "a_and_b": result, "expected": (req.a & req.b) % 2}

@app.post("/pa19/secure_xor")
def api_secure_xor(req: SecureGateRequest):
    from pa19_secure_and.secure_and import Secure_XOR
    result = Secure_XOR(req.a % 2, req.b % 2)
    return {"a": req.a % 2, "b": req.b % 2, "a_xor_b": result}

class MillionairesRequest(BaseModel):
    x: int
    y: int
    n_bits: int = 4

@app.post("/pa20/millionaires")
def api_millionaires(req: MillionairesRequest):
    from pa20_mpc.mpc import build_millionaires_circuit, Secure_Eval
    group = get_dh_group()
    n = req.n_bits
    circuit = build_millionaires_circuit(n)
    x_bits = [(req.x >> (n - 1 - i)) & 1 for i in range(n)]
    y_bits = [(req.y >> (n - 1 - i)) & 1 for i in range(n)]
    out, transcript, ot_calls, elapsed = Secure_Eval(circuit, x_bits, y_bits, group)
    return {
        "x": req.x, "y": req.y,
        "x_greater_than_y": bool(out[0]),
        "expected": req.x > req.y,
        "ot_calls": ot_calls,
        "elapsed_s": round(elapsed, 3),
        "transcript_length": len(transcript)
    }

@app.post("/pa20/equality")
def api_equality(req: MillionairesRequest):
    from pa20_mpc.mpc import build_equality_circuit, Secure_Eval
    group = get_dh_group()
    n = req.n_bits
    circuit = build_equality_circuit(n)
    x_bits = [(req.x >> (n - 1 - i)) & 1 for i in range(n)]
    y_bits = [(req.y >> (n - 1 - i)) & 1 for i in range(n)]
    out, _, ot_calls, elapsed = Secure_Eval(circuit, x_bits, y_bits, group)
    return {
        "x": req.x, "y": req.y,
        "equal": bool(out[0]),
        "expected": req.x == req.y,
        "ot_calls": ot_calls,
        "elapsed_s": round(elapsed, 3)
    }


# ── Reduction routing table ───────────────────────────────────────────────────

REDUCTION_TABLE = {
    ("OWF", "PRG"): {
        "forward": "HILL iterative construction (PA#1): PRG(s) = GL-bit(f^i(s))",
        "backward": "f_G(s) = G(s): inverting G recovers seed → OWF"
    },
    ("PRG", "PRF"): {
        "forward": "GGM tree construction (PA#2): F(k,x) = G_{b1}(G_{b2}(...G_{bn}(k)))",
        "backward": "G(s) = F_s(0^n) || F_s(1^n)"
    },
    ("PRF", "MAC"): {
        "forward": "PRF-MAC (PA#5): Mac(k,m) = F_k(m)",
        "backward": "Query PRF-MAC on random inputs; use as PRF distinguisher"
    },
    ("CRHF", "HMAC"): {
        "forward": "HMAC (PA#10): H((k⊕opad) || H((k⊕ipad) || m))",
        "backward": "HMAC_k(cv || block) as compression function → MD hash"
    },
    ("HMAC", "MAC"): {
        "forward": "HMAC is a secure MAC (EUF-CMA proven)",
        "backward": "Secure MAC serves as collision-resistant compression"
    },
}

@app.get("/reductions/{primitive_a}/{primitive_b}")
def get_reduction(primitive_a: str, primitive_b: str):
    key = (primitive_a.upper(), primitive_b.upper())
    if key in REDUCTION_TABLE:
        return {"from": primitive_a, "to": primitive_b, **REDUCTION_TABLE[key]}
    # Try reverse
    rev_key = (primitive_b.upper(), primitive_a.upper())
    if rev_key in REDUCTION_TABLE:
        r = REDUCTION_TABLE[rev_key]
        return {"from": primitive_b, "to": primitive_a,
                "forward": r.get("backward"), "backward": r.get("forward"),
                "note": "Reversed direction"}
    return {"error": f"No reduction path from {primitive_a} to {primitive_b}",
            "suggestion": "Check supported pairs: OWF↔PRG, PRG↔PRF, PRF→MAC, CRHF↔HMAC, HMAC↔MAC"}


# ── Shutdown ──────────────────────────────────────────────────────────────────

@app.post("/shutdown")
def shutdown(response: Response):
    """
    Gracefully shut down the API server.

    Usage:
        curl -X POST http://localhost:8000/shutdown

    The server sends a SIGTERM to itself, which uvicorn handles cleanly:
    - Finishes in-flight requests
    - Closes all connections
    - Exits with code 0

    For development (uvicorn --reload), the reloader process also stops.
    """
    def _kill():
        # Small delay so the HTTP response is sent before the process exits
        import time; time.sleep(0.2)
        os.kill(os.getpid(), signal.SIGTERM)

    thread = threading.Thread(target=_kill, daemon=True)
    thread.start()

    return {
        "status": "shutting_down",
        "message": "Server will stop after this response is delivered.",
        "pid": os.getpid(),
    }


@app.on_event("shutdown")
def on_shutdown():
    """Called by uvicorn during graceful shutdown — clears cached state."""
    _cache.clear()
    print("[CS8.401 API] Shutdown complete — all resources released.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
