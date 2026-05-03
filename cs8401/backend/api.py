"""
CS8.401 Backend API Server — All 20 PA endpoints
Run: cd cs8401 && python -m uvicorn backend.api:app --reload --port 8000
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import signal
import threading
import time as _time
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List

app = FastAPI(title="CS8.401 Cryptographic Primitives API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Lazy-loaded singletons ────────────────────────────────────────────────────
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

def get_signature():
    if 'sig' not in _cache:
        from pa15_signatures.signatures import RSA_Signature
        _cache['sig'] = RSA_Signature(get_rsa_kp(), get_dlp_hash())
    return _cache['sig']


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "project": "CS8.401 Cryptographic Primitives"}

@app.get("/health")
def health():
    return {"status": "healthy"}


# ── PA#1: OWF + PRG ──────────────────────────────────────────────────────────

class OWFRequest(BaseModel):
    input_hex: str

class PRGRequest(BaseModel):
    seed_hex: str
    output_bits: int = 64

@app.post("/pa01/owf")
def api_owf(req: OWFRequest):
    from pa01_owf_prg.owf_prg import DLPOneWayFunction
    owf = DLPOneWayFunction(bits=32)
    x_int = int.from_bytes(bytes.fromhex(req.input_hex)[:8].ljust(8, b'\x00'), 'big') % owf.q
    y_int = owf.evaluate(x_int)
    return {"input": x_int, "output": y_int, "one_way": True,
            "note": "f(x) = g^x mod p — inverting requires solving DLP"}

@app.post("/pa01/prg")
def api_prg(req: PRGRequest):
    from pa01_owf_prg.owf_prg import DLPOneWayFunction, OWF_PRG
    owf = DLPOneWayFunction(bits=32)
    prg = OWF_PRG(owf)
    seed_int = int.from_bytes(bytes.fromhex(req.seed_hex)[:8].ljust(8, b'\x00'), 'big') % owf.q
    n_bits = max(8, min(req.output_bits, 2048))
    prg.seed(seed_int)
    bits = [prg._next_bit() for _ in range(n_bits)]
    bits_str = ''.join(str(b) for b in bits)
    out_hex = hex(int(bits_str, 2))[2:].zfill(n_bits // 4)
    ones = sum(bits)
    return {"seed": seed_int, "output_hex": out_hex, "output_bits": n_bits,
            "ones_count": ones, "zeros_count": n_bits - ones,
            "ones_ratio": round(ones / n_bits, 4)}

@app.post("/pa01/randomness_test")
def api_randomness_test(req: PRGRequest):
    from pa01_owf_prg.owf_prg import DLPOneWayFunction, OWF_PRG, run_nist_tests
    owf = DLPOneWayFunction(bits=32)
    prg = OWF_PRG(owf)
    seed_int = int.from_bytes(bytes.fromhex(req.seed_hex)[:8].ljust(8, b'\x00'), 'big') % owf.q
    n_bits = max(64, min(req.output_bits, 2048))
    prg.seed(seed_int)
    bits = [prg._next_bit() for _ in range(n_bits)]
    data = bytes(int(''.join(str(b) for b in bits[i:i+8]), 2) for i in range(0, len(bits) - 7, 8))
    results = run_nist_tests(data, label="PRG output")
    return results


# ── PA#2: PRF + GGM Tree ─────────────────────────────────────────────────────

class PRFRequest(BaseModel):
    key_hex: str
    input_hex: str

class GGMTreeRequest(BaseModel):
    key_hex: str
    query_bits: str  # e.g. "0110"

@app.post("/pa02/prf")
def api_prf(req: PRFRequest):
    prf = get_aes_prf()
    k = bytes.fromhex(req.key_hex)[:16].ljust(16, b'\x00')
    x = bytes.fromhex(req.input_hex)[:16].ljust(16, b'\x00')
    y = prf.F(k, x)
    return {"key_hex": k.hex(), "input_hex": x.hex(), "output_hex": y.hex()}

@app.post("/pa02/ggm_tree")
def api_ggm_tree(req: GGMTreeRequest):
    """Build full GGM binary tree and return nodes + highlighted path."""
    prf = get_aes_prf()
    k = bytes.fromhex(req.key_hex)[:16].ljust(16, b'\x00')
    query = req.query_bits[:8]  # cap depth at 8
    depth = len(query)
    if depth == 0:
        return {"tree": [{"id": "", "label": "K", "hex": k.hex()[:8],
                          "level": 0, "on_path": True, "is_leaf": True}],
                "query": "", "depth": 0, "leaf_hex": k.hex(), "leaf_label": "F_k()"}

    # G_0(v) = AES_v(0^16),  G_1(v) = AES_v(FF^16)
    ZERO = bytes(16)
    ONE = bytes([0xFF] * 16)

    # Compute all node values level by level via BFS
    # values[prefix] = 16-byte value
    values = {"": k}
    for lvl in range(depth):
        for bits_val in range(2**lvl):
            parent = format(bits_val, f'0{lvl}b') if lvl > 0 else ""
            if parent not in values:
                continue
            pv = values[parent]
            values[parent + "0"] = prf.F(pv, ZERO)
            values[parent + "1"] = prf.F(pv, ONE)

    # Build node list for frontend
    nodes = [{"id": "", "label": "K", "hex": k.hex()[:8],
              "level": 0, "on_path": True, "is_leaf": False}]

    for lvl in range(1, depth + 1):
        for bits_val in range(2**lvl):
            prefix = format(bits_val, f'0{lvl}b')
            if prefix not in values:
                continue
            on_path = (query[:lvl] == prefix)
            nodes.append({
                "id": prefix, "label": prefix, "hex": values[prefix].hex()[:8],
                "level": lvl, "on_path": on_path, "is_leaf": (lvl == depth)
            })

    leaf_hex = values.get(query, b'').hex() if query in values else "?"
    return {"tree": nodes, "query": query, "depth": depth,
            "leaf_hex": leaf_hex, "leaf_label": f"F_k({query})"}


# ── PA#3: CPA Encryption ─────────────────────────────────────────────────────

class EncryptRequest(BaseModel):
    key_hex: str
    message_hex: str

@app.post("/pa03/encrypt")
def api_cpa_encrypt(req: EncryptRequest):
    from pa03_cpa.cpa import CPA_Cipher
    k = bytes.fromhex(req.key_hex)[:16].ljust(16, b'\x00')
    m = bytes.fromhex(req.message_hex)
    cipher = CPA_Cipher(get_aes_prf())
    r, c = cipher.encrypt(k, m)
    return {"nonce_hex": r.hex(), "ciphertext_hex": c.hex()}

@app.post("/pa03/decrypt")
def api_cpa_decrypt(req: EncryptRequest):
    from pa03_cpa.cpa import CPA_Cipher
    k = bytes.fromhex(req.key_hex)[:16].ljust(16, b'\x00')
    # expect message_hex = nonce_hex + ciphertext_hex
    data = bytes.fromhex(req.message_hex)
    r, c = data[:16], data[16:]
    cipher = CPA_Cipher(get_aes_prf())
    m = cipher.decrypt(k, r, c)
    return {"plaintext_hex": m.hex()}


# ── PA#4: Modes ───────────────────────────────────────────────────────────────

class ModeRequest(BaseModel):
    mode: str
    key_hex: str
    message_hex: str

@app.post("/pa04/encrypt")
def api_mode_encrypt(req: ModeRequest):
    from pa04_modes.modes import Encrypt
    k = bytes.fromhex(req.key_hex)[:16].ljust(16, b'\x00')
    m = bytes.fromhex(req.message_hex)
    iv, c = Encrypt(req.mode, k, m, get_aes_prf())
    return {"iv_hex": iv.hex(), "ciphertext_hex": c.hex(), "mode": req.mode}


# ── PA#5: MACs ────────────────────────────────────────────────────────────────

class MacRequest(BaseModel):
    key_hex: str
    message_hex: str
    mac_type: str = "prf"

@app.post("/pa05/mac")
def api_mac(req: MacRequest):
    k = bytes.fromhex(req.key_hex)[:16].ljust(16, b'\x00')
    m = bytes.fromhex(req.message_hex)
    if req.mac_type == "cbc":
        from pa05_mac.mac import CBC_MAC
        mac = CBC_MAC(get_aes_prf())
    else:
        from pa05_mac.mac import PRF_MAC
        mac = PRF_MAC(get_aes_prf())
    t = mac.Mac(k, m)
    return {"tag_hex": t.hex(), "mac_type": req.mac_type}

class MacVerifyRequest(BaseModel):
    key_hex: str
    message_hex: str
    tag_hex: str
    mac_type: str = "prf"

@app.post("/pa05/verify")
def api_mac_verify(req: MacVerifyRequest):
    k = bytes.fromhex(req.key_hex)[:16].ljust(16, b'\x00')
    m = bytes.fromhex(req.message_hex)
    t = bytes.fromhex(req.tag_hex)
    if req.mac_type == "cbc":
        from pa05_mac.mac import CBC_MAC
        mac = CBC_MAC(get_aes_prf())
    else:
        from pa05_mac.mac import PRF_MAC
        mac = PRF_MAC(get_aes_prf())
    return {"valid": mac.Vrfy(k, m, t)}


# ── PA#6: CCA ─────────────────────────────────────────────────────────────────

@app.post("/pa06/encrypt")
def api_cca_encrypt(req: EncryptRequest):
    from pa06_cca.cca import CCA_Cipher
    k = bytes.fromhex(req.key_hex)[:16].ljust(16, b'\x00')
    m = bytes.fromhex(req.message_hex)
    cipher = CCA_Cipher(get_aes_prf())
    kE = k
    kM = bytes(b ^ 0xff for b in k)  # derive second key
    r, c, t = cipher.Enc(kE, kM, m)
    return {"nonce_hex": r.hex(), "ciphertext_hex": c.hex(), "tag_hex": t.hex(),
            "note": "Encrypt-then-MAC: tamper-evident ciphertext"}


# ── PA#7: Merkle-Damgard ──────────────────────────────────────────────────────

class HashRequest(BaseModel):
    message_hex: str

@app.post("/pa07/hash")
def api_md_hash(req: HashRequest):
    from pa07_merkle_damgard.merkle_damgard import build_toy_hash
    md = build_toy_hash(16)
    m = bytes.fromhex(req.message_hex)
    h = md.hash(m)
    return {"message_hex": req.message_hex, "digest_hex": h.hex(), "digest_bytes": len(h)}


# ── PA#8: DLP Hash ────────────────────────────────────────────────────────────

@app.post("/pa08/hash")
def api_dlp_hash(req: HashRequest):
    dlp = get_dlp_hash()
    m = bytes.fromhex(req.message_hex)
    h = dlp.hash(m)
    return {"message_hex": req.message_hex, "digest_hex": h.hex()}


# ── PA#9: Birthday Attack ────────────────────────────────────────────────────

class BirthdayRequest(BaseModel):
    bit_size: int = 16

@app.post("/pa09/birthday")
def api_birthday(req: BirthdayRequest):
    from pa09_birthday.birthday import birthday_attack
    dlp = get_dlp_hash()
    m1, m2, attempts = birthday_attack(dlp, req.bit_size)
    result = {"attempts": attempts, "bit_size": req.bit_size,
              "expected_attempts": 2 ** (req.bit_size // 2)}
    if m1 is not None:
        result["m1_hex"] = m1.hex()
        result["m2_hex"] = m2.hex()
        result["collision_found"] = True
    else:
        result["collision_found"] = False
    return result


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
        "A": str(A)[:20] + "...", "B": str(B)[:20] + "...",
        "shared_key_matches": KA == KB,
        "shared_key_prefix": str(KA)[:20] + "..."
    }


# ── PA#12: RSA ────────────────────────────────────────────────────────────────

class RSAEncRequest(BaseModel):
    message: int

@app.get("/pa12/keygen")
def api_rsa_keygen():
    kp = get_rsa_kp()
    return {"n_bits": kp.n.bit_length(), "e": kp.e, "n_prefix": str(kp.n)[:30]}

@app.post("/pa12/encrypt")
def api_rsa_encrypt(req: RSAEncRequest):
    from pa12_rsa.rsa import rsa_enc, rsa_dec
    kp = get_rsa_kp()
    c = rsa_enc(kp.public_key, req.message)
    m_dec = rsa_dec(kp.private_key, c)
    return {"message": req.message, "ciphertext_prefix": str(c)[:30],
            "decrypted": m_dec, "correct": m_dec == req.message}


# ── PA#13: Miller-Rabin ──────────────────────────────────────────────────────

class PrimalityRequest(BaseModel):
    n: int
    k: int = 10

@app.post("/pa13/is_prime")
def api_is_prime(req: PrimalityRequest):
    from pa13_miller_rabin.miller_rabin import miller_rabin
    return {"n": req.n, "is_prime": miller_rabin(req.n, req.k), "rounds": req.k}

@app.post("/pa13/miller_rabin_rounds")
def api_mr_rounds(req: PrimalityRequest):
    from pa13_miller_rabin.miller_rabin import miller_rabin
    results = []
    for i in range(min(req.k, 10)):
        r = miller_rabin(req.n, k=1)
        results.append({"round": i + 1, "composite_detected": not r})
    return {"n": req.n, "rounds": results, "final_is_prime": miller_rabin(req.n, req.k)}

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


# ── PA#14: CRT ────────────────────────────────────────────────────────────────

class CRTRequest(BaseModel):
    residues: List[int]
    moduli: List[int]

@app.post("/pa14/crt")
def api_crt(req: CRTRequest):
    from pa14_crt.crt import crt
    x = crt(req.residues, req.moduli)
    checks = [f"{x} mod {m} = {x % m} (expect {r})"
              for r, m in zip(req.residues, req.moduli)]
    return {"x": x, "checks": checks}


# ── PA#15: Digital Signatures ─────────────────────────────────────────────────

class SignRequest(BaseModel):
    message_hex: str

@app.post("/pa15/sign")
def api_sign(req: SignRequest):
    sig = get_signature()
    kp = get_rsa_kp()
    m = bytes.fromhex(req.message_hex)
    sigma = sig.Sign(kp.private_key, m)
    h_int = sig._hash_to_int(m)
    return {"message_hex": req.message_hex, "signature": str(sigma)[:30] + "...",
            "hash_int": h_int, "sigma_e_mod_n": str(pow(sigma, kp.e, kp.n))[:30]}

@app.post("/pa15/verify")
def api_verify(req: SignRequest):
    sig = get_signature()
    kp = get_rsa_kp()
    m = bytes.fromhex(req.message_hex)
    sigma = sig.Sign(kp.private_key, m)
    valid = sig.Verify(kp.public_key, m, sigma)
    # Tamper
    m_tampered = bytearray(m)
    m_tampered[0] ^= 1
    valid_tampered = sig.Verify(kp.public_key, bytes(m_tampered), sigma)
    return {"valid": valid, "tampered_valid": valid_tampered}


# ── PA#16: ElGamal ────────────────────────────────────────────────────────────

class ElGamalRequest(BaseModel):
    message: int

@app.post("/pa16/encrypt")
def api_eg_encrypt(req: ElGamalRequest):
    from pa16_elgamal.elgamal import elgamal_enc, elgamal_dec
    kp = get_elgamal_kp()
    c1, c2 = elgamal_enc(kp.public_key, req.message)
    m_dec = elgamal_dec(kp.private_key, c1, c2)
    return {"message": req.message, "c1": str(c1)[:20], "c2": str(c2)[:20],
            "decrypted": m_dec, "correct": m_dec == req.message}

@app.post("/pa16/malleability")
def api_eg_malleability(req: ElGamalRequest):
    from pa16_elgamal.elgamal import elgamal_enc, elgamal_dec
    kp = get_elgamal_kp()
    group = kp.group
    c1, c2 = elgamal_enc(kp.public_key, req.message)
    m_dec = elgamal_dec(kp.private_key, c1, c2)
    c2_doubled = (2 * c2) % group.p
    m_mall = elgamal_dec(kp.private_key, c1, c2_doubled)
    expected = (2 * req.message) % group.p
    return {"message": req.message, "decrypted": m_dec,
            "malleable_decrypted": m_mall, "expected_2m": expected,
            "malleability_works": m_mall == expected}


# ── PA#17: CCA-PKC ────────────────────────────────────────────────────────────

@app.post("/pa17/encrypt")
def api_cca_pkc_encrypt(req: ElGamalRequest):
    from pa17_cca_pkc.cca_pkc import CCA_PKC
    kp_eg = get_elgamal_kp()
    kp_rsa = get_rsa_kp()
    cca = CCA_PKC(kp_eg, kp_rsa, get_dlp_hash())
    c1, c2, sigma = cca.Enc(kp_eg.public_key, kp_rsa.private_key, req.message)
    m_dec = cca.Dec(kp_eg.private_key, kp_rsa.public_key, c1, c2, sigma)
    # Tamper
    c2_bad = (c2 + 1) % kp_eg.group.p
    m_tampered = cca.Dec(kp_eg.private_key, kp_rsa.public_key, c1, c2_bad, sigma)
    return {"message": req.message, "decrypted": m_dec, "correct": m_dec == req.message,
            "tampered_result": m_tampered, "tampered_rejected": m_tampered is None}


# ── PA#18: OT ─────────────────────────────────────────────────────────────────

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
    expected = req.m0 if req.b == 0 else req.m1
    return {"received": m_b, "b": req.b, "expected": expected,
            "correct": m_b == expected}


# ── PA#19: Secure Gates ───────────────────────────────────────────────────────

class GateRequest(BaseModel):
    a: int
    b: int

@app.post("/pa19/secure_and")
def api_secure_and(req: GateRequest):
    from pa19_secure_and.secure_and import Secure_AND
    group = get_dh_group()
    result = Secure_AND(group, req.a % 2, req.b % 2)
    return {"a": req.a % 2, "b": req.b % 2, "result": result,
            "expected": (req.a & req.b) % 2, "correct": result == (req.a & req.b) % 2}

@app.post("/pa19/secure_xor")
def api_secure_xor(req: GateRequest):
    from pa19_secure_and.secure_and import Secure_XOR
    result = Secure_XOR(req.a % 2, req.b % 2)
    return {"a": req.a % 2, "b": req.b % 2, "result": result,
            "expected": (req.a ^ req.b) % 2}

@app.post("/pa19/truth_table")
def api_truth_table():
    from pa19_secure_and.secure_and import Secure_AND, Secure_XOR, Secure_NOT
    group = get_dh_group()
    rows = []
    for a in range(2):
        for b in range(2):
            rows.append({
                "a": a, "b": b,
                "AND": Secure_AND(group, a, b),
                "XOR": Secure_XOR(a, b),
                "NOT_a": Secure_NOT(a),
            })
    return {"truth_table": rows}


# ── PA#20: MPC ────────────────────────────────────────────────────────────────

class MPCRequest(BaseModel):
    x: int
    y: int
    n_bits: int = 4

@app.post("/pa20/millionaires")
def api_millionaires(req: MPCRequest):
    from pa20_mpc.mpc import build_millionaires_circuit, Secure_Eval
    group = get_dh_group()
    n = req.n_bits
    circuit = build_millionaires_circuit(n)
    x_bits = [(req.x >> (n - 1 - i)) & 1 for i in range(n)]
    y_bits = [(req.y >> (n - 1 - i)) & 1 for i in range(n)]
    out, transcript, ot_calls, elapsed = Secure_Eval(circuit, x_bits, y_bits, group)
    return {"x": req.x, "y": req.y, "x_greater_than_y": bool(out[0]),
            "ot_calls": ot_calls, "elapsed_s": round(elapsed, 3)}

@app.post("/pa20/equality")
def api_equality(req: MPCRequest):
    from pa20_mpc.mpc import build_equality_circuit, Secure_Eval
    group = get_dh_group()
    n = req.n_bits
    circuit = build_equality_circuit(n)
    x_bits = [(req.x >> (n - 1 - i)) & 1 for i in range(n)]
    y_bits = [(req.y >> (n - 1 - i)) & 1 for i in range(n)]
    out, _, ot_calls, elapsed = Secure_Eval(circuit, x_bits, y_bits, group)
    return {"x": req.x, "y": req.y, "equal": bool(out[0]),
            "ot_calls": ot_calls, "elapsed_s": round(elapsed, 3)}

@app.post("/pa20/addition")
def api_addition(req: MPCRequest):
    from pa20_mpc.mpc import build_addition_circuit, Secure_Eval
    group = get_dh_group()
    n = req.n_bits
    circuit = build_addition_circuit(n)
    x_bits = [(req.x >> (n - 1 - i)) & 1 for i in range(n)]
    y_bits = [(req.y >> (n - 1 - i)) & 1 for i in range(n)]
    out, _, ot_calls, elapsed = Secure_Eval(circuit, x_bits, y_bits, group)
    carry = out[0]
    result_int = sum(b << (n - 1 - i) for i, b in enumerate(out[1:]))
    return {"x": req.x, "y": req.y, "sum": result_int, "carry": carry,
            "expected": (req.x + req.y) % (1 << n),
            "ot_calls": ot_calls, "elapsed_s": round(elapsed, 3)}


# ── Reduction table ───────────────────────────────────────────────────────────

REDUCTION_TABLE = {
    ("OWF", "PRG"): {
        "forward": "HILL iterative construction (PA#1): PRG(s) = GL-bit(f^i(s))",
        "backward": "f_G(s) = G(s): inverting G recovers seed -> OWF"
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
        "forward": "HMAC (PA#10): H((k xor opad) || H((k xor ipad) || m))",
        "backward": "HMAC_k(cv || block) as compression function -> MD hash"
    },
}

@app.get("/reductions/{a}/{b}")
def get_reduction(a: str, b: str):
    key = (a.upper(), b.upper())
    if key in REDUCTION_TABLE:
        return {"from": a, "to": b, **REDUCTION_TABLE[key]}
    rev = (b.upper(), a.upper())
    if rev in REDUCTION_TABLE:
        r = REDUCTION_TABLE[rev]
        return {"from": b, "to": a, "forward": r.get("backward"), "backward": r.get("forward")}
    return {"error": f"No reduction path from {a} to {b}"}


# ── Shutdown ──────────────────────────────────────────────────────────────────

@app.post("/shutdown")
def shutdown():
    def _kill():
        _time.sleep(0.2)
        os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=_kill, daemon=True).start()
    return {"status": "shutting_down"}

@app.on_event("shutdown")
def on_shutdown():
    _cache.clear()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
