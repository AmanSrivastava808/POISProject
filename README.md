# CS8.401 — Cryptographic Primitives Project

End-to-end implementation of 21 Programming Assignments covering the full cryptographic primitive stack from OWFs to 2-party MPC, plus a React web application.

---

## Repository Structure

```
cs8401/
├── src/
│   ├── pa01_owf_prg/      owf_prg.py        — OWF + PRG (HILL)
│   ├── pa02_prf/          prf.py             — PRF (GGM + AES)
│   ├── pa03_cpa/          cpa.py             — CPA-secure encryption
│   ├── pa04_modes/        modes.py           — CBC, OFB, CTR modes
│   ├── pa05_mac/          mac.py             — PRF-MAC, CBC-MAC, HMAC stub
│   ├── pa06_cca/          cca.py             — Encrypt-then-MAC (CCA)
│   ├── pa07_merkle_damgard/ merkle_damgard.py — MD framework
│   ├── pa08_dlp_crhf/     dlp_crhf.py        — DLP-based CRHF
│   ├── pa09_birthday/     birthday.py        — Birthday attack
│   ├── pa10_hmac/         hmac_impl.py       — HMAC + Encrypt-then-HMAC
│   ├── pa11_dh/           dh.py              — Diffie-Hellman
│   ├── pa12_rsa/          rsa.py             — RSA + PKCS#1 v1.5
│   ├── pa13_miller_rabin/ miller_rabin.py    — Miller-Rabin + prime gen
│   ├── pa14_crt/          crt.py             — CRT + Håstad attack
│   ├── pa15_signatures/   signatures.py      — RSA digital signatures
│   ├── pa16_elgamal/      elgamal.py         — ElGamal PKE
│   ├── pa17_cca_pkc/      cca_pkc.py         — CCA-secure PKC
│   ├── pa18_ot/           ot.py              — Oblivious Transfer
│   ├── pa19_secure_and/   secure_and.py      — Secure AND/XOR/NOT
│   └── pa20_mpc/          mpc.py             — 2-party MPC circuits
├── tests/
│   └── test_all.py        — Comprehensive test suite (all PAs)
├── backend/
│   └── api.py             — FastAPI backend (HTTP endpoints for webapp)
└── webapp/
    ├── src/
    │   ├── App.jsx        — Main React app (three-tier layout)
    │   └── main.jsx       — Entry point
    ├── index.html
    ├── package.json
    └── vite.config.js
```

---

## Setup

**Requirements:** Python 3.10+, Node 18+ (only for the webapp).

```bash
# Clone
git clone https://github.com/<your-username>/cs8401.git
cd cs8401

# (Optional) virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install API dependencies (only needed for the webapp)
pip install -r requirements.txt

# Install webapp dependencies
cd webapp && npm install && cd ..
```

All cryptographic implementations (PA#1–PA#20) use **only the Python standard library**.
`requirements.txt` only contains FastAPI/uvicorn for the optional web UI.

---

## Quick Start

### 1. Run all tests

```bash
cd cs8401
python tests/test_all.py
```

### 2. Run individual PAs

```bash
# Phase 1 (no dependencies)
python src/pa13_miller_rabin/miller_rabin.py
python src/pa07_merkle_damgard/merkle_damgard.py

# Phase 2 (symmetric crypto)
python src/pa01_owf_prg/owf_prg.py
python src/pa02_prf/prf.py
python src/pa03_cpa/cpa.py
python src/pa04_modes/modes.py
python src/pa05_mac/mac.py
python src/pa06_cca/cca.py

# Phase 3 (hashing)
python src/pa08_dlp_crhf/dlp_crhf.py
python src/pa09_birthday/birthday.py
python src/pa10_hmac/hmac_impl.py

# Phase 4 (public-key)
python src/pa11_dh/dh.py
python src/pa12_rsa/rsa.py
python src/pa14_crt/crt.py
python src/pa15_signatures/signatures.py
python src/pa16_elgamal/elgamal.py
python src/pa17_cca_pkc/cca_pkc.py

# Phase 5 (MPC)
python src/pa18_ot/ot.py
python src/pa19_secure_and/secure_and.py
python src/pa20_mpc/mpc.py
```

### 3. Start the backend API

```bash
pip install fastapi uvicorn
cd cs8401
uvicorn backend.api:app --reload --port 8000
```

### 4. Start the React webapp

```bash
cd cs8401/webapp
npm install
npm run dev
# Open http://localhost:5173
```

---

## Dependency Graph

```
PA#13 ────────────────────────────────────────────┐
  ├─▶ PA#7 (Merkle-Damgård)                        │
  │     └─▶ PA#8 (DLP-CRHF) ──▶ PA#9 (Birthday)   │
  │           └─▶ PA#10 (HMAC)                      │
  ├─▶ PA#1 (OWF+PRG) ─▶ PA#2 (PRF) ─▶ PA#3 (CPA)  │
  │                           ├─▶ PA#4 (Modes)      │
  │                           ├─▶ PA#5 (MAC) ───────┤
  │                           │     └─▶ PA#6 (CCA)  │
  │                           └─▶ PA#10 (HMAC)      │
  ├─▶ PA#11 (DH) ──▶ PA#16 (ElGamal) ──────────────┤
  │         └─▶ PA#18 (OT) ──▶ PA#19 (Secure gates) │
  │               └─▶ PA#20 (MPC circuits)          │
  └─▶ PA#12 (RSA) ──▶ PA#14 (CRT + Håstad)         │
              ├─▶ PA#15 (Signatures) ───────────────┤
              └─▶ PA#17 (CCA-PKC) ◀─ PA#15+PA#16   │
```

---

## PA#20: Full Call-Stack Trace

One AND gate evaluation in PA#20 traces through the entire project:

```
PA#20 Secure_Eval(circuit, x_Alice, y_Bob, group)
└── gate.type == 'AND':
    └── PA#19 Secure_AND(group, a, b)
        ├── PA#18 OT_Receiver_Step1(group, b)
        │   └── PA#11 DHGroup.random_exponent()
        │       └── os.urandom() [allowed]
        ├── PA#18 OT_Sender_Step(group, pk_0, pk_1, m0, m1)
        │   └── PA#16 elgamal_enc((group, pk_i), m_i)
        │       └── PA#11 DHGroup.power(g, r)
        │           └── PA#13 _square_and_multiply(g, r, p)
        └── PA#18 OT_Receiver_Step2(state, C_0, C_1)
            └── PA#16 elgamal_dec((group, sk_b), c1, c2)
                └── PA#13 _square_and_multiply(c1, sk_b, p)

Group initialization (PA#11 DHGroup):
└── PA#13 gen_safe_prime(bits)
    ├── PA#13 gen_prime(bits-1)  [Miller-Rabin loop]
    │   └── PA#13 miller_rabin(candidate, k=40)
    │       └── PA#13 _square_and_multiply(a, d, n)
    └── PA#13 miller_rabin(p=2q+1, k=40)
```

---

## Bidirectional Reductions

### PA#1 — OWF ↔ PRG
- **OWF → PRG**: HILL construction. For seed s, iterate f repeatedly, extract Goldreich-Levin hard-core bit per step.
- **PRG → OWF**: Define f_G(s) = G(s). Inverting G recovers s (PRG seed), which is hard by PRG security.

### PA#2 — PRG ↔ PRF
- **PRG → PRF**: GGM binary tree. Parse input x = b₁...bₙ, walk tree applying G_{b_i} at each level.
- **PRF → PRG**: G(s) = F_s(0ⁿ) ∥ F_s(1ⁿ). Security reduces to PRF security.

### PA#10 — CRHF ↔ HMAC ↔ MAC (6 directions)
- **CRHF → HMAC**: HMAC construction using CRHF as underlying hash.
- **HMAC → CRHF**: Use HMAC_k(cv ∥ block) as compression function in MD framework.
- **HMAC → MAC**: HMAC satisfies EUF-CMA (proven from CRHF security).
- **MAC → CRHF**: A secure MAC serves as collision-resistant compression.
- **CRHF → MAC**: Via HMAC bridge.
- **MAC → HMAC**: Mac forgery implies HMAC forgery.

---

## Allowed Library Exceptions (per spec)

1. `int` — Python's arbitrary-precision integers
2. `os.urandom` — cryptographically secure randomness
3. `pow(a, b, n)` — Python's built-in modular exponentiation (only where noted; own `_square_and_multiply` also implemented for benchmarks)

All other cryptographic operations are implemented from scratch.

---

## Backend API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/pa13/is_prime` | POST | Miller-Rabin primality test |
| `/pa13/gen_prime` | POST | Generate probable prime |
| `/pa13/gen_safe_prime` | POST | Generate safe prime p=2q+1 |
| `/pa13/carmichael_demo` | GET | Show Carmichael number detection |
| `/pa07/hash` | POST | Merkle-Damgård toy hash |
| `/pa03/encrypt` | POST | CPA-secure encrypt |
| `/pa03/decrypt` | POST | CPA-secure decrypt |
| `/pa03/ind_cpa_game` | GET | Run IND-CPA game |
| `/pa04/encrypt` | POST | Block cipher mode encrypt |
| `/pa05/mac` | POST | PRF-MAC or CBC-MAC |
| `/pa05/verify` | POST | MAC verification |
| `/pa08/hash` | POST | DLP-CRHF hash |
| `/pa10/hmac` | POST | HMAC computation |
| `/pa10/hmac_verify` | POST | HMAC verification |
| `/pa11/dh_exchange` | GET | Full DH exchange demo |
| `/pa12/keygen` | GET | RSA key generation |
| `/pa12/encrypt` | POST | RSA PKCS#1 v1.5 encrypt |
| `/pa18/ot` | POST | 1-out-of-2 OT protocol |
| `/pa19/secure_and` | POST | Secure AND gate |
| `/pa19/secure_xor` | POST | Secure XOR gate |
| `/pa20/millionaires` | POST | Millionaire's problem |
| `/pa20/equality` | POST | Secure equality test |
| `/reductions/{A}/{B}` | GET | Reduction routing table |

---

## Implementation Notes

- **AES-128**: Fully implemented from scratch (S-box, key schedule, MixColumns, ShiftRows, AddRoundKey, inverses). Verified against NIST KAT vector.
- **Miller-Rabin**: 40 rounds, correctly identifies all tested Carmichael numbers (561, 1105, 1729, ...).
- **Safe primes**: Both gen_safe_prime and gen_prime use own Miller-Rabin.
- **ElGamal**: Uses PA#11 group; modular inverse via Fermat's little theorem (p prime).
- **OT**: Receiver privacy: pk_{1-b} is a random group element with no known dlog. Sender privacy: receiver cannot decrypt C_{1-b} without sk_{1-b}.
- **MPC circuits**: Topologically ordered DAG; AND gates use OT (PA#18), XOR uses additive sharing, NOT is local.
