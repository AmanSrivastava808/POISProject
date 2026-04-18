"""
PA#18 — Oblivious Transfer (1-out-of-2 OT)
Depends on: PA#16 (ElGamal)
Receiver gets m_b without sender learning b; sender's m_{1-b} stays hidden.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa11_dh.dh import DHGroup
from pa16_elgamal.elgamal import ElGamal_KeyPair, elgamal_keygen, elgamal_enc, elgamal_dec
from pa13_miller_rabin.miller_rabin import _square_and_multiply


# ── OT Protocol ───────────────────────────────────────────────────────────────

def OT_Receiver_Step1(group: DHGroup, b: int) -> tuple:
    """
    Receiver step 1 (choice bit b ∈ {0,1}).
    - Generate pk_b honestly (with sk_b).
    - Generate pk_{1-b} as a random group element (no trapdoor).
    Returns (pk_0, pk_1, state).
    state = (b, sk_b, group) — kept secret by receiver.
    """
    assert b in (0, 1)

    # Honest keypair for index b
    x_b = group.random_exponent()
    pk_b = group.power(group.g, x_b)   # g^{x_b}

    # Fake public key for index 1-b: random group element, no known dlog
    pk_fake = int.from_bytes(os.urandom((group.p.bit_length() + 7) // 8), 'big') % group.p
    if pk_fake == 0:
        pk_fake = group.g

    if b == 0:
        pk_0, pk_1 = pk_b, pk_fake
    else:
        pk_0, pk_1 = pk_fake, pk_b

    state = {'b': b, 'sk_b': x_b, 'group': group}
    return pk_0, pk_1, state


def OT_Sender_Step(group: DHGroup, pk_0: int, pk_1: int,
                   m0: int, m1: int) -> tuple:
    """
    Sender step: encrypt both messages.
    C_i = ElGamal_enc(pk_i, m_i) for i ∈ {0, 1}.
    Returns (C_0, C_1).
    """
    C_0 = elgamal_enc((group, pk_0), m0)
    C_1 = elgamal_enc((group, pk_1), m1)
    return C_0, C_1


def OT_Receiver_Step2(state: dict, C_0: tuple, C_1: tuple) -> int:
    """
    Receiver step 2: decrypt only C_b using sk_b.
    Returns m_b.
    """
    b = state['b']
    sk_b = state['sk_b']
    group = state['group']
    C_b = C_0 if b == 0 else C_1
    c1, c2 = C_b
    return elgamal_dec((group, sk_b), c1, c2)


# ── Privacy demonstrations ────────────────────────────────────────────────────

def demo_receiver_privacy(group: DHGroup, trials: int = 5) -> None:
    """
    Sender cannot distinguish pk_{1-b} from a real key.
    Both pk_b and pk_fake look like random group elements.
    """
    print("\n[Receiver Privacy Demo]")
    print("  Sender sees two public keys — cannot determine which is 'real':")
    for _ in range(trials):
        b = int.from_bytes(os.urandom(1), 'big') % 2
        pk_0, pk_1, state = OT_Receiver_Step1(group, b)
        # Both keys look like random elements in Zp
        print(f"  b={b}: pk_0={str(pk_0)[:15]}..., pk_1={str(pk_1)[:15]}... "
              f"[indistinguishable to sender]")


def demo_sender_privacy(group: DHGroup, m0: int, m1: int) -> None:
    """
    Receiver cannot decrypt C_{1-b}: no trapdoor for pk_{1-b}.
    Demonstrates brute-force attempt fails.
    """
    print("\n[Sender Privacy Demo]")
    b = 0
    pk_0, pk_1, state = OT_Receiver_Step1(group, b)
    C_0, C_1 = OT_Sender_Step(group, pk_0, pk_1, m0, m1)

    # Receiver correctly gets m0
    m_b = OT_Receiver_Step2(state, C_0, C_1)
    print(f"  Receiver (b={b}) correctly recovers m_{b} = {m_b}")
    print(f"  m0={m0}, recovered={m_b}, correct={m_b == m0}")

    # Receiver tries brute-force to get m1 (decrypt C_1 without sk_1)
    c1, c2 = C_1
    found = None
    print(f"  Receiver trying brute-force to recover m1 (should fail)...")
    for candidate_x in range(min(5000, group.q)):
        m_try = elgamal_dec((group, candidate_x), c1, c2)
        if m_try == m1:
            found = candidate_x
            break
    print(f"  Brute-force found sk_1: {found is not None and found != 0} "
          f"(False = sender privacy holds for large parameters)")


# ── Correctness over 100 trials ───────────────────────────────────────────────

def run_correctness_trials(group: DHGroup, trials: int = 100) -> dict:
    """Run OT protocol for all (b, m0, m1) combinations, verify correctness."""
    correct = 0
    for _ in range(trials):
        b = int.from_bytes(os.urandom(1), 'big') % 2
        m0 = int.from_bytes(os.urandom(4), 'big') % (group.p - 1) + 1
        m1 = int.from_bytes(os.urandom(4), 'big') % (group.p - 1) + 1
        pk_0, pk_1, state = OT_Receiver_Step1(group, b)
        C_0, C_1 = OT_Sender_Step(group, pk_0, pk_1, m0, m1)
        m_b = OT_Receiver_Step2(state, C_0, C_1)
        expected = m0 if b == 0 else m1
        if m_b == expected:
            correct += 1
    return {'trials': trials, 'correct': correct, 'accuracy': correct / trials}


if __name__ == "__main__":
    print("=== PA#18: Oblivious Transfer ===\n")

    print("[Building DH group...]")
    group = DHGroup(bits=64)

    # Correctness
    print("\n[OT correctness trials]")
    result = run_correctness_trials(group, trials=100)
    print(f"  {result}")

    # Example
    print("\n[OT example]")
    m0, m1 = 42, 99
    for b in [0, 1]:
        pk_0, pk_1, state = OT_Receiver_Step1(group, b)
        C_0, C_1 = OT_Sender_Step(group, pk_0, pk_1, m0, m1)
        m_b = OT_Receiver_Step2(state, C_0, C_1)
        expected = m0 if b == 0 else m1
        print(f"  b={b}: received m_{b}={m_b}, expected={expected}, correct={m_b==expected}")

    demo_receiver_privacy(group, trials=3)
    demo_sender_privacy(group, m0=42, m1=99)
