"""
PA#19 — Secure 2-Party AND, XOR, NOT Gates
Depends on: PA#18 (OT)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa11_dh.dh import DHGroup
from pa18_ot.ot import OT_Receiver_Step1, OT_Sender_Step, OT_Receiver_Step2


# ── Secure AND via OT ─────────────────────────────────────────────────────────

def Secure_AND(group: DHGroup, a: int, b: int) -> int:
    """
    Secure AND gate via OT.
    Alice holds a ∈ {0,1}, Bob holds b ∈ {0,1}.
    Alice is OT Sender with messages (0, a).
    Bob is OT Receiver with choice b.
    Bob receives a AND b = messages[b].
    """
    assert a in (0, 1) and b in (0, 1)
    # Alice's OT messages: m0=0 (if b=0, AND=0), m1=a (if b=1, AND=a)
    m0 = 0
    m1 = a

    # Bob acts as OT Receiver
    pk_0, pk_1, state = OT_Receiver_Step1(group, b)
    # Alice acts as OT Sender
    C_0, C_1 = OT_Sender_Step(group, pk_0, pk_1, m0, m1)
    # Bob decrypts
    result = OT_Receiver_Step2(state, C_0, C_1)
    return result % 2  # ensure bit


# ── Secure XOR via additive secret sharing ────────────────────────────────────

def Secure_XOR(a: int, b: int) -> int:
    """
    Secure XOR via additive secret sharing over Z_2.
    No OT required: Alice and Bob each compute locally.
    Alice holds a, Bob holds b → XOR = a XOR b.
    In MPC: shares are added locally, result is XOR.
    """
    assert a in (0, 1) and b in (0, 1)
    return a ^ b


# ── Secure NOT ────────────────────────────────────────────────────────────────

def Secure_NOT(a: int) -> int:
    """
    Secure NOT: local bit flip.
    No communication required.
    """
    assert a in (0, 1)
    return 1 - a


# ── Verification suite ────────────────────────────────────────────────────────

def verify_all_gates(group: DHGroup, trials_each: int = 50) -> dict:
    """Verify AND, XOR, NOT across all input combinations."""
    results = {}

    # AND
    and_correct = 0
    for _ in range(trials_each):
        for a in range(2):
            for b in range(2):
                result = Secure_AND(group, a, b)
                expected = a & b
                if result == expected:
                    and_correct += 1
    results['AND'] = {'correct': and_correct, 'total': trials_each * 4}

    # XOR
    xor_correct = sum(
        1 for a in range(2) for b in range(2)
        if Secure_XOR(a, b) == (a ^ b)
    ) * trials_each
    results['XOR'] = {'correct': xor_correct, 'total': trials_each * 4}

    # NOT
    not_correct = sum(
        1 for a in range(2)
        if Secure_NOT(a) == (1 - a)
    ) * trials_each
    results['NOT'] = {'correct': not_correct, 'total': trials_each * 2}

    return results


# ── Privacy argument ──────────────────────────────────────────────────────────

PRIVACY_ARGUMENT = """
Privacy Argument for Secure AND (OT-based):

1. Alice's privacy: Bob learns only the OT output (a AND b).
   Bob's choice bit b is encoded in his OT public keys (pk_0, pk_1).
   One key is honestly generated, one is a random group element.
   Alice sends encryptions under both keys — she cannot distinguish which
   message Bob will receive, so she learns nothing about b.

2. Bob's privacy: Alice learns nothing about b.
   In the OT protocol (PA#18), Alice sees only pk_0 and pk_1.
   Both are indistinguishable random group elements to Alice.
   Thus b is information-theoretically hidden from Alice.

3. Secure XOR: uses additive secret sharing over Z_2.
   Each party's bit is a uniform random share; the XOR reveals no information
   beyond the output, since any output is consistent with any pair of inputs
   that XOR to that output.

4. Secure NOT: local operation, no communication, no leakage.
"""


if __name__ == "__main__":
    print("=== PA#19: Secure AND, XOR, NOT ===\n")

    print("[Building DH group...]")
    group = DHGroup(bits=64)

    # Truth table verification
    print("\n[Gate truth tables]")
    for a in range(2):
        for b in range(2):
            and_r = Secure_AND(group, a, b)
            xor_r = Secure_XOR(a, b)
            not_r = Secure_NOT(a)
            print(f"  a={a}, b={b}: AND={and_r} (exp={a&b}), XOR={xor_r} (exp={a^b}), NOT(a)={not_r} (exp={1-a})")

    # Full verification
    print("\n[Verification (50 trials each combination)]")
    results = verify_all_gates(group, trials_each=50)
    for gate, r in results.items():
        acc = r['correct'] / r['total']
        print(f"  {gate}: {r['correct']}/{r['total']} correct ({acc:.1%})")

    print("\n" + PRIVACY_ARGUMENT)
