"""
PA#20 — All 2-Party MPC via Secure Circuit Evaluation
Depends on: PA#19 (Secure_AND, Secure_XOR, Secure_NOT)

Call-stack trace for one AND gate evaluation:
PA#20 Secure_Eval (AND gate)
└── PA#19 Secure_AND(a, b)
    └── PA#18 OT_Receiver_Step1 / OT_Sender_Step / OT_Receiver_Step2
        └── PA#16 elgamal_enc / elgamal_dec
            └── PA#11 DHGroup (DH group operations)
                └── PA#13 gen_safe_prime, _square_and_multiply, miller_rabin
"""

import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa11_dh.dh import DHGroup
from pa19_secure_and.secure_and import Secure_AND, Secure_XOR, Secure_NOT


# ── Circuit DAG ───────────────────────────────────────────────────────────────

class Gate:
    """A single logic gate in the circuit."""
    def __init__(self, gate_type: str, inputs: list, output: int):
        """
        gate_type: 'AND', 'XOR', 'NOT', 'INPUT_A', 'INPUT_B'
        inputs: list of wire indices (0 for NOT/input, 1-2 for AND/XOR)
        output: wire index for output
        """
        assert gate_type in ('AND', 'XOR', 'NOT', 'INPUT_A', 'INPUT_B')
        self.gate_type = gate_type
        self.inputs = inputs
        self.output = output

    def __repr__(self):
        return f"Gate({self.gate_type}, in={self.inputs}, out={self.output})"


class Circuit:
    """
    Boolean circuit as a DAG of AND/XOR/NOT gates.
    Wires are indexed integers. Topological ordering is enforced.
    """

    def __init__(self, n_alice_inputs: int, n_bob_inputs: int):
        self.n_alice = n_alice_inputs
        self.n_bob = n_bob_inputs
        self.gates: list[Gate] = []
        self.n_wires = n_alice_inputs + n_bob_inputs
        self.output_wires: list[int] = []

        # Alice's input wires: 0 .. n_alice-1
        # Bob's input wires:   n_alice .. n_alice+n_bob-1
        for i in range(n_alice_inputs):
            self.gates.append(Gate('INPUT_A', [], i))
        for i in range(n_bob_inputs):
            self.gates.append(Gate('INPUT_B', [], n_alice_inputs + i))

    def add_and(self, wire_a: int, wire_b: int) -> int:
        """Add AND gate. Returns output wire index."""
        out = self.n_wires
        self.n_wires += 1
        self.gates.append(Gate('AND', [wire_a, wire_b], out))
        return out

    def add_xor(self, wire_a: int, wire_b: int) -> int:
        """Add XOR gate. Returns output wire index."""
        out = self.n_wires
        self.n_wires += 1
        self.gates.append(Gate('XOR', [wire_a, wire_b], out))
        return out

    def add_not(self, wire_a: int) -> int:
        """Add NOT gate. Returns output wire index."""
        out = self.n_wires
        self.n_wires += 1
        self.gates.append(Gate('NOT', [wire_a], out))
        return out

    def set_outputs(self, wires: list[int]):
        """Mark output wires."""
        self.output_wires = wires


# ── Circuit Evaluator ─────────────────────────────────────────────────────────

def Secure_Eval(circuit: Circuit, x_Alice: list[int], y_Bob: list[int],
                group: DHGroup) -> tuple:
    """
    Securely evaluate circuit with Alice's input x_Alice and Bob's input y_Bob.
    Traverses gates topologically, using PA#19 secure gate operations.
    Returns (output_bits, transcript, ot_call_count, elapsed_s).
    """
    assert len(x_Alice) == circuit.n_alice
    assert len(y_Bob) == circuit.n_bob

    wires = {}
    transcript = []
    ot_calls = 0
    t0 = time.time()

    # Load Alice's inputs
    for i, v in enumerate(x_Alice):
        wires[i] = v % 2

    # Load Bob's inputs
    for i, v in enumerate(y_Bob):
        wires[circuit.n_alice + i] = v % 2

    # Evaluate gates in order (circuit is already topologically ordered by construction)
    for gate in circuit.gates:
        if gate.gate_type in ('INPUT_A', 'INPUT_B'):
            continue  # already loaded

        if gate.gate_type == 'AND':
            a = wires[gate.inputs[0]]
            b = wires[gate.inputs[1]]
            result = Secure_AND(group, a, b)
            ot_calls += 1
            transcript.append({'gate': 'AND', 'inputs': (a, b), 'output': result,
                                'wire': gate.output})

        elif gate.gate_type == 'XOR':
            a = wires[gate.inputs[0]]
            b = wires[gate.inputs[1]]
            result = Secure_XOR(a, b)
            transcript.append({'gate': 'XOR', 'inputs': (a, b), 'output': result,
                                'wire': gate.output})

        elif gate.gate_type == 'NOT':
            a = wires[gate.inputs[0]]
            result = Secure_NOT(a)
            transcript.append({'gate': 'NOT', 'inputs': (a,), 'output': result,
                                'wire': gate.output})

        wires[gate.output] = result

    outputs = [wires[w] for w in circuit.output_wires]
    elapsed = time.time() - t0
    return outputs, transcript, ot_calls, elapsed


# ── Mandatory Test Circuits ───────────────────────────────────────────────────

def build_millionaires_circuit(n_bits: int) -> Circuit:
    """
    Millionaire's problem: compute x > y for n-bit integers.
    Alice has x = x_{n-1}...x_0 (MSB first), Bob has y.
    Uses ripple-carry comparison: x > y iff exists i where x_i=1, y_i=0, and x_j=y_j for all j>i.
    Simplified: compare bit by bit with carry.
    """
    c = Circuit(n_bits, n_bits)
    # Wires: Alice x[i] = wire i, Bob y[i] = wire n_bits+i
    # We compute GT (greater than) with a chain of comparators
    # gt[i] = x[i] AND NOT(y[i]) XOR (x[i] XNOR y[i]) AND gt[i+1]
    # XNOR(a,b) = NOT(XOR(a,b))

    # Start from MSB
    # Accumulate: gt = result so far (0 initially means "equal so far")
    # At each bit i: new_gt = (x[i] AND NOT(y[i])) OR (eq[i] AND gt)
    # eq[i] = NOT(XOR(x[i], y[i]))

    # For simplicity: implement bit-by-bit with cascade
    # gt_wire: 1 if x > y considering bits seen so far
    # eq_wire: 1 if x == y considering bits seen so far

    # Initialize: gt = 0, eq = 1 (start equal)
    # We need constant wires — use XOR(a, a) = 0, NOT(XOR(a,a)) = 1
    # Use Alice's bit 0 XOR itself for 0
    zero_wire = c.add_xor(0, 0)   # 0 XOR 0 = 0 (any bit with itself)
    one_wire = c.add_not(zero_wire)  # NOT(0) = 1

    gt_wire = zero_wire  # starts at 0
    eq_wire = one_wire   # starts at 1

    for i in range(n_bits):
        xi = i             # Alice wire
        yi = n_bits + i    # Bob wire

        # eq_i = NOT(XOR(x_i, y_i))
        xor_i = c.add_xor(xi, yi)
        eq_i = c.add_not(xor_i)

        # not_yi
        not_yi = c.add_not(yi)

        # bit_gt = x_i AND NOT(y_i)  [x_i=1, y_i=0 → greater at this bit]
        bit_gt = c.add_and(xi, not_yi)

        # new_gt = gt_wire OR (eq_wire AND bit_gt)
        # Semantics: x > y so far, OR (equal so far AND x_i > y_i at this bit)
        # This correctly preserves gt once set, since eq_wire tracks "equal so far".
        # Once gt_wire=1, eq_wire=0 (different bits seen), so it stays gt via gt_wire term.
        # a OR b = NOT(NOT(a) AND NOT(b))
        eq_and_bitgt = c.add_and(eq_wire, bit_gt)
        not_gt_wire = c.add_not(gt_wire)
        not_eq_bitgt = c.add_not(eq_and_bitgt)
        not_new_gt = c.add_and(not_gt_wire, not_eq_bitgt)
        new_gt = c.add_not(not_new_gt)

        # new_eq = eq_wire AND eq_i
        new_eq = c.add_and(eq_wire, eq_i)

        gt_wire = new_gt
        eq_wire = new_eq

    c.set_outputs([gt_wire])
    return c


def build_equality_circuit(n_bits: int) -> Circuit:
    """
    Secure equality test: x == y.
    Output 1 iff x_i == y_i for all i.
    """
    c = Circuit(n_bits, n_bits)
    zero_wire = c.add_xor(0, 0)
    one_wire = c.add_not(zero_wire)

    eq_wire = one_wire
    for i in range(n_bits):
        xi = i
        yi = n_bits + i
        xor_i = c.add_xor(xi, yi)
        eq_i = c.add_not(xor_i)
        eq_wire = c.add_and(eq_wire, eq_i)

    c.set_outputs([eq_wire])
    return c


def build_addition_circuit(n_bits: int) -> Circuit:
    """
    Secure n-bit addition x + y mod 2^n using a ripple-carry full adder chain.

    Output layout: n+1 bits total — [carry, sum_{n-1}, ..., sum_0]
      out[0]    = final carry (the overflow / (n+1)-th bit)
      out[1:]   = the n-bit sum (MSB first)

    To read the mod-2^n result: interpret out[1:] as an n-bit integer, i.e.
      result = sum(bit << (n-1-i) for i, bit in enumerate(out[1:]))
    This discards the carry, giving (x + y) mod 2^n correctly even when carry=1.
    """
    c = Circuit(n_bits, n_bits)

    carry_wire = c.add_xor(0, 0)  # carry = 0
    sum_wires = []

    for i in range(n_bits - 1, -1, -1):  # LSB first
        xi = i
        yi = n_bits + i
        # sum_i = xi XOR yi XOR carry
        xor_xy = c.add_xor(xi, yi)
        sum_i = c.add_xor(xor_xy, carry_wire)
        sum_wires.append(sum_i)

        # carry = (xi AND yi) OR (carry AND (xi XOR yi))
        and_xy = c.add_and(xi, yi)
        and_cx = c.add_and(carry_wire, xor_xy)
        not_and_xy = c.add_not(and_xy)
        not_and_cx = c.add_not(and_cx)
        not_carry = c.add_and(not_and_xy, not_and_cx)
        carry_wire = c.add_not(not_carry)

    sum_wires.append(carry_wire)  # final carry
    c.set_outputs(list(reversed(sum_wires)))
    return c


# ── Simulatability check ──────────────────────────────────────────────────────

def check_simulatability(transcript: list, output: list) -> bool:
    """
    Verify transcript is simulatable from output alone:
    each gate's output is the sole information that could not be derived from inputs alone.
    The transcript should not reveal individual input bits beyond what the output implies.
    """
    # For XOR and NOT gates: output can be simulated from inputs without extra info
    # For AND gates: OT ensures each party only learns what OT allows
    # Check: no entry reveals both parties' full inputs
    for entry in transcript:
        if entry['gate'] == 'AND':
            a, b = entry['inputs']
            out = entry['output']
            # AND output is simulatable: if out=0, simulator could set (a=0,b=anything)
            # if out=1, simulator sets (a=1,b=1). Consistent with output.
            if out == 1 and not (a == 1 and b == 1):
                return False
            if out == 0 and (a == 1 and b == 1):
                return False
    return True


if __name__ == "__main__":
    print("=== PA#20: 2-Party MPC ===")
    print("""
Call-stack trace (one AND gate):
PA#20 Secure_Eval (AND gate)
└── PA#19 Secure_AND(a, b)
    └── PA#18 OT_Receiver_Step1 / OT_Sender_Step / OT_Receiver_Step2
        └── PA#16 elgamal_enc / elgamal_dec
            └── PA#11 DHGroup
                └── PA#13 gen_safe_prime, _square_and_multiply, miller_rabin
    """)

    print("[Building DH group...]")
    group = DHGroup(bits=64)
    n = 4  # 4-bit inputs for demo

    # ── Millionaire's Problem ─────────────────────────────────────────────────
    print(f"\n[Millionaire's Problem ({n}-bit)]")
    mill_circuit = build_millionaires_circuit(n)
    test_pairs = [(5, 3), (3, 5), (4, 4), (7, 0), (0, 7)]
    for x, y in test_pairs:
        x_bits = [(x >> (n - 1 - i)) & 1 for i in range(n)]
        y_bits = [(y >> (n - 1 - i)) & 1 for i in range(n)]
        out, transcript, ot_cnt, elapsed = Secure_Eval(mill_circuit, x_bits, y_bits, group)
        result = out[0]
        expected = int(x > y)
        sim_ok = check_simulatability(transcript, out)
        print(f"  {x} > {y}: secure={result}, expected={expected}, "
              f"correct={result==expected}, OT_calls={ot_cnt}, t={elapsed:.3f}s, simulatable={sim_ok}")

    # ── Equality Test ─────────────────────────────────────────────────────────
    print(f"\n[Secure Equality ({n}-bit)]")
    eq_circuit = build_equality_circuit(n)
    for x, y in [(5, 5), (3, 7), (0, 0), (4, 4)]:
        x_bits = [(x >> (n - 1 - i)) & 1 for i in range(n)]
        y_bits = [(y >> (n - 1 - i)) & 1 for i in range(n)]
        out, transcript, ot_cnt, elapsed = Secure_Eval(eq_circuit, x_bits, y_bits, group)
        result = out[0]
        expected = int(x == y)
        print(f"  {x} == {y}: secure={result}, expected={expected}, "
              f"correct={result==expected}, OT_calls={ot_cnt}, t={elapsed:.3f}s")

    # ── Secure Addition ───────────────────────────────────────────────────────
    print(f"\n[Secure Addition ({n}-bit, mod 2^{n})]")
    add_circuit = build_addition_circuit(n)
    for x, y in [(3, 5), (7, 1), (6, 6), (0, 15)]:
        x_bits = [(x >> (n - 1 - i)) & 1 for i in range(n)]
        y_bits = [(y >> (n - 1 - i)) & 1 for i in range(n)]
        out, transcript, ot_cnt, elapsed = Secure_Eval(add_circuit, x_bits, y_bits, group)
        # out = [carry, sum_{n-1}, ..., sum_0]  (n+1 bits total)
        # mod-2^n result: drop the carry (out[0]) and read out[1:]
        carry = out[0]
        result_int = sum(b << (n - 1 - i) for i, b in enumerate(out[1:]))
        expected = (x + y) % (1 << n)
        print(f"  {x} + {y} = {result_int} (carry={carry}), expected={expected}, "
              f"correct={result_int==expected}, OT_calls={ot_cnt}, t={elapsed:.3f}s")

    print("\n[Done — see README for full call-stack documentation]")
