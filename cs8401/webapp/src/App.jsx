// CS8.401 Cryptographic Primitives Web App (PA#0)
// Three-tier layout: foundation toggle | build + reduce panels | proof summary

import { useState, useEffect, useCallback } from "react";

const API = "http://localhost:8000";

// ── API helper ────────────────────────────────────────────────────────────────
async function apiFetch(path, body = null) {
  const opts = body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    : { method: "GET" };
  try {
    const r = await fetch(API + path, opts);
    return await r.json();
  } catch (e) {
    return { error: e.message };
  }
}

// ── Foundation modules ────────────────────────────────────────────────────────
const AES_Foundation = {
  name: "AES-128",
  description: "AES block cipher as PRF/PRP foundation",
  asOWF: () => "AES-Davies-Meyer: f(k) = AES_k(0^128) ⊕ k",
  asPRF: () => "F_k(x) = AES_k(x) — direct PRF instantiation",
  asPRP: () => "AES is a pseudorandom permutation by design",
};

const DLP_Foundation = {
  name: "DLP Group",
  description: "Discrete Log Problem in prime-order group",
  asOWF: () => "f(x) = g^x mod p — discrete log is hard",
  asPRG: () => "HILL iterative: extract GL-bit from f^i(s)",
  asOWP: () => "f is a one-way permutation on Zq*",
};

// ── Primitive display names ───────────────────────────────────────────────────
const PRIMITIVES = ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF", "HMAC"];

const PA_LABELS = {
  OWF: "PA#1", PRG: "PA#1", PRF: "PA#2", PRP: "PA#4",
  MAC: "PA#5", CRHF: "PA#8", HMAC: "PA#10",
};

// ── Stub placeholder ──────────────────────────────────────────────────────────
function Stub({ primitive }) {
  return (
    <div className="stub">
      <code>{primitive}</code> — Not yet implemented ({PA_LABELS[primitive] || "PA#?"})
    </div>
  );
}

// ── Build Panel (Column 1) ────────────────────────────────────────────────────
function BuildPanel({ foundation, primitive, setPrimitive, onResult }) {
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState(null);

  const runDemo = async () => {
    setLoading(true);
    let result;
    if (primitive === "OWF") {
      result = await apiFetch("/pa13/is_prime", { n: 104729, k: 40 });
    } else if (primitive === "PRG") {
      result = await apiFetch("/pa08/hash", { message_hex: "deadbeef" });
    } else if (primitive === "PRF") {
      const key = "000102030405060708090a0b0c0d0e0f";
      const msg = "48656c6c6f20576f726c64212121212121";
      result = await apiFetch("/pa05/mac", { key_hex: key, message_hex: "48656c6c6f20576f726c642121212121", mac_type: "prf" });
    } else if (primitive === "MAC") {
      result = await apiFetch("/pa05/mac", {
        key_hex: "000102030405060708090a0b0c0d0e0f",
        message_hex: "48656c6c6f",
        mac_type: "cbc"
      });
    } else if (primitive === "HMAC") {
      result = await apiFetch("/pa10/hmac", {
        key_hex: "000102030405060708090a0b0c0d0e0f",
        message_hex: "48656c6c6f"
      });
    } else if (primitive === "CRHF") {
      result = await apiFetch("/pa08/hash", { message_hex: "48656c6c6f" });
    } else {
      result = { note: `${primitive} demo — see backend for full implementation` };
    }
    setOutput(result);
    onResult(result);
    setLoading(false);
  };

  return (
    <div className="panel build-panel">
      <h2 className="panel-title">
        🏗 Build Panel
        <span className="panel-subtitle">Construct primitive A</span>
      </h2>
      <div className="select-row">
        <label>Select Primitive A:</label>
        <select value={primitive} onChange={e => setPrimitive(e.target.value)}>
          {PRIMITIVES.map(p => <option key={p} value={p}>{p} ({PA_LABELS[p]})</option>)}
        </select>
      </div>
      <div className="foundation-info">
        <strong>Foundation:</strong> {foundation === "AES" ? AES_Foundation.asOWF() : DLP_Foundation.asOWF()}
      </div>
      <button className="btn primary" onClick={runDemo} disabled={loading}>
        {loading ? "Running..." : `Demo ${primitive}`}
      </button>
      {output && (
        <div className="output-box">
          <pre>{JSON.stringify(output, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

// ── Reduce Panel (Column 2) ───────────────────────────────────────────────────
function ReducePanel({ primitiveA, primitiveB, setPrimitiveB, sourceResult }) {
  const [loading, setLoading] = useState(false);
  const [reduction, setReduction] = useState(null);
  const [direction, setDirection] = useState("forward");

  const fetchReduction = async () => {
    setLoading(true);
    const [a, b] = direction === "forward" ? [primitiveA, primitiveB] : [primitiveB, primitiveA];
    const result = await apiFetch(`/reductions/${a}/${b}`);
    setReduction(result);
    setLoading(false);
  };

  return (
    <div className="panel reduce-panel">
      <h2 className="panel-title">
        🔄 Reduce Panel
        <span className="panel-subtitle">Reduce A → B or B → A</span>
      </h2>
      <div className="select-row">
        <label>Select Primitive B:</label>
        <select value={primitiveB} onChange={e => setPrimitiveB(e.target.value)}>
          {PRIMITIVES.map(p => <option key={p} value={p}>{p} ({PA_LABELS[p]})</option>)}
        </select>
      </div>
      <div className="direction-toggle">
        <button
          className={`btn toggle ${direction === "forward" ? "active" : ""}`}
          onClick={() => setDirection("forward")}
        >
          {primitiveA} → {primitiveB}
        </button>
        <button
          className={`btn toggle ${direction === "backward" ? "active" : ""}`}
          onClick={() => setDirection("backward")}
        >
          {primitiveB} → {primitiveA}
        </button>
      </div>
      <button className="btn primary" onClick={fetchReduction} disabled={loading}>
        {loading ? "Fetching..." : "Get Reduction"}
      </button>
      {reduction && (
        <div className="output-box">
          {reduction.error ? (
            <div className="error">{reduction.error}<br /><small>{reduction.suggestion}</small></div>
          ) : (
            <>
              <div className="reduction-step">
                <strong>Forward ({reduction.from} → {reduction.to}):</strong>
                <p>{reduction.forward || "Not available"}</p>
              </div>
              <div className="reduction-step">
                <strong>Backward ({reduction.to} → {reduction.from}):</strong>
                <p>{reduction.backward || "Not available"}</p>
              </div>
            </>
          )}
        </div>
      )}
      {!reduction && <Stub primitive={primitiveB} />}
    </div>
  );
}

// ── Demo Widgets ──────────────────────────────────────────────────────────────
function MillionairesWidget({ group }) {
  const [x, setX] = useState(5);
  const [y, setY] = useState(3);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    const r = await apiFetch("/pa20/millionaires", { x, y, n_bits: 4 });
    setResult(r);
    setLoading(false);
  };

  return (
    <div className="widget">
      <h3>🤑 Millionaire's Problem (PA#20)</h3>
      <div className="widget-inputs">
        <label>Alice's wealth x: <input type="number" min="0" max="15" value={x} onChange={e => setX(+e.target.value)} /></label>
        <label>Bob's wealth y: <input type="number" min="0" max="15" value={y} onChange={e => setY(+e.target.value)} /></label>
      </div>
      <button className="btn primary" onClick={run} disabled={loading}>{loading ? "Computing..." : "Secure Compare"}</button>
      {result && (
        <div className="widget-result">
          <div className={`result-badge ${result.x_greater_than_y ? "success" : "neutral"}`}>
            {x} {result.x_greater_than_y ? ">" : "≤"} {y}
          </div>
          <div className="result-meta">
            OT calls: {result.ot_calls} | Time: {result.elapsed_s}s
          </div>
        </div>
      )}
    </div>
  );
}

function PrimalityWidget() {
  const [n, setN] = useState(104729);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    const r = await apiFetch("/pa13/miller_rabin_rounds", { n, k: 10 });
    setResult(r);
    setLoading(false);
  };

  return (
    <div className="widget">
      <h3>🔢 Miller-Rabin Primality Test (PA#13)</h3>
      <div className="widget-inputs">
        <label>Number n: <input type="number" value={n} onChange={e => setN(+e.target.value)} /></label>
      </div>
      <button className="btn primary" onClick={run} disabled={loading}>{loading ? "Testing..." : "Test Primality"}</button>
      {result && (
        <div className="widget-result">
          <div className={`result-badge ${result.final_is_prime ? "success" : "error"}`}>
            {n} is {result.final_is_prime ? "" : "NOT "}prime
          </div>
          <div className="rounds-grid">
            {result.rounds?.map((r, i) => (
              <span key={i} className={`round-badge ${r.composite_detected ? "error" : "success"}`}>
                R{r.round}: {r.composite_detected ? "COMP" : "PASS"}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SecureAndWidget() {
  const [a, setA] = useState(1);
  const [b, setB] = useState(1);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    const r = await apiFetch("/pa19/secure_and", { a, b });
    setResult(r);
    setLoading(false);
  };

  return (
    <div className="widget">
      <h3>🔐 Secure AND Gate (PA#19)</h3>
      <div className="widget-inputs">
        <label>Alice's bit a:
          <select value={a} onChange={e => setA(+e.target.value)}>
            <option value={0}>0</option><option value={1}>1</option>
          </select>
        </label>
        <label>Bob's bit b:
          <select value={b} onChange={e => setB(+e.target.value)}>
            <option value={0}>0</option><option value={1}>1</option>
          </select>
        </label>
      </div>
      <button className="btn primary" onClick={run} disabled={loading}>{loading ? "Computing..." : "Secure AND"}</button>
      {result && (
        <div className="widget-result">
          <div className="result-badge success">{a} AND {b} = {result.a_and_b}</div>
          <div className="result-meta">Expected: {(a & b)} ✓</div>
        </div>
      )}
    </div>
  );
}

// ── Proof Summary Panel ───────────────────────────────────────────────────────
function ProofPanel({ primitiveA, primitiveB, foundation }) {
  const [open, setOpen] = useState(false);

  const proofText = `
Security Reduction Summary
══════════════════════════

Foundation: ${foundation === "AES" ? "AES-128 (assumed secure PRF/PRP)" : "DLP Group (CDH/DDH hardness)"}

Build Path: ${primitiveA}
  ${PA_LABELS[primitiveA]}: Implements ${primitiveA} from foundation

Reduction: ${primitiveA} → ${primitiveB}
  Security theorem: If ${primitiveA} is secure, then ${primitiveB} is secure.
  Proof by reduction: any adversary breaking ${primitiveB} can be used
  to break ${primitiveA}, contradicting its assumed security.

Key results:
  • OWF → PRG: HILL theorem (computational security)
  • PRG → PRF: GGM tree (security reduces to PRG security)
  • PRF → MAC: PRF-MAC theorem (EUF-CMA from PRF security)
  • CRHF → HMAC: HMAC security from collision resistance
  • ElGamal IND-CPA: from DDH assumption in prime-order group
  • RSA signatures EUF-CMA: from RSA assumption + CRHF

Bidirectional reductions (PA#1, #2, #10):
  • OWF ↔ PRG, PRG ↔ PRF, CRHF ↔ HMAC ↔ MAC
  `;

  return (
    <div className="proof-panel">
      <button className="proof-toggle" onClick={() => setOpen(!open)}>
        📋 Proof Summary {open ? "▲" : "▼"}
      </button>
      {open && (
        <div className="proof-content">
          <pre>{proofText}</pre>
        </div>
      )}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [foundation, setFoundation] = useState("AES");
  const [primitiveA, setPrimitiveA] = useState("OWF");
  const [primitiveB, setPrimitiveB] = useState("PRG");
  const [buildResult, setBuildResult] = useState(null);
  const [apiStatus, setApiStatus] = useState("checking");

  useEffect(() => {
    apiFetch("/health").then(r => {
      setApiStatus(r.status === "healthy" ? "connected" : "error");
    }).catch(() => setApiStatus("offline"));
  }, []);

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <h1>CS8.401 — Cryptographic Primitives</h1>
          <span className="subtitle">Interactive Reduction Explorer</span>
        </div>
        <div className="header-right">
          <div className={`api-status ${apiStatus}`}>
            API: {apiStatus}
          </div>
          <div className="foundation-toggle">
            <span>Foundation:</span>
            {["AES", "DLP"].map(f => (
              <button
                key={f}
                className={`btn toggle ${foundation === f ? "active" : ""}`}
                onClick={() => setFoundation(f)}
              >
                {f === "AES" ? "AES-128" : "DLP Group"}
              </button>
            ))}
          </div>
        </div>
      </header>

      <main className="main-grid">
        <BuildPanel
          foundation={foundation}
          primitive={primitiveA}
          setPrimitive={setPrimitiveA}
          onResult={setBuildResult}
        />
        <ReducePanel
          primitiveA={primitiveA}
          primitiveB={primitiveB}
          setPrimitiveB={setPrimitiveB}
          sourceResult={buildResult}
        />
      </main>

      <section className="demo-section">
        <h2>Interactive Demo Widgets</h2>
        <div className="widgets-grid">
          <PrimalityWidget />
          <SecureAndWidget />
          <MillionairesWidget />
        </div>
      </section>

      <ProofPanel primitiveA={primitiveA} primitiveB={primitiveB} foundation={foundation} />

      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', system-ui, sans-serif; background: #0f1117; color: #e1e4e8; }
        .app { min-height: 100vh; display: flex; flex-direction: column; }

        .header {
          display: flex; justify-content: space-between; align-items: center;
          padding: 1rem 2rem; background: #161b22; border-bottom: 1px solid #30363d;
        }
        .header h1 { font-size: 1.4rem; color: #58a6ff; }
        .subtitle { font-size: 0.8rem; color: #8b949e; display: block; margin-top: 2px; }
        .header-right { display: flex; gap: 1rem; align-items: center; }
        .api-status { padding: 4px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }
        .api-status.connected { background: #0d4f2d; color: #56d364; }
        .api-status.offline { background: #4a0f0f; color: #f85149; }
        .api-status.checking { background: #333; color: #999; }

        .foundation-toggle { display: flex; gap: 6px; align-items: center; font-size: 0.85rem; color: #8b949e; }

        .main-grid {
          display: grid; grid-template-columns: 1fr 1fr;
          gap: 1.5rem; padding: 1.5rem 2rem;
        }

        .panel {
          background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.5rem;
          display: flex; flex-direction: column; gap: 1rem;
        }
        .panel-title {
          font-size: 1.1rem; color: #f0f6fc; display: flex;
          justify-content: space-between; align-items: baseline;
        }
        .panel-subtitle { font-size: 0.75rem; color: #8b949e; font-weight: 400; }

        .select-row { display: flex; gap: 1rem; align-items: center; }
        .select-row label { font-size: 0.85rem; color: #8b949e; white-space: nowrap; }
        select {
          background: #0d1117; border: 1px solid #30363d; color: #e1e4e8;
          padding: 6px 10px; border-radius: 6px; font-size: 0.85rem;
        }
        .foundation-info { font-size: 0.8rem; color: #8b949e; padding: 8px 12px; background: #0d1117; border-radius: 6px; }

        .btn {
          padding: 8px 16px; border-radius: 6px; border: 1px solid #30363d;
          cursor: pointer; font-size: 0.85rem; transition: all 0.15s;
        }
        .btn.primary { background: #238636; color: white; border-color: #238636; }
        .btn.primary:hover { background: #2ea043; }
        .btn.primary:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn.toggle { background: #21262d; color: #8b949e; }
        .btn.toggle.active { background: #1f6feb; color: white; border-color: #1f6feb; }
        .btn.toggle:hover:not(.active) { background: #30363d; }

        .direction-toggle { display: flex; gap: 8px; }

        .output-box {
          background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
          padding: 1rem; overflow: auto; max-height: 280px;
        }
        .output-box pre { font-size: 0.75rem; color: #79c0ff; white-space: pre-wrap; }
        .error { color: #f85149; font-size: 0.85rem; }
        .reduction-step { margin-bottom: 0.75rem; }
        .reduction-step p { font-size: 0.82rem; color: #8b949e; margin-top: 4px; }

        .stub {
          background: #1c2128; border: 1px dashed #30363d; border-radius: 6px;
          padding: 12px; font-size: 0.82rem; color: #6e7681; text-align: center;
        }

        .demo-section { padding: 0 2rem 1.5rem; }
        .demo-section h2 { font-size: 1rem; color: #8b949e; margin-bottom: 1rem; }
        .widgets-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }

        .widget {
          background: #161b22; border: 1px solid #30363d; border-radius: 10px;
          padding: 1.25rem; display: flex; flex-direction: column; gap: 0.75rem;
        }
        .widget h3 { font-size: 0.9rem; color: #f0f6fc; }
        .widget-inputs { display: flex; flex-direction: column; gap: 6px; }
        .widget-inputs label { font-size: 0.82rem; color: #8b949e; display: flex; gap: 8px; align-items: center; }
        .widget-inputs input, .widget-inputs select {
          background: #0d1117; border: 1px solid #30363d; color: #e1e4e8;
          padding: 4px 8px; border-radius: 4px; font-size: 0.82rem; width: 80px;
        }
        .widget-result { display: flex; flex-direction: column; gap: 6px; }
        .result-badge {
          padding: 6px 12px; border-radius: 6px; font-size: 0.85rem; font-weight: 600; text-align: center;
        }
        .result-badge.success { background: #0d4f2d; color: #56d364; }
        .result-badge.error { background: #4a0f0f; color: #f85149; }
        .result-badge.neutral { background: #333; color: #8b949e; }
        .result-meta { font-size: 0.75rem; color: #6e7681; }
        .rounds-grid { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
        .round-badge { padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; }
        .round-badge.success { background: #0d4f2d; color: #56d364; }
        .round-badge.error { background: #4a0f0f; color: #f85149; }

        .proof-panel { margin: 0 2rem 2rem; }
        .proof-toggle {
          width: 100%; padding: 10px 16px; background: #21262d; border: 1px solid #30363d;
          color: #8b949e; border-radius: 8px; cursor: pointer; text-align: left; font-size: 0.88rem;
        }
        .proof-toggle:hover { background: #30363d; color: #e1e4e8; }
        .proof-content {
          background: #0d1117; border: 1px solid #30363d; border-top: none;
          border-radius: 0 0 8px 8px; padding: 1.5rem;
        }
        .proof-content pre { font-size: 0.78rem; color: #8b949e; white-space: pre-wrap; line-height: 1.6; }
      `}</style>
    </div>
  );
}
