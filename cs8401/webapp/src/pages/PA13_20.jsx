import { useState } from "react";
import { apiFetch } from "../api";

// ── Shared helpers ────────────────────────────────────────────────────────────
function Field({ label, value, mono = true, accent }) {
  return (
    <div style={{ marginBottom: "0.5rem" }}>
      <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: 2 }}>{label}</div>
      <div style={{
        fontFamily: mono ? "'JetBrains Mono', monospace" : "inherit",
        fontSize: "0.8rem", color: accent || "var(--accent-cyan)",
        background: "var(--bg-input)", padding: "0.4rem 0.6rem",
        borderRadius: 6, border: "1px solid var(--border)", wordBreak: "break-all"
      }}>{String(value)}</div>
    </div>
  );
}

// ── PA#13: Miller-Rabin — Interactive Primality Tester ───────────────────────
export function PA13() {
  const [n, setN] = useState("104729");
  const [k, setK] = useState(10);
  const [result, setResult] = useState(null);
  const [carmResult, setCarmResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true); setCarmResult(null);
    const num = parseInt(n);
    if (isNaN(num) || num < 2) { setResult({ error: "Enter an integer ≥ 2" }); setLoading(false); return; }
    setResult(await apiFetch("/pa13/miller_rabin_rounds", { n: num, k }));
    setLoading(false);
  };

  const runCarmichael = async () => {
    setLoading(true); setResult(null);
    setCarmResult(await apiFetch("/pa13/carmichael_demo"));
    setLoading(false);
  };

  const presets = [
    { label: "561 (Carmichael)", value: "561", desc: "Fools Fermat, caught by MR" },
    { label: "104729 (prime)", value: "104729", desc: "Known 512-bit-range prime" },
    { label: "1000000007 (prime)", value: "1000000007", desc: "Large prime" },
    { label: "1729 (Carmichael)", value: "1729", desc: "Hardy-Ramanujan number" },
    { label: "15 (composite)", value: "15", desc: "3 × 5" },
  ];

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#13</span> Miller-Rabin Primality Tester</h2>
      <p>Probabilistic primality test. Error probability ≤ 4<sup>−k</sup>. For k = {k}: ≤ {(Math.pow(4, -k)).toExponential(2)}.</p>
    </div>

    <div className="card">
      <h3>🔢 Input</h3>
      <div className="input-group">
        <label>Number n (up to 20 digits)</label>
        <input value={n} onChange={e => setN(e.target.value)} placeholder="Enter integer ≥ 2" style={{ fontFamily: "'JetBrains Mono', monospace" }} />
      </div>
      <div className="input-group" style={{ marginTop: '0.5rem' }}>
        <label>Rounds k = {k} <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>(error ≤ 4<sup>−{k}</sup>)</span></label>
        <input type="range" min={1} max={40} value={k} onChange={e => setK(+e.target.value)}
          style={{ width: '100%', accentColor: 'var(--accent-blue)' }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.65rem', color: 'var(--text-muted)' }}>
          <span>k = 1 (fast)</span><span>k = 40 (very high confidence)</span>
        </div>
      </div>
    </div>

    <div className="card">
      <h3>⚡ Quick Test Presets</h3>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {presets.map(p => (
          <button key={p.value} className="btn btn-ghost"
            onClick={() => { setN(p.value); setResult(null); }}
            style={{ fontSize: '0.75rem', padding: '0.35rem 0.6rem', borderRadius: 6 }}>
            {p.label}
          </button>
        ))}
      </div>
    </div>

    <div className="card">
      <div className="input-row">
        <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "🧪 Test Primality"}</button>
        <button className="btn btn-danger" onClick={runCarmichael} disabled={loading}>Carmichael Numbers Demo</button>
      </div>
    </div>

    {result && !result.error && (
      <div className="card fade-in">
        <div className="result-row" style={{ marginBottom: '0.75rem' }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            {result.n}
          </span>
          <span className={`badge ${result.final_is_prime ? 'badge-success' : 'badge-error'}`} style={{ fontSize: '0.9rem', padding: '0.3rem 0.8rem' }}>
            {result.final_is_prime ? 'PROBABLY PRIME' : 'COMPOSITE'}
          </span>
        </div>

        {result.rounds && (
          <>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 6 }}>
              Witness rounds (k = {result.rounds.length}):
            </div>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              {result.rounds.map((r, i) => (
                <span key={i} className={`badge ${r.composite_detected ? 'badge-error' : 'badge-success'}`}
                  style={{ fontSize: '0.68rem', padding: '3px 7px' }}>
                  a<sub>{r.round}</sub>: {r.composite_detected ? 'COMPOSITE' : 'PASS'}
                </span>
              ))}
            </div>
            {!result.final_is_prime && (
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-red)' }}>
                ✗ Composite detected — at least one witness proved n is not prime.
              </div>
            )}
            {result.final_is_prime && (
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-green)' }}>
                ✓ All {result.rounds.length} witnesses passed — n is prime with probability ≥ 1 − 4<sup>−{result.rounds.length}</sup>.
              </div>
            )}
          </>
        )}
      </div>
    )}

    {result?.error && <div className="card fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}

    {carmResult && carmResult.carmichael_numbers && (
      <div className="card fade-in">
        <h3>🎭 Carmichael Numbers</h3>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>{carmResult.note}</p>
        <table className="data-table">
          <thead><tr><th>n</th><th>Fermat Test</th><th>Miller-Rabin</th></tr></thead>
          <tbody>{carmResult.carmichael_numbers.map(c => (
            <tr key={c.n}>
              <td style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: 'var(--accent-cyan)' }}>{c.n}</td>
              <td><span className="badge badge-error" style={{ fontSize: '0.7rem' }}>Passes Fermat ⚠️</span></td>
              <td><span className={`badge ${c.is_prime ? 'badge-error' : 'badge-success'}`} style={{ fontSize: '0.7rem' }}>
                {c.is_prime ? 'PRIME (false!)' : 'COMPOSITE ✓'}
              </span></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    )}
  </>);
}

// ── PA#14: CRT & Håstad Broadcast Attack ─────────────────────────────────────
export function PA14() {
  const [residues, setResidues] = useState("2,3,2");
  const [moduli, setModuli] = useState("3,5,7");
  const [crtResult, setCrtResult] = useState(null);
  const [hastadMsg, setHastadMsg] = useState(42);
  const [usePkcs, setUsePkcs] = useState(false);
  const [hastadResult, setHastadResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [hLoading, setHLoading] = useState(false);

  const runCrt = async () => {
    setLoading(true);
    const r = residues.split(",").map(Number);
    const m = moduli.split(",").map(Number);
    setCrtResult(await apiFetch("/pa14/crt", { residues: r, moduli: m }));
    setLoading(false);
  };

  const runHastad = async () => {
    setHLoading(true);
    setHastadResult(await apiFetch("/pa14/hastad", { message: hastadMsg, use_pkcs: usePkcs }));
    setHLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#14</span> CRT & Håstad Broadcast Attack</h2>
      <p>CRT solver + broadcast attack on textbook RSA with e = 3.</p>
    </div>

    <div className="card">
      <h3>⚡ CRT Solver</h3>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        <div className="input-group"><label>Residues (comma-separated)</label><input value={residues} onChange={e => setResidues(e.target.value)} /></div>
        <div className="input-group"><label>Moduli (comma-separated)</label><input value={moduli} onChange={e => setModuli(e.target.value)} /></div>
      </div>
      <button className="btn btn-primary" onClick={runCrt} disabled={loading}>{loading ? <span className="spinner"/> : "Solve CRT"}</button>
      {crtResult && !crtResult.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Solution x" value={crtResult.x} mono={false} accent="var(--accent-green)" />
          <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: 4, marginTop: "0.5rem" }}>Verification:</div>
          {crtResult.checks?.map((chk, i) => (
            <div key={i} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.72rem",
              color: "var(--accent-cyan)", padding: "0.2rem 0.5rem",
              background: "var(--bg-input)", borderRadius: 4, marginBottom: 2,
              border: "1px solid var(--border)" }}>{chk}</div>
          ))}
        </div>
      )}
    </div>

    <div className="card" style={{ borderColor: usePkcs ? 'rgba(16,185,129,0.4)' : 'rgba(239,68,68,0.4)' }}>
      <h3>📡 Håstad Broadcast Attack (e = 3)</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Same message m encrypted under 3 independent RSA keys (N₁, N₂, N₃) with e = 3. CRT recovers m³, cube root recovers m.
      </p>
      <div className="input-group"><label>Secret message m (integer)</label>
        <input type="number" value={hastadMsg} onChange={e => setHastadMsg(+e.target.value)} />
      </div>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap', marginTop: '0.25rem', marginBottom: '0.5rem' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', cursor: 'pointer',
          padding: '0.4rem 0.7rem', borderRadius: 6,
          background: usePkcs ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.08)',
          border: `1px solid ${usePkcs ? 'var(--accent-green)' : 'var(--accent-red)'}`,
          color: usePkcs ? 'var(--accent-green)' : 'var(--accent-red)' }}>
          <input type="checkbox" checked={usePkcs} onChange={e => { setUsePkcs(e.target.checked); setHastadResult(null); }} />
          {usePkcs ? '✅ PKCS#1 v1.5 padding (attack fails)' : '⚠️ No padding (attack succeeds)'}
        </label>
      </div>
      <button className="btn btn-danger" onClick={runHastad} disabled={hLoading}>
        {hLoading ? <span className="spinner"/> : "🚀 Run Broadcast Attack"}
      </button>

      {hastadResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
            {hastadResult.recipients?.map((r, i) => (
              <div key={i} style={{ background: 'rgba(59,130,246,0.06)', borderRadius: 8, padding: '0.6rem', border: '1px solid rgba(59,130,246,0.2)' }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4 }}>Recipient {i + 1}</div>
                <div style={{ fontSize: '0.65rem', color: 'var(--accent-cyan)', fontFamily: "'JetBrains Mono', monospace", wordBreak: 'break-all', marginBottom: 4 }}>
                  N{i+1} = {r.N}
                </div>
                <div style={{ fontSize: '0.65rem', color: 'var(--accent-purple)', fontFamily: "'JetBrains Mono', monospace", wordBreak: 'break-all' }}>
                  c{i+1} = {r.c}
                </div>
              </div>
            ))}
          </div>

          <div style={{ background: 'rgba(245,158,11,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(245,158,11,0.3)', marginBottom: '0.75rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4 }}>🕵️ Attacker: CRT(c₁, c₂, c₃) mod N₁·N₂·N₃ = m³</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-amber)', wordBreak: 'break-all' }}>
              m³ = {hastadResult.m_cubed_prefix}
            </div>
          </div>

          <div style={{ background: hastadResult.original_matches ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
            borderRadius: 8, padding: '0.75rem', textAlign: 'center',
            border: `1px solid ${hastadResult.original_matches ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}` }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4 }}>∛m³ = Cube Root</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '1.1rem', fontWeight: 600,
              color: hastadResult.original_matches ? 'var(--accent-green)' : 'var(--accent-red)' }}>
              m = {hastadResult.m_recovered}
            </div>
            <div className="result-row" style={{ justifyContent: 'center', marginTop: '0.5rem' }}>
              <span className={`badge ${hastadResult.original_matches ? 'badge-success' : 'badge-error'}`}>
                {hastadResult.original_matches ? '✅ Attack succeeded! m recovered exactly' : '❌ Attack failed — cube root ≠ original m'}
              </span>
              <span className={`badge ${hastadResult.perfect_cube ? 'badge-info' : 'badge-warn'}`}>
                Perfect cube: {hastadResult.perfect_cube ? 'Yes' : 'No'}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  </>);
}

// ── PA#15: Digital Signatures — Sign, Verify, Forge ──────────────────────────
export function PA15() {
  const [msg, setMsg] = useState("48656c6c6f");
  const [signResult, setSignResult] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [m1, setM1] = useState(7);
  const [m2, setM2] = useState(11);
  const [forgeryResult, setForgeryResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const sign = async () => { setLoading(true); setVerifyResult(null); setSignResult(await apiFetch("/pa15/sign", { message_hex: msg })); setLoading(false); };
  const verify = async () => { setLoading(true); setVerifyResult(await apiFetch("/pa15/verify", { message_hex: msg })); setLoading(false); };
  const forge = async () => { setLoading(true); setForgeryResult(await apiFetch("/pa15/forgery", { m1, m2 })); setLoading(false); };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#15</span> Digital Signatures — Sign & Verify</h2>
      <p>σ = H(m)<sup>d</sup> mod N. Verify: σ<sup>e</sup> mod N = H(m). Hash-then-sign prevents forgery.</p>
    </div>

    <div className="card">
      <h3>✍️ Sign Message</h3>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <div className="input-row">
        <button className="btn btn-primary" onClick={sign} disabled={loading}>{loading ? <span className="spinner"/> : "✍️ Sign"}</button>
        {signResult && <button className="btn btn-success" onClick={verify} disabled={loading}>✅ Verify + Tamper Test</button>}
      </div>
      {signResult && !signResult.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Message (hex)" value={signResult.message_hex} />
          <Field label="H(m) = DLP_Hash(m)" value={signResult.hash_hex} accent="var(--accent-cyan)" />
          <Field label="σ = H(m)^d mod N" value={signResult.signature} accent="var(--accent-purple)" />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            <Field label="σ^e mod N" value={String(signResult.sigma_e_mod_n).slice(0, 30)} accent="var(--accent-amber)" />
            <Field label="H(m) (int)" value={signResult.hash_int} accent="var(--accent-cyan)" />
          </div>
          <div className="result-row">
            <span className={`badge ${signResult.sigma_e_matches_h ? 'badge-success' : 'badge-error'}`}>
              σ^e mod N {signResult.sigma_e_matches_h ? '= H(m) ✓' : '≠ H(m) ✗'}
            </span>
          </div>
        </div>
      )}
    </div>

    {verifyResult && (
      <div className="card fade-in">
        <h3>🔒 Verification & Tamper Test</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div style={{ background: 'rgba(16,185,129,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(16,185,129,0.3)' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6 }}>Original message</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-cyan)', marginBottom: 8, wordBreak: 'break-all' }}>{msg}</div>
            <span className={`badge ${verifyResult.valid ? 'badge-success' : 'badge-error'}`}>
              {verifyResult.valid ? '✅ Signature Valid' : '❌ Invalid'}
            </span>
          </div>
          <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6 }}>Tampered (1 bit flipped)</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-red)', marginBottom: 8, wordBreak: 'break-all' }}>{verifyResult.tampered_hex}</div>
            <span className={`badge ${verifyResult.tampered_valid ? 'badge-error' : 'badge-success'}`}>
              {verifyResult.tampered_valid ? '⚠️ Forgery Accepted!' : '✅ Forgery Rejected'}
            </span>
          </div>
        </div>
        <div style={{ marginTop: '0.5rem', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          Hash-then-sign: even 1-bit tamper invalidates the signature.
        </div>
      </div>
    )}

    <div className="card" style={{ borderColor: 'rgba(239,68,68,0.4)' }}>
      <h3>⚠️ Multiplicative Forgery (Raw RSA, no hash)</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Without hashing, RSA signatures are homomorphic: σ(m₁)·σ(m₂) mod N = σ(m₁·m₂ mod N).
        An attacker with signatures on m₁ and m₂ can forge a signature on m₁·m₂ without the private key!
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        <div className="input-group"><label>m₁ (integer)</label><input type="number" value={m1} onChange={e => setM1(+e.target.value)} /></div>
        <div className="input-group"><label>m₂ (integer)</label><input type="number" value={m2} onChange={e => setM2(+e.target.value)} /></div>
      </div>
      <button className="btn btn-danger" onClick={forge} disabled={loading}>
        {loading ? <span className="spinner"/> : "🔓 Forge σ(m₁·m₂)"}
      </button>

      {forgeryResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <Field label="σ(m₁) = m₁^d mod N" value={forgeryResult.sigma1_prefix} />
            <Field label="σ(m₂) = m₂^d mod N" value={forgeryResult.sigma2_prefix} />
            <Field label="σ_forged = σ₁·σ₂ mod N" value={forgeryResult.sigma_forged_prefix} accent="var(--accent-red)" />
          </div>
          <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem',
            border: '1px solid rgba(239,68,68,0.3)', textAlign: 'center' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>
              m₁·m₂ mod N = {forgeryResult.m_product}
            </div>
            <span className={`badge ${forgeryResult.forged_valid ? 'badge-error' : 'badge-success'}`} style={{ fontSize: '0.85rem' }}>
              {forgeryResult.forged_valid ? '⚠️ Forged signature VALID! (no hash = broken)' : '✅ Forgery failed'}
            </span>
            <div style={{ fontSize: '0.72rem', color: 'var(--accent-red)', marginTop: '0.5rem', fontStyle: 'italic' }}>
              {forgeryResult.note}
            </div>
          </div>
        </div>
      )}
    </div>
  </>);
}

// ── PA#16: ElGamal — Malleability Demo ───────────────────────────────────────
export function PA16() {
  const [msg, setMsg] = useState(42);
  const [encResult, setEncResult] = useState(null);
  const [malResult, setMalResult] = useState(null);
  const [batchResult, setBatchResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const enc = async () => { setLoading(true); setMalResult(null); setEncResult(await apiFetch("/pa16/encrypt", { message: msg })); setLoading(false); };
  const mal = async () => { setLoading(true); setMalResult(await apiFetch("/pa16/malleability", { message: msg })); setLoading(false); };
  const batch = async () => { setLoading(true); setBatchResult(await apiFetch("/pa16/malleability_batch", { trials: 10 })); setLoading(false); };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#16</span> ElGamal — IND-CPA but NOT CCA</h2>
      <p>ElGamal is IND-CPA secure (DDH assumption) but malleable. Modify c₂ → control plaintext.</p>
    </div>

    <div className="card">
      <h3>🔐 Encrypt / Decrypt</h3>
      <div className="input-group"><label>Plaintext m (group element, integer)</label>
        <input type="number" value={msg} onChange={e => setMsg(+e.target.value)} />
      </div>
      <button className="btn btn-primary" onClick={enc} disabled={loading}>
        {loading ? <span className="spinner"/> : "🔐 Encrypt → Decrypt"}
      </button>
      {encResult && !encResult.error && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <Field label="Plaintext m" value={encResult.message} mono={false} accent="var(--text-primary)" />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            <Field label="c₁ = g^r mod p" value={encResult.c1} />
            <Field label="c₂ = m·h^r mod p" value={encResult.c2} />
          </div>
          <Field label="Dec(c₁, c₂) = m'" value={encResult.decrypted} mono={false} accent="var(--accent-green)" />
          <div className="result-row">
            <span className={`badge ${encResult.correct ? 'badge-success' : 'badge-error'}`}>
              Roundtrip: {encResult.correct ? '✓ Correct' : '✗ Failed'}
            </span>
          </div>
        </div>
      )}
    </div>

    <div className="card" style={{ borderColor: 'rgba(239,68,68,0.4)' }}>
      <h3>⚠️ Malleability Attack: Multiply c₂ by 2</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Given ciphertext (c₁, c₂), construct (c₁, 2c₂ mod p). Decryption yields 2m — attacker controls plaintext without knowing m or the key!
      </p>
      <div className="input-row">
        <button className="btn btn-danger" onClick={mal} disabled={loading}>
          {loading ? <span className="spinner"/> : "🔄 Multiply c₂ by 2 → Decrypt"}
        </button>
        <button className="btn btn-warn" onClick={batch} disabled={loading}>
          📊 Run 10 Trials
        </button>
      </div>

      {malResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{ background: 'rgba(59,130,246,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(59,130,246,0.2)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4 }}>Original ciphertext</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-cyan)', marginBottom: 4 }}>c₁ = {malResult.c1}...</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-blue)' }}>c₂ = {malResult.c2}...</div>
              <div style={{ marginTop: 6, fontSize: '0.75rem' }}>Dec → <strong style={{ color: 'var(--accent-green)' }}>{malResult.decrypted}</strong></div>
            </div>
            <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4 }}>Modified ciphertext</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-cyan)', marginBottom: 4 }}>c₁ = {malResult.c1}... (same)</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-red)' }}>2·c₂ = {malResult.c2_doubled}...</div>
              <div style={{ marginTop: 6, fontSize: '0.75rem' }}>Dec → <strong style={{ color: 'var(--accent-red)' }}>{malResult.malleable_decrypted}</strong></div>
            </div>
          </div>
          <div className="result-row" style={{ justifyContent: 'center' }}>
            <span className="badge badge-info">Expected: 2 × {malResult.message} = {malResult.expected_2m}</span>
            <span className={`badge ${malResult.malleability_works ? 'badge-error' : 'badge-success'}`}>
              {malResult.malleability_works ? '⚠️ Dec(c₁, 2c₂) = 2m — CCA BROKEN!' : '✓ Attack failed'}
            </span>
          </div>
        </div>
      )}

      {batchResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ background: 'rgba(239,68,68,0.06)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.2)', textAlign: 'center' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4 }}>Malleability success rate</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--accent-red)', fontFamily: "'JetBrains Mono', monospace" }}>
              {batchResult.rate}%
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              {batchResult.successes}/{batchResult.trials} trials — should be 100%
            </div>
            {/* Visual bar */}
            <div style={{ width: '100%', height: 8, borderRadius: 4, background: 'var(--bg-input)', marginTop: 6, overflow: 'hidden' }}>
              <div style={{ width: `${batchResult.rate}%`, height: '100%', borderRadius: 4,
                background: 'linear-gradient(90deg, var(--accent-red), var(--accent-amber))', transition: 'width 0.3s' }} />
            </div>
          </div>
        </div>
      )}
    </div>
  </>);
}

// ── PA#17: CCA-Secure PKC — Encrypt-then-Sign ───────────────────────────────
export function PA17() {
  const [msg, setMsg] = useState(42);
  const [encResult, setEncResult] = useState(null);
  const [contrastResult, setContrastResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => { setLoading(true); setContrastResult(null); setEncResult(await apiFetch("/pa17/encrypt", { message: msg })); setLoading(false); };
  const contrast = async () => { setLoading(true); setContrastResult(await apiFetch("/pa17/contrast", { message: msg })); setLoading(false); };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#17</span> CCA-Secure PKC — Encrypt-then-Sign</h2>
      <p>Sign the ciphertext with PA#15 signatures. Tampered ciphertexts fail signature verification → ⊥.</p>
    </div>

    <div className="card">
      <h3>🏰 Encrypt-then-Sign</h3>
      <div className="input-group"><label>Message m (integer)</label>
        <input type="number" value={msg} onChange={e => setMsg(+e.target.value)} />
      </div>
      <div className="input-row">
        <button className="btn btn-primary" onClick={run} disabled={loading}>
          {loading ? <span className="spinner"/> : "🔐 Encrypt + Sign → Tamper Test"}
        </button>
        <button className="btn btn-danger" onClick={contrast} disabled={loading}>
          ⚔️ Contrast: ElGamal vs CCA-PKC
        </button>
      </div>
    </div>

    {encResult && !encResult.error && (
      <div className="card fade-in">
        <h3>📦 Ciphertext (C_E, σ)</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <Field label="c₁ (ElGamal)" value={encResult.c1_prefix} />
          <Field label="c₂ (ElGamal)" value={encResult.c2_prefix} />
          <Field label="σ (signature)" value={encResult.sigma_prefix} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div style={{ background: 'rgba(16,185,129,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(16,185,129,0.3)' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--accent-green)', marginBottom: 6 }}>✅ Honest Decrypt</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>1. Verify(σ, C_E) → ✓</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>2. Dec(C_E) → m'</div>
            <div style={{ marginTop: 4 }}>
              <span className={`badge ${encResult.correct ? 'badge-success' : 'badge-error'}`}>
                m' = {encResult.decrypted} {encResult.correct ? '✓' : '✗'}
              </span>
            </div>
          </div>
          <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--accent-red)', marginBottom: 6 }}>🕵️ CCA Attacker: Tamper c₂</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>1. Modify c₂ → c₂ + 1</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>2. Verify(σ, C_E') → ✗</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--accent-red)', fontWeight: 600, marginBottom: 4 }}>
              "Signature invalid, decryption aborted, output ⊥"
            </div>
            <div style={{ marginTop: 4 }}>
              <span className={`badge ${encResult.tampered_rejected ? 'badge-success' : 'badge-error'}`}>
                {encResult.tampered_rejected ? '✅ Tampered ciphertext REJECTED (⊥)' : '⚠️ ACCEPTED — CCA broken!'}
              </span>
            </div>
          </div>
        </div>
      </div>
    )}

    {contrastResult && (
      <div className="card fade-in">
        <h3>⚔️ Contrast: Plain ElGamal vs CCA-PKC</h3>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
          Same message m = {contrastResult.message}. Attacker tries to tamper the ciphertext.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--accent-red)', marginBottom: 6 }}>PA#16 Plain ElGamal</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>Tamper: (c₁, 2c₂ mod p)</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>Oracle returns: <strong style={{ color: 'var(--accent-red)' }}>{contrastResult.elgamal_tampered}</strong></div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 6 }}>Expected 2m: {contrastResult.elgamal_expected}</div>
            <span className={`badge ${contrastResult.elgamal_attack_works ? 'badge-error' : 'badge-success'}`}>
              {contrastResult.elgamal_attack_works ? '⚠️ Attack WORKS — got 2m!' : '✓ Attack failed'}
            </span>
          </div>
          <div style={{ background: 'rgba(16,185,129,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(16,185,129,0.3)' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--accent-green)', marginBottom: 6 }}>PA#17 CCA-PKC (Encrypt-then-Sign)</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>Tamper: modify c₂ → c₂ + 1</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>Signature check: <strong style={{ color: 'var(--accent-red)' }}>FAIL</strong></div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 6 }}>Oracle returns: <strong style={{ color: 'var(--accent-green)' }}>⊥ (null)</strong></div>
            <span className={`badge ${contrastResult.cca_rejected ? 'badge-success' : 'badge-error'}`}>
              {contrastResult.cca_rejected ? '✅ Attack BLOCKED — signature invalid!' : '⚠️ Attack succeeded!'}
            </span>
          </div>
        </div>
        <div style={{ marginTop: '0.75rem', fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center' }}>
          Encrypt-then-Sign ensures the decryption oracle is useless to the CCA adversary.
        </div>
      </div>
    )}
  </>);
}

// ── PA#18: OT ────────────────────────────────────────────────────────────────
export function PA18() {
  const [b, setB] = useState(0);
  const [m0, setM0] = useState(42);
  const [m1, setM1] = useState(99);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); setResult(await apiFetch("/pa18/ot", { b, m0, m1 })); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#18</span> Oblivious Transfer</h2><p>1-out-of-2 OT: Bob gets m_b, Alice learns nothing about b</p></div>
    <div className="card"><h3>📨 OT Protocol</h3>
      <div className="input-row">
        <div className="input-group"><label>m₀ (Alice)</label><input type="number" value={m0} onChange={e => setM0(+e.target.value)} /></div>
        <div className="input-group"><label>m₁ (Alice)</label><input type="number" value={m1} onChange={e => setM1(+e.target.value)} /></div>
        <div className="input-group"><label>Bob's choice b</label>
          <select value={b} onChange={e => setB(+e.target.value)}><option value={0}>0</option><option value={1}>1</option></select>
        </div>
      </div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Run OT"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <div className="result-row" style={{ marginBottom: "0.75rem" }}>
            <span className={`badge ${result.correct ? "badge-success" : "badge-error"}`}>
              Bob received m_{result.b} = {result.received} {result.correct ? "✓" : "✗"}
            </span>
            <span className="badge badge-info">
              m_{1 - result.b} = {result.b === 0 ? m1 : m0} (hidden from Bob)
            </span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "0.5rem" }}>
            <Field label="Bob's choice b" value={result.b} mono={false} accent="var(--text-primary)" />
            <Field label="Received m_b" value={result.received} mono={false} accent="var(--accent-green)" />
            <Field label="Expected" value={result.expected} mono={false} accent="var(--text-secondary)" />
          </div>
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 4 }}>
            Alice cannot learn b; Bob cannot learn m_{"{1-b}"}
          </div>
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#19: Secure Gates ──────────────────────────────────────────────────────
export function PA19() {
  const [a, setA] = useState(1);
  const [b, setB] = useState(1);
  const [result, setResult] = useState(null);
  const [ttResult, setTTResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); setResult(await apiFetch("/pa19/secure_and", { a, b })); setLoading(false); };
  const runTT = async () => { setLoading(true); setTTResult(await apiFetch("/pa19/truth_table", {})); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#19</span> Secure AND / XOR / NOT</h2><p>Secure gates via OT and additive secret sharing</p></div>
    <div className="card"><h3>🚪 Secure AND</h3>
      <div className="input-row">
        <div className="input-group"><label>Alice's bit a</label><select value={a} onChange={e => setA(+e.target.value)}><option value={0}>0</option><option value={1}>1</option></select></div>
        <div className="input-group"><label>Bob's bit b</label><select value={b} onChange={e => setB(+e.target.value)}><option value={0}>0</option><option value={1}>1</option></select></div>
      </div>
      <div className="input-row">
        <button className="btn btn-primary" onClick={run} disabled={loading}>Secure AND</button>
        <button className="btn btn-success" onClick={runTT} disabled={loading}>Full Truth Table</button>
      </div>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <div className="result-row" style={{ marginBottom: "0.75rem" }}>
            <span className={`badge ${result.correct ? "badge-success" : "badge-error"}`}>
              {result.a} AND {result.b} = {result.result} {result.correct ? "✓" : "✗"}
            </span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "0.5rem" }}>
            <Field label="Alice's a" value={result.a} mono={false} accent="var(--text-primary)" />
            <Field label="Bob's b" value={result.b} mono={false} accent="var(--text-primary)" />
            <Field label="Secure AND result" value={result.result} mono={false} accent="var(--accent-green)" />
          </div>
        </div>
      )}
      {ttResult && !ttResult.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: 6 }}>Full Truth Table</div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "'JetBrains Mono',monospace", fontSize: "0.78rem" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)" }}>
                {["a", "b", "AND", "XOR", "NOT a"].map(h => (
                  <th key={h} style={{ padding: "0.3rem 0.5rem", color: "var(--text-muted)", textAlign: "center", fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ttResult.truth_table?.map((row, i) => (
                <tr key={i} style={{ borderBottom: "1px solid var(--border)", color: "var(--accent-cyan)" }}>
                  <td style={{ padding: "0.3rem 0.5rem", textAlign: "center" }}>{row.a}</td>
                  <td style={{ padding: "0.3rem 0.5rem", textAlign: "center" }}>{row.b}</td>
                  <td style={{ padding: "0.3rem 0.5rem", textAlign: "center", color: "var(--accent-green)" }}>{row.AND}</td>
                  <td style={{ padding: "0.3rem 0.5rem", textAlign: "center", color: "var(--accent-blue)" }}>{row.XOR}</td>
                  <td style={{ padding: "0.3rem 0.5rem", textAlign: "center", color: "var(--accent-amber)" }}>{row.NOT_a}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {(result?.error || ttResult?.error) && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result?.error || ttResult?.error}</pre></div>}
    </div>
  </>);
}

// ── PA#20: MPC ───────────────────────────────────────────────────────────────
export function PA20() {
  const [x, setX] = useState(7);
  const [y, setY] = useState(12);
  const [circuit, setCircuit] = useState("millionaires");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => {
    setLoading(true);
    setResult(await apiFetch(`/pa20/${circuit}`, { x, y, n_bits: 4 }));
    setLoading(false);
  };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#20</span> 2-Party MPC</h2><p>Secure circuit evaluation — Millionaire's, Equality, Addition</p></div>
    <div className="card"><h3>🤑 Secure Circuit Evaluation</h3>
      <div className="input-row">
        <div className="input-group"><label>Circuit</label>
          <select value={circuit} onChange={e => setCircuit(e.target.value)}>
            <option value="millionaires">Millionaire's (x &gt; y)</option>
            <option value="equality">Equality (x == y)</option>
            <option value="addition">Addition (x + y)</option>
          </select>
        </div>
        <div className="input-group"><label>Alice's x (0-15)</label><input type="number" min={0} max={15} value={x} onChange={e => setX(+e.target.value)} /></div>
        <div className="input-group"><label>Bob's y (0-15)</label><input type="number" min={0} max={15} value={y} onChange={e => setY(+e.target.value)} /></div>
      </div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Secure Evaluate"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <div className="result-row" style={{ marginBottom: "0.75rem" }}>
            {result.x_greater_than_y !== undefined && (
              <span className={`badge ${result.x_greater_than_y ? "badge-success" : "badge-info"}`}>
                {result.x} {result.x_greater_than_y ? ">" : "≤"} {result.y}
              </span>
            )}
            {result.equal !== undefined && (
              <span className={`badge ${result.equal ? "badge-success" : "badge-info"}`}>
                {result.x} {result.equal ? "==" : "!="} {result.y}
              </span>
            )}
            {result.sum !== undefined && (
              <span className="badge badge-success">{result.x} + {result.y} = {result.sum} (mod 16)</span>
            )}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
            <Field label="Alice's x" value={result.x} mono={false} accent="var(--text-primary)" />
            <Field label="Bob's y" value={result.y} mono={false} accent="var(--text-primary)" />
          </div>
          {result.sum !== undefined && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
              <Field label="Sum (mod 16)" value={result.sum} mono={false} accent="var(--accent-green)" />
              <Field label="Carry bit" value={result.carry} mono={false} accent="var(--accent-amber)" />
            </div>
          )}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem", marginTop: "0.25rem" }}>
            <Field label="OT calls" value={result.ot_calls} mono={false} accent="var(--text-secondary)" />
            <Field label="Elapsed" value={`${result.elapsed_s}s`} mono={false} accent="var(--text-muted)" />
          </div>
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}
