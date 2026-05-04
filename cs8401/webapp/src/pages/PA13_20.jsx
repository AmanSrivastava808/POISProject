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

// ── PA#13: Miller-Rabin ──────────────────────────────────────────────────────
export function PA13() {
  const [n, setN] = useState(104729);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); setResult(await apiFetch("/pa13/miller_rabin_rounds", { n, k: 10 })); setLoading(false); };
  const runCarmichael = async () => { setLoading(true); setResult(await apiFetch("/pa13/carmichael_demo")); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#13</span> Miller-Rabin Primality</h2><p>Probabilistic primality test with witness rounds</p></div>
    <div className="card"><h3>🔢 Primality Test</h3>
      <div className="input-group"><label>Number n</label><input type="number" value={n} onChange={e => setN(+e.target.value)} /></div>
      <div className="input-row">
        <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Test Primality"}</button>
        <button className="btn btn-danger" onClick={runCarmichael} disabled={loading}>Carmichael Demo</button>
      </div>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          {/* Miller-Rabin rounds result */}
          {result.final_is_prime !== undefined && (
            <>
              <div className="result-row" style={{ marginBottom: "0.75rem" }}>
                <span className={`badge ${result.final_is_prime ? "badge-success" : "badge-error"}`}>
                  {result.n ?? n} is {result.final_is_prime ? "" : "NOT "}prime
                </span>
              </div>
              {result.rounds && (
                <div style={{ marginBottom: "0.75rem" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginBottom: 4 }}>Witness rounds:</div>
                  <div className="result-row">
                    {result.rounds.map((r, i) => (
                      <span key={i} className={`badge ${r.composite_detected ? "badge-error" : "badge-success"}`} style={{fontSize:"0.7rem"}}>
                        R{r.round}: {r.composite_detected ? "COMPOSITE" : "PASS"}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
          {/* Carmichael demo result */}
          {result.carmichael_numbers && (
            <>
              <div style={{ fontSize: "0.78rem", color: "var(--text-secondary)", marginBottom: "0.5rem" }}>{result.note}</div>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                {result.carmichael_numbers.map(c => (
                  <div key={c.n} style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "0.82rem", minWidth: 60 }}>{c.n}</span>
                    <span className={`badge ${c.is_prime ? "badge-error" : "badge-success"}`}>
                      Miller-Rabin: {c.is_prime ? "PRIME (false!)" : "NOT PRIME ✓"}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#14: CRT ───────────────────────────────────────────────────────────────
export function PA14() {
  const [residues, setResidues] = useState("2,3,2");
  const [moduli, setModuli] = useState("3,5,7");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => {
    setLoading(true);
    const r = residues.split(",").map(Number);
    const m = moduli.split(",").map(Number);
    setResult(await apiFetch("/pa14/crt", { residues: r, moduli: m }));
    setLoading(false);
  };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#14</span> CRT &amp; Håstad Attack</h2><p>Chinese Remainder Theorem solver</p></div>
    <div className="card"><h3>⚡ CRT Solver</h3>
      <div className="input-group"><label>Residues (comma-separated)</label><input value={residues} onChange={e => setResidues(e.target.value)} /></div>
      <div className="input-group"><label>Moduli (comma-separated)</label><input value={moduli} onChange={e => setModuli(e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Solve CRT"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Solution x" value={result.x} mono={false} accent="var(--accent-green)" />
          <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: 4, marginTop: "0.5rem" }}>Verification checks:</div>
          {result.checks?.map((chk, i) => (
            <div key={i} style={{
              fontFamily: "'JetBrains Mono', monospace", fontSize: "0.75rem",
              color: "var(--accent-cyan)", padding: "0.25rem 0.5rem",
              background: "var(--bg-input)", borderRadius: 4, marginBottom: 3,
              border: "1px solid var(--border)"
            }}>{chk}</div>
          ))}
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#15: Signatures ────────────────────────────────────────────────────────
export function PA15() {
  const [msg, setMsg] = useState("48656c6c6f");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const sign = async () => { setLoading(true); setResult(await apiFetch("/pa15/sign", { message_hex: msg })); setLoading(false); };
  const verify = async () => { setLoading(true); setResult(await apiFetch("/pa15/verify", { message_hex: msg })); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#15</span> Digital Signatures</h2><p>RSA signature: σ = H(m)^d mod N</p></div>
    <div className="card"><h3>✍️ Sign &amp; Verify</h3>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <div className="input-row">
        <button className="btn btn-primary" onClick={sign} disabled={loading}>Sign</button>
        <button className="btn btn-success" onClick={verify} disabled={loading}>Sign + Verify + Tamper</button>
      </div>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          {/* Sign result */}
          {result.signature !== undefined && (
            <>
              <Field label="Message (hex)" value={result.message_hex} />
              <Field label="Hash H(m) as integer" value={result.hash_int} mono={false} accent="var(--text-secondary)" />
              <Field label="Signature σ = H(m)^d mod N (prefix)" value={result.signature} />
              <Field label="σ^e mod N (should = H(m))" value={result.sigma_e_mod_n} accent="var(--accent-green)" />
            </>
          )}
          {/* Verify result */}
          {result.valid !== undefined && (
            <div className="result-row">
              <span className={`badge ${result.valid ? "badge-success" : "badge-error"}`}>
                Verify: {result.valid ? "✓ Valid" : "✗ Invalid"}
              </span>
              <span className={`badge ${result.tampered_valid ? "badge-error" : "badge-success"}`}>
                Tampered: {result.tampered_valid ? "⚠ FORGED!" : "✓ Rejected"}
              </span>
            </div>
          )}
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#16: ElGamal ───────────────────────────────────────────────────────────
export function PA16() {
  const [msg, setMsg] = useState(42);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const enc = async () => { setLoading(true); setResult(await apiFetch("/pa16/encrypt", { message: msg })); setLoading(false); };
  const mal = async () => { setLoading(true); setResult(await apiFetch("/pa16/malleability", { message: msg })); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#16</span> ElGamal Encryption</h2><p>IND-CPA secure but malleable (NOT CCA)</p></div>
    <div className="card"><h3>🔐 ElGamal Demo</h3>
      <div className="input-group"><label>Message (integer)</label><input type="number" value={msg} onChange={e => setMsg(+e.target.value)} /></div>
      <div className="input-row">
        <button className="btn btn-primary" onClick={enc} disabled={loading}>Encrypt/Decrypt</button>
        <button className="btn btn-danger" onClick={mal} disabled={loading}>Malleability Attack</button>
      </div>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Plaintext m" value={result.message} mono={false} accent="var(--text-primary)" />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
            <Field label="Ciphertext c₁ (prefix)" value={result.c1} />
            <Field label="Ciphertext c₂ (prefix)" value={result.c2} />
          </div>
          <Field label="Decrypted m'" value={result.decrypted} mono={false} accent="var(--accent-green)" />
          {/* Malleability specific */}
          {result.malleability_works !== undefined && (
            <>
              <Field label="Malleable c₂ → decrypts to" value={result.malleable_decrypted} mono={false} accent="var(--accent-red)" />
              <Field label="Expected 2·m" value={result.expected_2m} mono={false} accent="var(--text-secondary)" />
              <div className="result-row" style={{marginTop:"0.25rem"}}>
                <span className={`badge ${result.malleability_works ? "badge-error" : "badge-success"}`}>
                  Malleability: {result.malleability_works ? "⚠ WORKS — CCA broken!" : "✗ Failed"}
                </span>
              </div>
            </>
          )}
          {result.malleability_works === undefined && (
            <div className="result-row">
              <span className={`badge ${result.decrypted === result.message ? "badge-success" : "badge-error"}`}>
                Roundtrip: {result.decrypted === result.message ? "✓ Correct" : "✗ Failed"}
              </span>
            </div>
          )}
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#17: CCA-PKC ───────────────────────────────────────────────────────────
export function PA17() {
  const [msg, setMsg] = useState(42);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); setResult(await apiFetch("/pa17/encrypt", { message: msg })); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#17</span> CCA-Secure PKC</h2><p>Encrypt-then-Sign blocks malleability attacks</p></div>
    <div className="card"><h3>🏰 CCA-PKC Encrypt + Tamper Test</h3>
      <div className="input-group"><label>Message (integer)</label><input type="number" value={msg} onChange={e => setMsg(+e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Encrypt + Tamper"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <div className="result-row" style={{ marginBottom: "0.75rem" }}>
            <span className={`badge ${result.correct ? "badge-success" : "badge-error"}`}>
              Decrypt: {result.correct ? "✓ Correct" : "✗ Failed"}
            </span>
            <span className={`badge ${result.tampered_rejected ? "badge-success" : "badge-error"}`}>
              Tampered: {result.tampered_rejected ? "✓ Rejected" : "⚠ ACCEPTED!"}
            </span>
          </div>
          <Field label="Plaintext m" value={result.message} mono={false} accent="var(--text-primary)" />
          <Field label="Decrypted m'" value={result.decrypted} mono={false} accent="var(--accent-green)" />
          <Field label="Tampered decryption result" value={result.tampered_result === null ? "null (rejected)" : result.tampered_result} mono={false} accent="var(--accent-red)" />
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
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
