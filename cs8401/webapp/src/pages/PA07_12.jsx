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

// ── PA#7: Merkle-Damgard ─────────────────────────────────────────────────────
export function PA07() {
  const [msg, setMsg] = useState("48656c6c6f20576f726c64");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); setResult(await apiFetch("/pa07/hash", { message_hex: msg })); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#7</span> Merkle-Damgård Hash</h2><p>Iterated hash from compression function</p></div>
    <div className="card"><h3>🔗 Hash Message</h3>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Hash"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Input Message (hex)" value={result.message_hex} />
          <Field label="Digest (hex)" value={result.digest_hex} accent="var(--accent-green)" />
          <Field label="Digest Size" value={`${result.digest_bytes} bytes`} mono={false} accent="var(--text-secondary)" />
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#8: DLP-CRHF ───────────────────────────────────────────────────────────
export function PA08() {
  const [msg, setMsg] = useState("48656c6c6f");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); setResult(await apiFetch("/pa08/hash", { message_hex: msg })); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#8</span> DLP-Based CRHF</h2><p>Collision-resistant hash from discrete log assumption</p></div>
    <div className="card"><h3>#️⃣ DLP Hash</h3>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Hash"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Input Message (hex)" value={result.message_hex} />
          <Field label="DLP Digest (hex)" value={result.digest_hex} accent="var(--accent-green)" />
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 4 }}>
            h(m) = g^m₁ · h^m₂ mod p — collision resistance follows from DLP hardness
          </div>
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#9: Birthday Attack (Live chart) ───────────────────────────────────────
export function PA09() {
  const [bits, setBits] = useState(12);
  const [result, setResult] = useState(null);
  const [curve, setCurve] = useState(null);
  const [loading, setLoading] = useState(false);
  const [curveLoading, setCurveLoading] = useState(false);

  const run = async () => { setLoading(true); setResult(await apiFetch("/pa09/birthday", { bit_size: bits })); setLoading(false); };
  const runCurve = async () => { setCurveLoading(true); setCurve(await apiFetch("/pa09/birthday_curve", { bit_size: bits, num_trials: 20 })); setCurveLoading(false); };

  const expected = Math.pow(2, bits / 2);
  const chartW = 560, chartH = 220, pad = { l: 50, r: 20, t: 10, b: 40 };
  const innerW = chartW - pad.l - pad.r, innerH = chartH - pad.t - pad.b;

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#9</span> Birthday Attack — Live Collision Search</h2>
      <p>Find hash collisions in O(2<sup>n/2</sup>) time. Expected ≈ {Math.round(expected)} evaluations for {bits}-bit hash.</p>
    </div>

    <div className="card">
      <h3>🎂 Attack Configuration</h3>
      <div className="input-group">
        <label>Hash output bit-length n</label>
        <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
          {[8, 10, 12, 14, 16].map(n => (
            <button key={n} onClick={() => { setBits(n); setResult(null); }}
              style={{ padding: '0.4rem 0.8rem', borderRadius: 6, border: '2px solid',
                borderColor: bits === n ? 'var(--accent-blue)' : 'var(--border)',
                background: bits === n ? 'rgba(59,130,246,0.2)' : 'var(--bg-input)',
                color: bits === n ? 'var(--accent-blue)' : 'var(--text-muted)',
                fontFamily: "'JetBrains Mono', monospace", fontSize: '0.85rem',
                fontWeight: 600, cursor: 'pointer', transition: 'all 0.15s' }}>{n}</button>
          ))}
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center', marginLeft: 8 }}>
            2<sup>{bits}</sup> = {Math.pow(2, bits).toLocaleString()} hash space
          </span>
        </div>
      </div>
      <div className="input-row" style={{ marginTop: '0.5rem' }}>
        <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "🚀 Run Attack"}</button>
        <button className="btn btn-success" onClick={runCurve} disabled={curveLoading}>{curveLoading ? <span className="spinner"/> : "📊 Empirical Curve (all n)"}</button>
      </div>
    </div>

    {result && result.collision_found && (
      <div className="card fade-in">
        <h3>💥 Collision Found!</h3>
        <div className="result-row" style={{ marginBottom: '0.5rem' }}>
          <span className="badge badge-success">Found in {result.attempts} evaluations</span>
          <span className="badge badge-info">Expected: ≈ {result.expected_attempts}</span>
          <span className="badge badge-warn">Ratio: {(result.attempts / result.expected_attempts).toFixed(2)}×</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <Field label="Message m₁" value={result.m1_hex} />
          <Field label="Message m₂" value={result.m2_hex} />
        </div>
        {result.h1 && (
          <div style={{ background: 'linear-gradient(135deg, rgba(239,68,68,0.1), rgba(245,158,11,0.08))',
            borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)', textAlign: 'center' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4 }}>Shared truncated hash</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '1.1rem', color: 'var(--accent-red)', fontWeight: 600 }}>
              H(m₁) = H(m₂) = {result.h1}
            </div>
          </div>
        )}
      </div>
    )}

    {curve?.curve_data && (
      <div className="card fade-in">
        <h3>📊 Empirical Birthday Curve ({curve.curve_data[0]?.trials} trials per n)</h3>
        {(() => {
          const data = curve.curve_data;
          const maxVal = Math.max(...data.map(d => Math.max(d.avg_attempts, d.expected_2n2)));
          const barW = innerW / data.length;
          return (
            <svg width={chartW} height={chartH} style={{ display: 'block', margin: '0 auto' }}>
              {[0, 0.25, 0.5, 0.75, 1].map(f => (
                <g key={f}>
                  <line x1={pad.l} y1={pad.t + innerH * (1-f)} x2={pad.l + innerW} y2={pad.t + innerH * (1-f)}
                    stroke="#2a3040" strokeWidth={1} strokeDasharray={f === 0 ? 'none' : '3,3'} />
                  <text x={pad.l - 6} y={pad.t + innerH * (1-f) + 4} textAnchor="end" fill="#64748b" fontSize={9} fontFamily="JetBrains Mono">{Math.round(maxVal * f)}</text>
                </g>
              ))}
              {data.map((d, i) => {
                const cx = pad.l + barW * i + barW / 2;
                const empH = (d.avg_attempts / maxVal) * innerH;
                const expH = (d.expected_2n2 / maxVal) * innerH;
                return (
                  <g key={d.bit_size}>
                    <rect x={cx - 16} y={pad.t + innerH - expH} width={14} height={expH} fill="none" stroke="#06b6d4" strokeWidth={1.5} strokeDasharray="4,2" rx={3} />
                    <rect x={cx + 2} y={pad.t + innerH - empH} width={14} height={empH} fill="rgba(59,130,246,0.6)" stroke="#3b82f6" strokeWidth={1} rx={3} />
                    <text x={cx} y={pad.t + innerH - Math.max(empH, expH) - 6} textAnchor="middle" fill="#e2e8f0" fontSize={8} fontWeight={600} fontFamily="JetBrains Mono">{d.ratio_vs_expected}×</text>
                    <text x={cx} y={chartH - 8} textAnchor="middle" fill="#94a3b8" fontSize={10} fontFamily="JetBrains Mono">n={d.bit_size}</text>
                  </g>
                );
              })}
              <rect x={chartW - 150} y={8} width={10} height={10} fill="rgba(59,130,246,0.6)" rx={2} />
              <text x={chartW - 136} y={17} fill="#94a3b8" fontSize={9}>Empirical avg</text>
              <rect x={chartW - 150} y={22} width={10} height={10} fill="none" stroke="#06b6d4" strokeDasharray="3,2" rx={2} />
              <text x={chartW - 136} y={31} fill="#94a3b8" fontSize={9}>Expected 2^(n/2)</text>
            </svg>
          );
        })()}
        <div style={{ overflowX: 'auto', marginTop: '0.75rem' }}>
          <table className="data-table">
            <thead><tr>{['n', '2^n', '2^(n/2)', 'Avg', 'Min', 'Max', 'Ratio'].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>{curve.curve_data.map(d => (
              <tr key={d.bit_size}>
                <td style={{color:'var(--accent-blue)', fontWeight:600}}>{d.bit_size}</td>
                <td>{Math.pow(2, d.bit_size)}</td><td style={{color:'var(--accent-cyan)'}}>{d.expected_2n2}</td>
                <td style={{color:'var(--accent-green)', fontWeight:600}}>{d.avg_attempts}</td>
                <td>{d.min_attempts}</td><td>{d.max_attempts}</td>
                <td><span className={`badge ${Math.abs(d.ratio_vs_expected - 1) < 0.5 ? 'badge-success' : 'badge-warn'}`} style={{fontSize:'0.7rem'}}>{d.ratio_vs_expected}×</span></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </div>
    )}

    {curve?.probability_curve && (() => {
      const pc = curve.probability_curve;
      const cW = 560, cH = 200, cP = { l: 45, r: 20, t: 15, b: 35 };
      const iW = cW - cP.l - cP.r, iH = cH - cP.t - cP.b;
      const maxK = pc[pc.length - 1]?.k || 1;
      const xS = k => cP.l + (k / maxK) * iW, yS = p => cP.t + (1 - p) * iH;
      const expK = curve.expected_collision_point;
      const pathD = pc.map((pt, i) => `${i === 0 ? 'M' : 'L'} ${xS(pt.k).toFixed(1)} ${yS(pt.p).toFixed(1)}`).join(' ');
      return (
        <div className="card fade-in">
          <h3>📈 Collision Probability vs Hashes Computed (n={curve.selected_bit_size})</h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
            P(collision) = 1 − e<sup>−k²/2N</sup>. Vertical marker at 2<sup>{curve.selected_bit_size}/2</sup> ≈ {Math.round(expK)}.
          </p>
          <svg width={cW} height={cH} style={{ display: 'block', margin: '0 auto' }}>
            {[0, 0.25, 0.5, 0.75, 1].map(f => (
              <g key={f}><line x1={cP.l} y1={yS(f)} x2={cP.l+iW} y2={yS(f)} stroke="#2a3040" strokeDasharray="3,3" />
              <text x={cP.l-5} y={yS(f)+4} textAnchor="end" fill="#64748b" fontSize={8} fontFamily="JetBrains Mono">{(f*100).toFixed(0)}%</text></g>
            ))}
            <path d={pathD} fill="none" stroke="url(#pg)" strokeWidth={2} />
            <defs><linearGradient id="pg" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stopColor="#3b82f6"/><stop offset="100%" stopColor="#ef4444"/></linearGradient></defs>
            <line x1={xS(expK)} y1={cP.t} x2={xS(expK)} y2={cP.t+iH} stroke="#f59e0b" strokeWidth={1.5} strokeDasharray="5,3" />
            <text x={xS(expK)} y={cP.t-2} textAnchor="middle" fill="#f59e0b" fontSize={8} fontFamily="JetBrains Mono" fontWeight={600}>2^({curve.selected_bit_size}/2)={Math.round(expK)}</text>
            <text x={cP.l+iW/2} y={cH-5} textAnchor="middle" fill="#64748b" fontSize={9}>Hashes computed (k)</text>
          </svg>
        </div>
      );
    })()}
  </>);
}

// ── PA#10: HMAC ──────────────────────────────────────────────────────────────
export function PA10() {
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [msg, setMsg] = useState("48656c6c6f");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); setResult(await apiFetch("/pa10/hmac", { key_hex: key, message_hex: msg })); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#10</span> HMAC</h2><p>H((k⊕opad) ‖ H((k⊕ipad) ‖ m)) — MAC from CRHF</p></div>
    <div className="card"><h3>🏷️ Compute HMAC</h3>
      <div className="input-group"><label>Key (hex)</label><input value={key} onChange={e => setKey(e.target.value)} /></div>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "HMAC"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="HMAC Tag (hex)" value={result.tag_hex} accent="var(--accent-green)" />
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 4 }}>
            HMAC = H((k ⊕ opad) ‖ H((k ⊕ ipad) ‖ m))
          </div>
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#11: Diffie-Hellman (Two-panel + MITM) ────────────────────────────────
export function PA11() {
  const [result, setResult] = useState(null);
  const [mitmResult, setMitmResult] = useState(null);
  const [enableEve, setEnableEve] = useState(false);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);

  const runExchange = async () => {
    setLoading(true); setMitmResult(null); setStep(1);
    const r = await apiFetch("/pa11/dh_interactive");
    setResult(r);
    setTimeout(() => setStep(2), 600);
    setTimeout(() => setStep(3), 1200);
    setLoading(false);
  };

  const runMitm = async () => {
    setLoading(true); setResult(null);
    const r = await apiFetch("/pa11/mitm", { enable_eve: enableEve });
    setMitmResult(r); setStep(3); setLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#11</span> Diffie-Hellman Key Exchange</h2>
      <p>Two parties establish a shared secret over an insecure channel. Enable Eve for MITM.</p>
    </div>

    <div className="card">
      <h3>⚙️ Exchange Controls</h3>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <button className="btn btn-primary" onClick={runExchange} disabled={loading}>
          {loading ? <span className="spinner"/> : "🤝 Run DH Exchange"}
        </button>
        <button className="btn btn-danger" onClick={runMitm} disabled={loading}>
          {loading ? <span className="spinner"/> : enableEve ? "🕵️ Run with Eve (MITM)" : "🤝 Run (no Eve)"}
        </button>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', cursor: 'pointer',
          color: enableEve ? 'var(--accent-red)' : 'var(--text-secondary)' }}>
          <input type="checkbox" checked={enableEve} onChange={e => setEnableEve(e.target.checked)} />
          🕵️ Enable Eve (MITM)
        </label>
      </div>
    </div>

    {result && (
      <div className="fade-in">
        <div className="card" style={{ padding: '0.75rem' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            Group: p = {result.p?.slice(0, 16)}..., g = {result.g?.slice(0, 10)}...
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: '0.75rem', alignItems: 'stretch' }}>
          <div className="card" style={{ borderColor: 'rgba(59,130,246,0.4)' }}>
            <h3 style={{ color: 'var(--accent-blue)' }}>👩 Alice</h3>
            <Field label="Private key a" value={result.alice?.private} />
            {step >= 1 && <Field label="Public A = gᵃ mod p" value={result.alice?.public} accent="var(--accent-blue)" />}
            {step >= 3 && <Field label="Shared K = Bᵃ mod p" value={result.alice_shared} accent="var(--accent-green)" />}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: '1.5rem', padding: '0 0.5rem' }}>
            {step >= 2 && (<>
              <div className="fade-in" style={{ textAlign: 'center', fontSize: '0.7rem', color: 'var(--accent-blue)' }}>A →<div style={{ fontSize: '1.2rem' }}>→</div></div>
              <div className="fade-in" style={{ textAlign: 'center', fontSize: '0.7rem', color: 'var(--accent-purple)' }}>← B<div style={{ fontSize: '1.2rem' }}>←</div></div>
            </>)}
          </div>
          <div className="card" style={{ borderColor: 'rgba(139,92,246,0.4)' }}>
            <h3 style={{ color: 'var(--accent-purple)' }}>👨 Bob</h3>
            <Field label="Private key b" value={result.bob?.private} />
            {step >= 1 && <Field label="Public B = gᵇ mod p" value={result.bob?.public} accent="var(--accent-purple)" />}
            {step >= 3 && <Field label="Shared K = Aᵇ mod p" value={result.bob_shared} accent="var(--accent-green)" />}
          </div>
        </div>
        {step >= 3 && (
          <div className="card fade-in" style={{
            background: result.keys_match ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
            borderColor: result.keys_match ? 'var(--accent-green)' : 'var(--accent-red)', textAlign: 'center' }}>
            <span className={`badge ${result.keys_match ? 'badge-success' : 'badge-error'}`} style={{ fontSize: '0.9rem' }}>
              {result.keys_match ? '✅ Keys Match! K_A = K_B' : '❌ Keys Do NOT Match'}
            </span>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--accent-green)', marginTop: '0.5rem', wordBreak: 'break-all' }}>
              Shared secret: {result.shared_key}
            </div>
          </div>
        )}
      </div>
    )}

    {mitmResult && (
      <div className="fade-in">
        <div style={{ display: 'grid', gridTemplateColumns: mitmResult.mitm_active ? '1fr 1fr 1fr' : '1fr 1fr', gap: '0.75rem' }}>
          <div className="card" style={{ borderColor: 'rgba(59,130,246,0.4)' }}>
            <h3 style={{ color: 'var(--accent-blue)' }}>👩 Alice</h3>
            <Field label="Public A" value={mitmResult.alice?.public} accent="var(--accent-blue)" />
            <Field label="Thinks shared K =" value={mitmResult.alice?.thinks_shared} accent={mitmResult.mitm_active ? 'var(--accent-amber)' : 'var(--accent-green)'} />
          </div>
          {mitmResult.mitm_active && mitmResult.eve && (
            <div className="card fade-in" style={{ borderColor: 'rgba(239,68,68,0.5)', background: 'rgba(239,68,68,0.05)' }}>
              <h3 style={{ color: 'var(--accent-red)' }}>🕵️ Eve (MITM)</h3>
              <Field label="Public E (sent to both)" value={mitmResult.eve.public} accent="var(--accent-red)" />
              <Field label="Key with Alice" value={mitmResult.eve.key_with_alice} accent="var(--accent-amber)" />
              <Field label="Key with Bob" value={mitmResult.eve.key_with_bob} accent="var(--accent-amber)" />
              <span className="badge badge-error" style={{ fontSize: '0.7rem' }}>Eve reads ALL traffic!</span>
            </div>
          )}
          <div className="card" style={{ borderColor: 'rgba(139,92,246,0.4)' }}>
            <h3 style={{ color: 'var(--accent-purple)' }}>👨 Bob</h3>
            <Field label="Public B" value={mitmResult.bob?.public} accent="var(--accent-purple)" />
            <Field label="Thinks shared K =" value={mitmResult.bob?.thinks_shared} accent={mitmResult.mitm_active ? 'var(--accent-amber)' : 'var(--accent-green)'} />
          </div>
        </div>
        <div className="card" style={{
          background: mitmResult.mitm_active ? 'rgba(239,68,68,0.08)' : 'rgba(16,185,129,0.08)',
          borderColor: mitmResult.mitm_active ? 'var(--accent-red)' : 'var(--accent-green)', textAlign: 'center' }}>
          {mitmResult.mitm_active ? (<>
            <span className="badge badge-error" style={{ fontSize: '0.85rem' }}>⚠️ MITM Successful — Alice & Bob have DIFFERENT keys!</span>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>Eve can decrypt, read, re-encrypt, and forward all messages.</p>
          </>) : (
            <span className="badge badge-success" style={{ fontSize: '0.85rem' }}>✅ No MITM — Keys match: {mitmResult.keys_match ? 'YES' : 'NO'}</span>
          )}
        </div>
      </div>
    )}
  </>);
}

// ── PA#12: RSA ───────────────────────────────────────────────────────────────
export function PA12() {
  const [msg, setMsg] = useState(42);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); setResult(await apiFetch("/pa12/encrypt", { message: msg })); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#12</span> RSA Encryption</h2><p>Textbook RSA with PKCS#1 v1.5 padding</p></div>
    <div className="card"><h3>🗝️ RSA Encrypt/Decrypt</h3>
      <div className="input-group"><label>Message (integer)</label><input type="number" value={msg} onChange={e => setMsg(+e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Encrypt → Decrypt"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <div className="result-row" style={{ marginBottom: "0.75rem" }}>
            <span className={`badge ${result.correct ? "badge-success" : "badge-error"}`}>
              Roundtrip: {result.correct ? "✓ Correct" : "✗ Failed"}
            </span>
          </div>
          <Field label="Plaintext m" value={result.message} mono={false} accent="var(--text-primary)" />
          <Field label="Ciphertext c = m^e mod N (prefix)" value={result.ciphertext_prefix} />
          <Field label="Decrypted m' = c^d mod N" value={result.decrypted} mono={false} accent="var(--accent-green)" />
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}
