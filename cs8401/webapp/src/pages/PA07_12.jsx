import { useState } from "react";
import { apiFetch } from "../api";

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
      {result && <div className="output-box fade-in"><pre>{JSON.stringify(result, null, 2)}</pre></div>}
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
      {result && <div className="output-box fade-in"><pre>{JSON.stringify(result, null, 2)}</pre></div>}
    </div>
  </>);
}

// ── PA#9: Birthday Attack ────────────────────────────────────────────────────
export function PA09() {
  const [bits, setBits] = useState(16);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); setResult(await apiFetch("/pa09/birthday", { bit_size: bits })); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#9</span> Birthday Attack</h2><p>Find hash collisions in O(2^(n/2)) time</p></div>
    <div className="card"><h3>🎂 Birthday Collision Search</h3>
      <div className="input-group"><label>Hash output bits</label>
        <select value={bits} onChange={e => setBits(+e.target.value)}>
          <option value={8}>8</option><option value={10}>10</option><option value={12}>12</option><option value={14}>14</option><option value={16}>16</option>
        </select>
      </div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Find Collision"}</button>
      {result && <div className="output-box fade-in"><pre>{JSON.stringify(result, null, 2)}</pre></div>}
    </div>
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
      {result && <div className="output-box fade-in"><pre>{JSON.stringify(result, null, 2)}</pre></div>}
    </div>
  </>);
}

// ── PA#11: Diffie-Hellman ────────────────────────────────────────────────────
export function PA11() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); setResult(await apiFetch("/pa11/dh_exchange")); setLoading(false); };
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#11</span> Diffie-Hellman Key Exchange</h2><p>Alice and Bob establish shared secret over insecure channel</p></div>
    <div className="card"><h3>🤝 DH Exchange</h3>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Run Key Exchange"}</button>
      {result && <div className="fade-in">
        <div className="result-row" style={{marginTop:'0.75rem'}}>
          <span className={`badge ${result.shared_key_matches ? 'badge-success' : 'badge-error'}`}>
            Keys match: {result.shared_key_matches ? '✓' : '✗'}
          </span>
        </div>
        <div className="output-box"><pre>{JSON.stringify(result, null, 2)}</pre></div>
      </div>}
    </div>
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
      {result && <div className="fade-in">
        <div className="result-row"><span className={`badge ${result.correct ? 'badge-success' : 'badge-error'}`}>Roundtrip: {result.correct ? '✓' : '✗'}</span></div>
        <div className="output-box"><pre>{JSON.stringify(result, null, 2)}</pre></div>
      </div>}
    </div>
  </>);
}
