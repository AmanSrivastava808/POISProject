import { useState, useEffect, useCallback } from "react";
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

function StatusBadge({ ok, trueLabel, falseLabel }) {
  return (
    <span className={`badge ${ok ? "badge-success" : "badge-error"}`}>
      {ok ? trueLabel : falseLabel}
    </span>
  );
}

// ── PA#1: OWF & PRG ──────────────────────────────────────────────────────────
export function PA01() {
  const [seed, setSeed] = useState("deadbeefcafebabe");
  const [owfInput, setOwfInput] = useState("deadbeefcafebabe");
  const [outputBits, setOutputBits] = useState(128);
  const [prg, setPrg] = useState(null);
  const [owf, setOwf] = useState(null);
  const [nist, setNist] = useState(null);
  const [loading, setLoading] = useState(false);
  const [owfLoading, setOwfLoading] = useState(false);
  const [nistLoading, setNistLoading] = useState(false);

  const fetchPrg = useCallback(async () => {
    if (!seed) return;
    setLoading(true);
    const r = await apiFetch("/pa01/prg", { seed_hex: seed, output_bits: outputBits });
    setPrg(r);
    setNist(null);
    setLoading(false);
  }, [seed, outputBits]);

  useEffect(() => {
    const t = setTimeout(fetchPrg, 300);
    return () => clearTimeout(t);
  }, [fetchPrg]);

  const runOwf = async () => {
    if (!owfInput) return;
    setOwfLoading(true);
    const r = await apiFetch("/pa01/owf", { input_hex: owfInput });
    setOwf(r);
    setOwfLoading(false);
  };

  const runNist = async () => {
    setNistLoading(true);
    const r = await apiFetch("/pa01/randomness_test", { seed_hex: seed, output_bits: Math.max(outputBits, 128) });
    setNist(r);
    setNistLoading(false);
  };

  const onesRatio = prg?.ones_ratio ?? 0.5;
  const onesPercent = Math.round(onesRatio * 100);

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#1</span> OWF &amp; PRG — Live Output Viewer</h2>
      <p>DLP-based OWF with Goldreich-Levin hard-core bit PRG. Slide to expand.</p>
    </div>

    {/* OWF Section */}
    <div className="card">
      <h3>🔐 One-Way Function f(x) = g^x mod p</h3>
      <div className="input-group">
        <label>Input x (hex)</label>
        <input value={owfInput} onChange={e => setOwfInput(e.target.value)} placeholder="e.g. deadbeefcafebabe" />
      </div>
      <button className="btn btn-primary" onClick={runOwf} disabled={owfLoading}>
        {owfLoading ? <span className="spinner"/> : "Evaluate OWF"}
      </button>
      {owf && !owf.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Input x (integer)" value={owf.input} />
          <Field label="Output f(x) = g^x mod p" value={owf.output} accent="var(--accent-green)" />
          <Field label="One-way property" value={owf.note} mono={false} accent="var(--text-secondary)" />
          <div className="result-row">
            <StatusBadge ok={owf.one_way} trueLabel="✓ One-Way" falseLabel="✗ Not One-Way" />
          </div>
        </div>
      )}
      {owf?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{owf.error}</pre></div>}
    </div>

    {/* PRG Section */}
    <div className="card">
      <h3>🔑 Seed Input</h3>
      <div className="input-group">
        <label>Seed s (hex)</label>
        <input value={seed} onChange={e => setSeed(e.target.value)} placeholder="e.g. deadbeefcafebabe" />
      </div>
    </div>

    <div className="card">
      <h3>📏 Output Length ℓ = {outputBits} bits ({outputBits / 8} bytes)</h3>
      <input type="range" min={8} max={512} step={8} value={outputBits}
        onChange={e => setOutputBits(+e.target.value)}
        style={{ width: '100%', accentColor: 'var(--accent-blue)', marginBottom: '0.75rem' }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
        <span>8 bits</span><span>512 bits</span>
      </div>
    </div>

    <div className="card">
      <h3>📡 Live PRG Output G(s) {loading && <span className="spinner" style={{marginLeft:6}}/>}</h3>
      {prg?.output_hex && (
        <div className="fade-in">
          <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: 4 }}>Output hex (seed={prg.seed})</div>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem',
            background: 'var(--bg-input)', borderRadius: 8, padding: '0.75rem',
            border: '1px solid var(--border)', wordBreak: 'break-all', lineHeight: 1.8,
            color: 'var(--accent-cyan)', letterSpacing: '0.05em'
          }}>
            {prg.output_hex.match(/.{1,2}/g)?.map((byte, i) => (
              <span key={i} style={{
                padding: '2px 3px', margin: 1, borderRadius: 3,
                background: i % 2 === 0 ? 'rgba(6,182,212,0.08)' : 'transparent'
              }}>{byte}</span>
            ))}
          </div>
          <div style={{ marginTop: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: 4 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                Bit ratio: {prg.ones_count} ones / {prg.zeros_count} zeros ({onesPercent}% ones)
              </span>
              <span className={`badge ${Math.abs(onesPercent - 50) < 10 ? 'badge-success' : 'badge-warn'}`} style={{fontSize:'0.68rem'}}>
                {Math.abs(onesPercent - 50) < 10 ? '≈ 50%' : 'Skewed'}
              </span>
            </div>
            <div style={{ width: '100%', height: 10, borderRadius: 5, background: 'var(--bg-input)', overflow: 'hidden', border: '1px solid var(--border)' }}>
              <div style={{ width: `${onesPercent}%`, height: '100%', borderRadius: 5,
                background: `linear-gradient(90deg, var(--accent-blue), var(--accent-cyan))`,
                transition: 'width 0.3s ease' }} />
            </div>
          </div>
        </div>
      )}
    </div>

    <div className="card">
      <h3>🧪 NIST Randomness Tests</h3>
      <p style={{fontSize:'0.78rem', color:'var(--text-secondary)', marginBottom:'0.75rem'}}>
        Runs frequency (monobit), runs, and serial tests on the PRG output.
      </p>
      <button className="btn btn-primary" onClick={runNist} disabled={nistLoading}>
        {nistLoading ? <span className="spinner"/> : "Run Randomness Tests"}
      </button>
      {nist && !nist.error && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          {Object.entries(nist).filter(([k]) => k !== 'label' && typeof nist[k] === 'number').map(([testName, pVal]) => {
            const passed = pVal > 0.01;
            return (
              <div key={testName} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.4rem 0', borderBottom: '1px solid var(--border)' }}>
                <span className={`badge ${passed ? 'badge-success' : 'badge-error'}`} style={{minWidth:60, justifyContent:'center'}}>
                  {passed ? 'PASS' : 'FAIL'}
                </span>
                <span style={{ fontSize: '0.8rem', fontWeight: 500, textTransform: 'capitalize' }}>{testName}</span>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>p = {pVal.toFixed(4)}</span>
              </div>
            );
          })}
        </div>
      )}
      {nist?.error && <div className="output-box fade-in"><pre style={{color:'var(--accent-red)'}}>{nist.error}</pre></div>}
    </div>
  </>);
}

// ── PA#2: GGM Tree Visualiser ────────────────────────────────────────────────
export function PA02() {
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [queryBits, setQueryBits] = useState("0110");
  const [tree, setTree] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchTree = useCallback(async () => {
    if (!key || !queryBits) return;
    setLoading(true);
    const r = await apiFetch("/pa02/ggm_tree", { key_hex: key, query_bits: queryBits });
    setTree(r);
    setLoading(false);
  }, [key, queryBits]);

  useEffect(() => {
    const t = setTimeout(fetchTree, 400);
    return () => clearTimeout(t);
  }, [fetchTree]);

  const toggleBit = (i) => {
    const bits = queryBits.split('');
    bits[i] = bits[i] === '0' ? '1' : '0';
    setQueryBits(bits.join(''));
  };

  const depth = queryBits.length;
  const nodeR = 28;
  const levelH = 70;
  const svgW = Math.max(600, (2 ** depth) * 70);
  const svgH = (depth + 1) * levelH + 60;

  const getNodePos = (id, level) => {
    if (level === 0) return { x: svgW / 2, y: 40 };
    const idx = parseInt(id, 2);
    const count = 2 ** level;
    const spacing = svgW / (count + 1);
    return { x: spacing * (idx + 1), y: 40 + level * levelH };
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#2</span> GGM Tree Visualiser</h2>
      <p>Interactive PRF tree — click bits to re-route the path instantly</p>
    </div>

    <div className="card">
      <h3>🔑 Key &amp; Query</h3>
      <div className="input-group">
        <label>Key k (hex, 16 bytes)</label>
        <input value={key} onChange={e => setKey(e.target.value)} />
      </div>
      <div className="input-group">
        <label>Query x (bit string, n ≤ 8) — click bits to toggle</label>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 4 }}>
          {queryBits.split('').map((b, i) => (
            <button key={i} onClick={() => toggleBit(i)}
              style={{
                width: 36, height: 36, borderRadius: 6, border: '2px solid',
                borderColor: b === '1' ? 'var(--accent-blue)' : 'var(--border)',
                background: b === '1' ? 'rgba(59,130,246,0.2)' : 'var(--bg-input)',
                color: b === '1' ? 'var(--accent-blue)' : 'var(--text-muted)',
                fontFamily: "'JetBrains Mono', monospace", fontSize: '1rem',
                fontWeight: 700, cursor: 'pointer', transition: 'all 0.15s'
              }}>
              {b}
            </button>
          ))}
          <button className="btn btn-ghost" style={{fontSize:'0.7rem'}} onClick={() => setQueryBits(queryBits + '0')}>+ bit</button>
          {queryBits.length > 1 && <button className="btn btn-ghost" style={{fontSize:'0.7rem'}} onClick={() => setQueryBits(queryBits.slice(0,-1))}>− bit</button>}
        </div>
      </div>
    </div>

    {tree?.leaf_hex && (
      <div className="card" style={{ background: 'linear-gradient(135deg, rgba(59,130,246,0.12), rgba(6,182,212,0.08))', borderColor: 'var(--accent-blue)' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 4 }}>{tree.leaf_label}</div>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: '1.1rem',
            color: 'var(--accent-cyan)', fontWeight: 600, letterSpacing: '0.05em',
            wordBreak: 'break-all'
          }}>
            {tree.leaf_hex}
          </div>
        </div>
      </div>
    )}

    <div className="card" style={{ overflow: 'auto' }}>
      <h3>🌳 GGM Binary Tree (depth {depth}) {loading && <span className="spinner" style={{marginLeft:6}}/>}</h3>
      {tree?.tree && (
        <svg width={svgW} height={svgH} style={{ display: 'block', margin: '0 auto' }}>
          {tree.tree.filter(n => n.level > 0).map(node => {
            const parentId = node.id.slice(0, -1);
            const parentLvl = node.level - 1;
            const p = getNodePos(parentId || '0', parentLvl);
            const c = getNodePos(node.id, node.level);
            return (
              <line key={`e_${node.id}`} x1={p.x} y1={p.y + nodeR} x2={c.x} y2={c.y - nodeR}
                stroke={node.on_path ? '#3b82f6' : '#2a3040'} strokeWidth={node.on_path ? 2.5 : 1}
                opacity={node.on_path ? 1 : 0.4} />
            );
          })}
          {tree.tree.filter(n => n.level > 0).map(node => {
            const parentId = node.id.slice(0, -1);
            const parentLvl = node.level - 1;
            const p = getNodePos(parentId || '0', parentLvl);
            const c = getNodePos(node.id, node.level);
            const bit = node.id[node.id.length - 1];
            return (
              <text key={`el_${node.id}`} x={(p.x + c.x) / 2 + (bit === '0' ? -10 : 10)}
                y={(p.y + c.y) / 2 + 4}
                fill={node.on_path ? '#60a5fa' : '#475569'} fontSize={11} fontWeight={600}
                textAnchor="middle" fontFamily="JetBrains Mono, monospace">
                {bit === '0' ? 'G₀' : 'G₁'}
              </text>
            );
          })}
          {tree.tree.map(node => {
            const pos = getNodePos(node.id || '0', node.level);
            return (
              <g key={`n_${node.id || 'root'}`}>
                <circle cx={pos.x} cy={pos.y} r={nodeR}
                  fill={node.on_path ? (node.is_leaf ? 'rgba(6,182,212,0.25)' : 'rgba(59,130,246,0.2)') : 'rgba(42,48,64,0.5)'}
                  stroke={node.on_path ? (node.is_leaf ? '#06b6d4' : '#3b82f6') : '#2a3040'}
                  strokeWidth={node.on_path ? 2 : 1} />
                <text x={pos.x} y={pos.y - 4} textAnchor="middle"
                  fill={node.on_path ? '#e2e8f0' : '#64748b'} fontSize={9}
                  fontFamily="JetBrains Mono, monospace" fontWeight={node.on_path ? 600 : 400}>
                  {node.label}
                </text>
                <text x={pos.x} y={pos.y + 10} textAnchor="middle"
                  fill={node.on_path ? '#06b6d4' : '#475569'} fontSize={7.5}
                  fontFamily="JetBrains Mono, monospace">
                  {node.hex}
                </text>
              </g>
            );
          })}
        </svg>
      )}
    </div>
  </>);
}

// ── PA#3: CPA Encryption ─────────────────────────────────────────────────────
export function PA03() {
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [msg, setMsg] = useState("48656c6c6f");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    const r = await apiFetch("/pa03/encrypt", { key_hex: key, message_hex: msg });
    setResult(r);
    setLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#3</span> CPA-Secure Encryption</h2>
      <p>PRF-based encryption with random nonce — IND-CPA secure</p>
    </div>
    <div className="card">
      <h3>🔒 Encrypt</h3>
      <div className="input-group"><label>Key (hex, 16 bytes)</label><input value={key} onChange={e => setKey(e.target.value)} /></div>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Encrypt"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Nonce / IV (hex)" value={result.nonce_hex} />
          <Field label="Ciphertext (hex)" value={result.ciphertext_hex} accent="var(--accent-purple)" />
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 4 }}>
            Ciphertext = F_k(nonce) ⊕ message — safe to reuse key with fresh nonce
          </div>
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#4: Modes ──────────────────────────────────────────────────────────────
export function PA04() {
  const [mode, setMode] = useState("CTR");
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [msg, setMsg] = useState("48656c6c6f20576f726c642121212121");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    const r = await apiFetch("/pa04/encrypt", { mode, key_hex: key, message_hex: msg });
    setResult(r);
    setLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#4</span> Block Cipher Modes</h2>
      <p>ECB, CBC, CTR modes of operation</p>
    </div>
    <div className="card">
      <h3>🧱 Mode Encryption</h3>
      <div className="input-row">
        <div className="input-group"><label>Mode</label>
          <select value={mode} onChange={e => setMode(e.target.value)}>
            <option>ECB</option><option>CBC</option><option>OFB</option><option>CTR</option>
          </select>
        </div>
      </div>
      <div className="input-group"><label>Key (hex)</label><input value={key} onChange={e => setKey(e.target.value)} /></div>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : `Encrypt (${mode})`}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <div className="result-row" style={{marginBottom:"0.5rem"}}>
            <span className="badge badge-info">Mode: {result.mode}</span>
            {result.mode === 'ECB' && <span className="badge badge-warn">⚠ No IV — NOT IND-CPA secure</span>}
          </div>
          {result.mode !== 'ECB' && <Field label="IV / Nonce (hex)" value={result.iv_hex} />}
          <Field label="Ciphertext (hex)" value={result.ciphertext_hex} accent="var(--accent-purple)" />
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#5: MAC ────────────────────────────────────────────────────────────────
export function PA05() {
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [msg, setMsg] = useState("48656c6c6f");
  const [macType, setMacType] = useState("prf");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    const r = await apiFetch("/pa05/mac", { key_hex: key, message_hex: msg, mac_type: macType });
    setResult(r);
    setLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#5</span> Message Authentication Codes</h2>
      <p>PRF-MAC and CBC-MAC — EUF-CMA secure</p>
    </div>
    <div className="card">
      <h3>✅ Compute MAC</h3>
      <div className="input-row">
        <div className="input-group"><label>Type</label>
          <select value={macType} onChange={e => setMacType(e.target.value)}>
            <option value="prf">PRF-MAC</option><option value="cbc">CBC-MAC</option>
          </select>
        </div>
      </div>
      <div className="input-group"><label>Key (hex)</label><input value={key} onChange={e => setKey(e.target.value)} /></div>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Compute Tag"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <div className="result-row" style={{marginBottom:"0.5rem"}}>
            <span className="badge badge-info">Type: {result.mac_type?.toUpperCase()}</span>
          </div>
          <Field label="Authentication Tag (hex)" value={result.tag_hex} accent="var(--accent-green)" />
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}

// ── PA#6: CCA ────────────────────────────────────────────────────────────────
export function PA06() {
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [msg, setMsg] = useState("48656c6c6f");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    const r = await apiFetch("/pa06/encrypt", { key_hex: key, message_hex: msg });
    setResult(r);
    setLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#6</span> CCA-Secure Encryption</h2>
      <p>Encrypt-then-MAC — IND-CCA2 secure symmetric encryption</p>
    </div>
    <div className="card">
      <h3>🛡️ CCA Encrypt</h3>
      <div className="input-group"><label>Key (hex)</label><input value={key} onChange={e => setKey(e.target.value)} /></div>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "CCA Encrypt"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Nonce (hex)" value={result.nonce_hex} />
          <Field label="Ciphertext (hex)" value={result.ciphertext_hex} accent="var(--accent-purple)" />
          <Field label="Authentication Tag (hex)" value={result.tag_hex} accent="var(--accent-green)" />
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 4 }}>
            {result.note}
          </div>
        </div>
      )}
      {result?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}
