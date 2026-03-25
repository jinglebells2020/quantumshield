import { useState, useEffect, useRef } from "react";

// Bloch Sphere SVG Component
const BlochSphere = ({ size = 48, className = "" }) => (
<svg width={size} height={size} viewBox="0 0 100 100" className={className} style={{ filter: "drop-shadow(0 0 12px rgba(0, 255, 136, 0.3))" }}>
<defs>
<radialGradient id="sphereGrad" cx="35%" cy="35%">
<stop offset="0%" stopColor="rgba(0,255,136,0.15)" />
<stop offset="100%" stopColor="rgba(0,0,0,0)" />
</radialGradient>
<linearGradient id="axisGrad" x1="0%" y1="0%" x2="100%" y2="100%">
<stop offset="0%" stopColor="#00ff88" stopOpacity="0.8" />
<stop offset="100%" stopColor="#00ff88" stopOpacity="0.2" />
</linearGradient>
</defs>
{/* Sphere outline */}
<circle cx="50" cy="50" r="38" fill="url(#sphereGrad)" stroke="#00ff88" strokeWidth="1" opacity="0.6" />
{/* Equator ellipse */}
<ellipse cx="50" cy="55" rx="38" ry="12" fill="none" stroke="#00ff88" strokeWidth="0.7" opacity="0.35" strokeDasharray="3,3" />
{/* Vertical meridian */}
<ellipse cx="50" cy="50" rx="12" ry="38" fill="none" stroke="#00ff88" strokeWidth="0.7" opacity="0.25" strokeDasharray="3,3" />
{/* Z-axis */}
<line x1="50" y1="8" x2="50" y2="92" stroke="#00ff88" strokeWidth="0.8" opacity="0.4" />
{/* |0⟩ label */}
<text x="50" y="7" textAnchor="middle" fill="#00ff88" fontSize="7" fontFamily="monospace" opacity="0.8">|0⟩</text>
{/* |1⟩ label */}
<text x="50" y="98" textAnchor="middle" fill="#00ff88" fontSize="7" fontFamily="monospace" opacity="0.8">|1⟩</text>
{/* State vector arrow */}
<line x1="50" y1="50" x2="30" y2="25" stroke="#00ff88" strokeWidth="1.8" />
{/* Arrow head */}
<polygon points="28,22 34,26 30,30" fill="#00ff88" />
{/* State dot */}
<circle cx="30" cy="25" r="2.5" fill="#00ff88">
<animate attributeName="opacity" values="1;0.5;1" dur="2s" repeatCount="indefinite" />
</circle>
{/* |ψ⟩ label */}
<text x="22" y="20" textAnchor="middle" fill="#00ff88" fontSize="8" fontFamily="monospace" fontWeight="bold">|ψ⟩</text>
</svg>
);

// Animated counter
const Counter = ({ end, duration = 2000, suffix = "" }: { end: number; duration?: number; suffix?: string }) => {
const [count, setCount] = useState(0);
const ref = useRef(null);
const counted = useRef(false);
useEffect(() => {
const observer = new IntersectionObserver(([entry]) => {
if (entry.isIntersecting && !counted.current) {
counted.current = true;
const start = Date.now();
const tick = () => {
const elapsed = Date.now() - start;
const progress = Math.min(elapsed / duration, 1);
const eased = 1 - Math.pow(1 - progress, 3);
setCount(Math.floor(eased * end));
if (progress < 1) requestAnimationFrame(tick);
};
tick();
}
}, { threshold: 0.3 });
if (ref.current) observer.observe(ref.current);
return () => observer.disconnect();
}, [end, duration]);
return <span ref={ref}>{count}{suffix}</span>;
};

// Leaderboard data
const leaderboardData = [
{ rank: 1, project: "Boulder (Let's Encrypt)", score: 0, findings: 414, critical: 428, shor: 521, description: "CA issuing 400M+ certificates" },
{ rank: 2, project: "Traefik", score: 3, findings: 200, critical: 26, shor: 247, description: "Cloud-native reverse proxy" },
{ rank: 3, project: "etcd", score: 4, findings: 46, critical: 12, shor: 75, description: "Distributed key-value store" },
{ rank: 4, project: "HashiCorp Vault", score: 6, findings: 527, critical: 390, shor: 626, description: "Secrets management platform" },
{ rank: 5, project: "Kubernetes", score: 7, findings: 453, critical: 192, shor: 554, description: "Container orchestration" },
{ rank: 6, project: "mkcert", score: 21, findings: 13, critical: 8, shor: 11, description: "Local dev certificates" },
{ rank: 7, project: "Django", score: 60, findings: 7, critical: 0, shor: 0, description: "Python web framework" },
];

const benchmarkData = [
{ suite: "NIST Juliet CWE-327/328", precision: "100%", recall: "94.4%", f1: "97.1%", fpr: "0%" },
{ suite: "OWASP Benchmark v1.2", precision: "100%", recall: "84.6%", f1: "91.6%", fpr: "0%" },
];

const comparisonData = [
{ category: "Classically broken (DES, MD5, SHA-1)", semgrep: 18, qs: 33 },
{ category: "Quantum-vulnerable (RSA, ECDSA, ECDH)", semgrep: 0, qs: 408 },
{ category: "TLS configuration", semgrep: 18, qs: 60 },
{ category: "Weak PRNG (math/rand)", semgrep: 30, qs: "—" },
];

export default function QuantumShieldSite() {
const [activeSection, setActiveSection] = useState("hero");
const [_mobileMenuOpen, setMobileMenuOpen] = useState(false);

const sections = ["hero", "problem", "product", "benchmarks", "leaderboard", "comparison", "install"];

useEffect(() => {
const handleScroll = () => {
for (const id of [...sections].reverse()) {
const el = document.getElementById(id);
if (el && el.getBoundingClientRect().top < window.innerHeight / 2) {
setActiveSection(id);
break;
}
}
};
window.addEventListener("scroll", handleScroll);
return () => window.removeEventListener("scroll", handleScroll);
}, []);

const scrollTo = (id: string) => {
document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
setMobileMenuOpen(false);
};

return (
<div style={{
background: "#050505",
color: "#e8e8e8",
fontFamily: "'IBM Plex Mono', 'JetBrains Mono', 'Fira Code', monospace",
minHeight: "100vh",
overflowX: "hidden",
}}>
<style>{`
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=Newsreader:ital,wght@0,300;0,400;0,600;1,300;1,400&display=swap');

    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    
    ::selection { background: rgba(0,255,136,0.25); color: #fff; }
    
    .nav-link { color: #666; text-decoration: none; font-size: 12px; letter-spacing: 1.5px; text-transform: uppercase; transition: color 0.3s; cursor: pointer; padding: 8px 0; }
    .nav-link:hover, .nav-link.active { color: #00ff88; }
    
    .section { padding: 120px 24px; max-width: 1100px; margin: 0 auto; }
    
    .green { color: #00ff88; }
    .dim { color: #555; }
    .mono { font-family: 'IBM Plex Mono', monospace; }
    .serif { font-family: 'Newsreader', Georgia, serif; }
    
    .headline {
      font-family: 'Newsreader', Georgia, serif;
      font-weight: 300;
      font-size: clamp(36px, 6vw, 64px);
      line-height: 1.15;
      letter-spacing: -1px;
      margin-bottom: 24px;
    }
    
    .subhead {
      font-size: 14px;
      line-height: 1.8;
      color: #888;
      max-width: 540px;
    }
    
    .label {
      font-size: 10px;
      letter-spacing: 3px;
      text-transform: uppercase;
      color: #00ff88;
      margin-bottom: 24px;
      opacity: 0.7;
    }
    
    .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 32px; margin-top: 48px; }
    .stat-box { border-left: 1px solid #1a1a1a; padding-left: 20px; }
    .stat-number { font-size: 42px; font-weight: 300; color: #00ff88; font-family: 'Newsreader', serif; }
    .stat-label { font-size: 11px; color: #555; text-transform: uppercase; letter-spacing: 2px; margin-top: 4px; }
    
    .table-wrap { overflow-x: auto; margin-top: 32px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 12px 16px; border-bottom: 1px solid #1a1a1a; color: #555; font-weight: 500; font-size: 10px; letter-spacing: 2px; text-transform: uppercase; }
    td { padding: 12px 16px; border-bottom: 1px solid #0d0d0d; }
    tr:hover td { background: rgba(0,255,136,0.02); }
    
    .score-bar { height: 4px; background: #111; border-radius: 2px; overflow: hidden; width: 100px; display: inline-block; vertical-align: middle; margin-left: 8px; }
    .score-fill { height: 100%; border-radius: 2px; transition: width 1s ease; }
    
    .code-block {
      background: #0a0a0a;
      border: 1px solid #151515;
      border-radius: 6px;
      padding: 24px;
      font-size: 13px;
      line-height: 1.7;
      overflow-x: auto;
      margin-top: 24px;
    }
    
    .cta-button {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: transparent;
      color: #00ff88;
      border: 1px solid #00ff88;
      padding: 12px 28px;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 13px;
      letter-spacing: 1px;
      cursor: pointer;
      transition: all 0.3s;
      text-decoration: none;
      margin-top: 32px;
    }
    .cta-button:hover { background: rgba(0,255,136,0.1); }
    
    .divider { height: 1px; background: linear-gradient(to right, transparent, #1a1a1a, transparent); margin: 0 auto; max-width: 1100px; }
    
    .comparison-bar { display: flex; align-items: center; gap: 12px; margin: 4px 0; }
    .bar { height: 20px; border-radius: 2px; transition: width 1s ease; min-width: 2px; }
    .bar-semgrep { background: #333; }
    .bar-qs { background: #00ff88; }
    
    .fade-in { opacity: 0; transform: translateY(20px); animation: fadeUp 0.8s ease forwards; }
    @keyframes fadeUp { to { opacity: 1; transform: translateY(0); } }
    
    .grain {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      pointer-events: none;
      z-index: 9999;
      opacity: 0.03;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E");
    }
    
    .glow-line {
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 1px;
      background: linear-gradient(to right, transparent, #00ff88, transparent);
      opacity: 0.3;
    }

    @media (max-width: 768px) {
      .section { padding: 80px 20px; }
      .stat-grid { grid-template-columns: 1fr 1fr; gap: 24px; }
      .headline { font-size: 32px; }
      .nav-desktop { display: none !important; }
    }
    @media (min-width: 769px) {
      .nav-mobile-toggle { display: none !important; }
    }
  `}</style>

  {/* Film grain overlay */}
  <div className="grain" />

  {/* Navigation */}
  <nav style={{
    position: "fixed",
    top: 0,
    left: 0,
    right: 0,
    zIndex: 1000,
    background: "rgba(5,5,5,0.85)",
    backdropFilter: "blur(20px)",
    borderBottom: "1px solid #111",
    padding: "0 24px",
  }}>
    <div style={{ maxWidth: 1100, margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "space-between", height: 56 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }} onClick={() => scrollTo("hero")}>
        <BlochSphere size={28} />
        <span style={{ fontSize: 14, fontWeight: 600, letterSpacing: 2 }}>QUANTUMSHIELD</span>
      </div>
      <div className="nav-desktop" style={{ display: "flex", gap: 28, alignItems: "center" }}>
        {[
          ["problem", "Problem"],
          ["product", "Product"],
          ["benchmarks", "Benchmarks"],
          ["leaderboard", "Leaderboard"],
          ["comparison", "vs Semgrep"],
          ["install", "Install"],
        ].map(([id, label]) => (
          <span key={id} className={`nav-link ${activeSection === id ? "active" : ""}`} onClick={() => scrollTo(id)}>{label}</span>
        ))}
        <a href="https://github.com/quantumshield/qs" target="_blank" rel="noopener" className="nav-link" style={{ color: "#888" }}>GitHub ↗</a>
      </div>
    </div>
  </nav>

  {/* Hero */}
  <section id="hero" style={{ minHeight: "100vh", display: "flex", alignItems: "center", position: "relative" }}>
    <div className="glow-line" style={{ top: 56 }} />
    <div className="section" style={{ paddingTop: 160 }}>
      <div className="fade-in">
        <div className="label">Open-Source Quantum Cryptography Scanner</div>
        <h1 className="headline">
          Your cryptography is<br />
          <span className="green">already being harvested.</span>
        </h1>
        <p className="subhead">
          QuantumShield finds quantum-vulnerable cryptography that every other
          scanner considers safe. RSA, ECDSA, ECDH — algorithms Shor's algorithm
          will break completely. 100% precision on NIST benchmarks. Zero false positives.
        </p>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 40 }}>
          <div className="code-block" style={{ marginTop: 0, display: "inline-block" }}>
            <span className="dim">$</span> <span className="green">go install</span> github.com/quantumshield/qs@latest
          </div>
        </div>
        <button className="cta-button" onClick={() => scrollTo("leaderboard")}>
          View Leaderboard →
        </button>
      </div>
      
      <div className="stat-grid" style={{ animationDelay: "0.3s" }}>
        <div className="stat-box fade-in" style={{ animationDelay: "0.2s" }}>
          <div className="stat-number"><Counter end={97} suffix="%" /></div>
          <div className="stat-label">F1 Score (NIST)</div>
        </div>
        <div className="stat-box fade-in" style={{ animationDelay: "0.4s" }}>
          <div className="stat-number"><Counter end={571} /></div>
          <div className="stat-label">Production Findings</div>
        </div>
        <div className="stat-box fade-in" style={{ animationDelay: "0.6s" }}>
          <div className="stat-number">0</div>
          <div className="stat-label">False Positives</div>
        </div>
        <div className="stat-box fade-in" style={{ animationDelay: "0.8s" }}>
          <div className="stat-number"><Counter end={19530} /></div>
          <div className="stat-label">Lines of Go</div>
        </div>
      </div>
    </div>
  </section>

  <div className="divider" />

  {/* Problem */}
  <section id="problem">
    <div className="section">
      <div className="label">The Threat</div>
      <h2 className="headline" style={{ fontSize: "clamp(28px, 4vw, 44px)" }}>
        <span className="dim">Semgrep found 66 crypto issues in Vault.</span><br />
        QuantumShield found <span className="green">527</span>.
      </h2>
      <p className="subhead" style={{ marginTop: 24 }}>
        Existing SAST tools flag what's broken today — DES, MD5, SHA-1. They consider
        RSA-2048, ECDSA-P256, and ECDH perfectly safe. Shor's algorithm will break all of them.
        The 408 findings Semgrep misses are real function calls — <code style={{ color: "#00ff88" }}>ecdsa.GenerateKey</code>,{" "}
        <code style={{ color: "#00ff88" }}>rsa.SignPKCS1v15</code>,{" "}
        <code style={{ color: "#00ff88" }}>x509.CreateCertificate</code> — that
        every existing tool considers safe.
      </p>
      <p style={{ color: "#555", fontSize: 13, marginTop: 32, fontStyle: "italic", fontFamily: "'Newsreader', serif" }}>
        CNSA 2.0 compliance deadline: January 2027 for new systems. Full migration by 2035.
      </p>
    </div>
  </section>

  <div className="divider" />

  {/* Product */}
  <section id="product">
    <div className="section">
      <div className="label">How It Works</div>
      <h2 className="headline" style={{ fontSize: "clamp(28px, 4vw, 44px)" }}>
        Four-layer scanning.<br />
        <span className="green">Twelve math modules.</span>
      </h2>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 40, marginTop: 48 }}>
        {[
          { title: "Layer 1 — Pattern Matching", desc: "Regex rules across Go, Python, JavaScript, Java, and config files. 10 YAML rule sets covering RSA, ECDSA, ECDH, AES-128, DES, MD5, SHA-1, TLS, SSH, X.509." },
          { title: "Layer 2 — Go AST Analysis", desc: "Parses actual abstract syntax trees. Resolves import aliases, extracts key sizes from literal arguments, analyzes tls.Config struct fields. 0.95 confidence." },
          { title: "Layer 3 — Certificate Scanning", desc: "Parses PEM/DER files. Extracts public key algorithm, key size, signature algorithm, expiry. Flags certs expiring after 2030 with quantum-vulnerable algorithms." },
          { title: "Layer 4 — Dependency Analysis", desc: "Parses go.mod, package.json, requirements.txt, pom.xml. Cross-references against 15 known-vulnerable crypto packages. Full dependency chain tracking." },
        ].map((item, i) => (
          <div key={i} style={{ borderLeft: "1px solid #1a1a1a", paddingLeft: 20 }}>
            <h3 style={{ fontSize: 14, fontWeight: 600, color: "#00ff88", marginBottom: 12 }}>{item.title}</h3>
            <p style={{ fontSize: 13, color: "#666", lineHeight: 1.7 }}>{item.desc}</p>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 64 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: "#00ff88", marginBottom: 20 }}>Analytics Engine — 12 Modules, Pure Go, Zero Dependencies</h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
          {[
            "Bayesian FP Reducer", "Markov Migration Predictor", "Developer Profiler",
            "HNDL Attack Model", "Monte Carlo Simulator", "FFT Traffic Fingerprinter",
            "Entropy Analyzer", "Spectral Graph Partitioner", "HMM Pattern Detector",
            "Information-Theoretic Scorer", "Optimal Stopping", "TDA Persistence",
          ].map((mod, i) => (
            <div key={i} style={{ fontSize: 12, color: "#444", padding: "8px 12px", border: "1px solid #111", borderRadius: 3 }}>
              <span className="green" style={{ opacity: 0.5 }}>▸</span> {mod}
            </div>
          ))}
        </div>
      </div>
    </div>
  </section>

  <div className="divider" />

  {/* Benchmarks */}
  <section id="benchmarks">
    <div className="section">
      <div className="label">Verified Results</div>
      <h2 className="headline" style={{ fontSize: "clamp(28px, 4vw, 44px)" }}>
        <span className="green">100% precision</span> on<br />
        government benchmarks.
      </h2>
      <p className="subhead">
        No quantum security company has published reproducible benchmark scores.
        Not SandboxAQ ($5.6B). Not Keyfactor ($1B+). Not PQShield ($65M raised).
        We publish ours.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Benchmark</th>
              <th>Precision</th>
              <th>Recall</th>
              <th>F1 Score</th>
              <th>False Positive Rate</th>
            </tr>
          </thead>
          <tbody>
            {benchmarkData.map((b, i) => (
              <tr key={i}>
                <td style={{ color: "#ccc", fontWeight: 500 }}>{b.suite}</td>
                <td className="green">{b.precision}</td>
                <td>{b.recall}</td>
                <td style={{ color: "#00ff88" }}>{b.f1}</td>
                <td className="green">{b.fpr}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p style={{ fontSize: 12, color: "#444", marginTop: 20, lineHeight: 1.7 }}>
        567 labeled test cases. 372 vulnerabilities detected. 0 false alarms.
        All 9 NIST misses are variant-12 cross-method data flow — a known limitation of pattern-based scanning.
        Every actual crypto API call site is detected correctly.
      </p>
    </div>
  </section>

  <div className="divider" />

  {/* Leaderboard */}
  <section id="leaderboard">
    <div className="section">
      <div className="label">Quantum Readiness Leaderboard</div>
      <h2 className="headline" style={{ fontSize: "clamp(28px, 4vw, 44px)" }}>
        The world's critical infrastructure<br />
        averages <span className="green">15/100</span>.
      </h2>
      <p className="subhead">
        We scanned 7 major open-source projects — 29,054 files total. Zero PQC adoption found.
        ML-KEM = 0. ML-DSA = 0. Nobody has started migrating.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Rank</th>
              <th>Project</th>
              <th>Score</th>
              <th style={{ textAlign: "right" }}>Findings</th>
              <th style={{ textAlign: "right" }}>Critical</th>
              <th style={{ textAlign: "right" }}>Shor-Vulnerable</th>
            </tr>
          </thead>
          <tbody>
            {leaderboardData.map((row) => {
              const barColor = row.score <= 10 ? "#ff3333" : row.score <= 30 ? "#ff8833" : row.score <= 60 ? "#ffcc00" : "#00ff88";
              return (
                <tr key={row.rank}>
                  <td className="dim">#{row.rank}</td>
                  <td>
                    <span style={{ color: "#ccc", fontWeight: 500 }}>{row.project}</span>
                    <br />
                    <span style={{ fontSize: 11, color: "#444" }}>{row.description}</span>
                  </td>
                  <td>
                    <span style={{ color: barColor, fontWeight: 600 }}>{row.score}/100</span>
                    <div className="score-bar">
                      <div className="score-fill" style={{ width: `${row.score}%`, background: barColor }} />
                    </div>
                  </td>
                  <td style={{ textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{row.findings}</td>
                  <td style={{ textAlign: "right", fontVariantNumeric: "tabular-nums", color: row.critical > 100 ? "#ff5555" : "#888" }}>{row.critical}</td>
                  <td style={{ textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{row.shor}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p style={{ fontSize: 12, color: "#333", marginTop: 24 }}>
        Updated March 2026. Findings verified by Go AST analysis after noise filtering. All counts represent real crypto API calls.
      </p>
    </div>
  </section>

  <div className="divider" />

  {/* Comparison */}
  <section id="comparison">
    <div className="section">
      <div className="label">QuantumShield vs Semgrep on HashiCorp Vault</div>
      <h2 className="headline" style={{ fontSize: "clamp(28px, 4vw, 44px)" }}>
        Semgrep catches what's broken <span className="dim">today</span>.<br />
        QuantumShield catches what's broken <span className="green">tomorrow</span>.
      </h2>
      <div style={{ marginTop: 48 }}>
        {comparisonData.map((row, i) => {
          const maxVal = Math.max(typeof row.semgrep === "number" ? row.semgrep : 0, typeof row.qs === "number" ? row.qs : 0, 1);
          return (
            <div key={i} style={{ marginBottom: 28 }}>
              <div style={{ fontSize: 12, marginBottom: 8, fontWeight: row.category.includes("Quantum") ? 600 : 400, color: row.category.includes("Quantum") ? "#ccc" : "#666" }}>
                {row.category}
              </div>
              <div className="comparison-bar">
                <span style={{ fontSize: 11, color: "#555", width: 70, textAlign: "right" }}>Semgrep</span>
                <div className="bar bar-semgrep" style={{ width: `${(typeof row.semgrep === "number" ? row.semgrep : 0) / maxVal * 300}px` }} />
                <span style={{ fontSize: 12, color: "#555", fontVariantNumeric: "tabular-nums" }}>{row.semgrep}</span>
              </div>
              <div className="comparison-bar">
                <span style={{ fontSize: 11, color: "#00ff88", width: 70, textAlign: "right", opacity: 0.7 }}>QShield</span>
                <div className="bar bar-qs" style={{ width: `${(typeof row.qs === "number" ? row.qs : 0) / maxVal * 300}px` }} />
                <span style={{ fontSize: 12, color: "#00ff88", fontVariantNumeric: "tabular-nums" }}>{row.qs}</span>
              </div>
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 40, padding: 24, border: "1px solid #1a1a1a", borderRadius: 4 }}>
        <p style={{ fontSize: 13, color: "#888", lineHeight: 1.7 }}>
          <span className="green" style={{ fontWeight: 600 }}>408 to 0.</span> That's not a marginal improvement —
          it's an entirely new category of threat that no existing SAST tool covers.
          No rule pack, no plugin, no extension to Semgrep, CodeQL, or SonarQube covers quantum-threat crypto.
        </p>
      </div>
    </div>
  </section>

  <div className="divider" />

  {/* Install */}
  <section id="install">
    <div className="section" style={{ textAlign: "center" }}>
      <div className="label">Get Started</div>
      <h2 className="headline" style={{ fontSize: "clamp(28px, 4vw, 44px)" }}>
        One command.<br />
        <span className="green">Zero dependencies.</span>
      </h2>
      <div className="code-block" style={{ maxWidth: 600, margin: "32px auto 0", textAlign: "left" }}>
        <div><span className="dim"># Install</span></div>
        <div><span className="dim">$</span> <span className="green">go install</span> github.com/quantumshield/qs@latest</div>
        <div style={{ marginTop: 16 }}><span className="dim"># Scan your project</span></div>
        <div><span className="dim">$</span> qs scan ./your-project</div>
        <div style={{ marginTop: 16 }}><span className="dim"># CI/CD mode (blocks quantum-vulnerable crypto)</span></div>
        <div><span className="dim">$</span> qs scan . --ci --format sarif</div>
        <div style={{ marginTop: 16 }}><span className="dim"># Install git pre-commit hook</span></div>
        <div><span className="dim">$</span> qs install-hook</div>
      </div>
      <div style={{ marginTop: 48, display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
        <a href="https://github.com/quantumshield/qs" target="_blank" rel="noopener" className="cta-button" style={{ marginTop: 0 }}>
          GitHub Repository →
        </a>
        <a href="https://github.com/quantumshield/qs/blob/main/docs/README.md" target="_blank" rel="noopener" className="cta-button" style={{ marginTop: 0, borderColor: "#333", color: "#888" }}>
          Documentation
        </a>
      </div>
    </div>
  </section>

  <div className="divider" />

  {/* Footer */}
  <footer style={{ padding: "48px 24px", maxWidth: 1100, margin: "0 auto" }}>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 20 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <BlochSphere size={22} />
        <span style={{ fontSize: 12, color: "#333", letterSpacing: 2 }}>QUANTUMSHIELD</span>
      </div>
      <div style={{ fontSize: 11, color: "#333" }}>
        73 Go files · 19,530 lines · 178 tests · Apache 2.0
      </div>
      <div style={{ fontSize: 11, color: "#333" }}>
        Built by <a href="https://github.com/altn" style={{ color: "#555", textDecoration: "none" }}>ALTN</a> · Benchmarked on NIST SARD + OWASP
      </div>
    </div>
  </footer>
</div>

);
}
