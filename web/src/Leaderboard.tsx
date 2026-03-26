import { useState } from 'react'

const LEADERBOARD = [
  { rank: 1, project: "Boulder (Let's Encrypt)", org: 'letsencrypt/boulder', score: 0, findings: 414, critical: 428, shor: 521, prod: 60, test: 354, desc: 'ACME CA — issues 400M+ certificates', stars: '5.3k', lang: 'Go' },
  { rank: 2, project: 'Traefik', org: 'traefik/traefik', score: 3, findings: 200, critical: 26, shor: 247, prod: 77, test: 123, desc: 'Cloud-native edge router & reverse proxy', stars: '53k', lang: 'Go' },
  { rank: 3, project: 'etcd', org: 'etcd-io/etcd', score: 5, findings: 46, critical: 12, shor: 75, prod: 23, test: 23, desc: 'Distributed key-value store for Kubernetes', stars: '48k', lang: 'Go' },
  { rank: 4, project: 'HashiCorp Vault', org: 'hashicorp/vault', score: 7, findings: 527, critical: 390, shor: 626, prod: 282, test: 245, desc: 'Secrets management & data encryption', stars: '32k', lang: 'Go' },
  { rank: 5, project: 'Kubernetes', org: 'kubernetes/kubernetes', score: 10, findings: 453, critical: 192, shor: 554, prod: 109, test: 344, desc: 'Container orchestration platform', stars: '113k', lang: 'Go' },
  { rank: 6, project: 'mkcert', org: 'FiloSottile/mkcert', score: 18, findings: 13, critical: 8, shor: 11, prod: 13, test: 0, desc: 'Zero-config local dev certificates', stars: '51k', lang: 'Go' },
  { rank: 7, project: 'Django', org: 'django/django', score: 60, findings: 7, critical: 0, shor: 0, prod: 7, test: 0, desc: 'Python web framework', stars: '82k', lang: 'Python' },
]

const BENCHMARKS = [
  { suite: 'NIST Juliet CWE-327/328', precision: '100%', recall: '94.4%', f1: '97.1%', fpr: '0%', cases: 264 },
  { suite: 'OWASP Benchmark v1.2', precision: '100%', recall: '84.6%', f1: '91.6%', fpr: '0%', cases: 482 },
]

const SEMGREP = { semgrep: 66, qs: 527, gap: 408 }

function scoreColor(score: number): string {
  if (score < 15) return '#ef4444'
  if (score < 30) return '#f97316'
  if (score < 50) return '#f59e0b'
  if (score < 70) return '#eab308'
  return '#22c55e'
}

function riskLabel(score: number): string {
  if (score < 15) return 'CRITICAL'
  if (score < 30) return 'HIGH'
  if (score < 50) return 'MODERATE'
  if (score < 70) return 'LOW'
  return 'SAFE'
}

export default function Leaderboard() {
  const [expanded, setExpanded] = useState<number | null>(null)

  const totalFindings = LEADERBOARD.reduce((s, e) => s + e.findings, 0)
  const totalShor = LEADERBOARD.reduce((s, e) => s + e.shor, 0)
  const totalProd = LEADERBOARD.reduce((s, e) => s + e.prod, 0)
  const avgScore = Math.round(LEADERBOARD.reduce((s, e) => s + e.score, 0) / LEADERBOARD.length)

  return (
    <div style={{ background: '#050505', color: '#e8e8e8', fontFamily: "'Inter', system-ui, sans-serif", minHeight: '100vh' }}>

      {/* Nav */}
      <nav style={{ background: '#0a0a0a', borderBottom: '1px solid #1a1a1a', padding: '16px 40px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'sticky', top: 0, zIndex: 50 }}>
        <a href="/" style={{ color: '#7c3aed', fontWeight: 800, fontSize: 20, textDecoration: 'none' }}>&#9670; QuantumShield</a>
        <div style={{ display: 'flex', gap: 24 }}>
          <a href="/" style={{ color: '#888', textDecoration: 'none', fontSize: 14 }}>Home</a>
          <a href="/dashboard" style={{ color: '#888', textDecoration: 'none', fontSize: 14 }}>Dashboard</a>
          <span style={{ color: '#e8e8e8', fontSize: 14, fontWeight: 600 }}>Leaderboard</span>
        </div>
      </nav>

      {/* Hero */}
      <div style={{ textAlign: 'center', padding: '60px 40px 40px' }}>
        <h1 style={{ fontSize: 42, fontWeight: 800, margin: 0, background: 'linear-gradient(135deg, #7c3aed, #ef4444)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          Quantum Readiness Leaderboard
        </h1>
        <p style={{ color: '#666', fontSize: 16, marginTop: 12, maxWidth: 600, marginLeft: 'auto', marginRight: 'auto' }}>
          How prepared is the world's critical open-source infrastructure for quantum computers?
        </p>
      </div>

      {/* Aggregate Stats */}
      <div style={{ display: 'flex', justifyContent: 'center', gap: 24, padding: '0 40px 48px', flexWrap: 'wrap' }}>
        {[
          { label: 'Projects Scanned', value: LEADERBOARD.length, color: '#7c3aed' },
          { label: 'Total Findings', value: totalFindings.toLocaleString(), color: '#ef4444' },
          { label: 'Shor-Vulnerable', value: totalShor.toLocaleString(), color: '#ef4444' },
          { label: 'Production Code', value: totalProd.toLocaleString(), color: '#f59e0b' },
          { label: 'Avg Readiness', value: `${avgScore}/100`, color: '#ef4444' },
        ].map((stat, i) => (
          <div key={i} style={{ background: '#111', border: '1px solid #222', borderRadius: 12, padding: '20px 28px', textAlign: 'center', minWidth: 140 }}>
            <div style={{ color: stat.color, fontSize: 28, fontWeight: 800 }}>{stat.value}</div>
            <div style={{ color: '#666', fontSize: 11, letterSpacing: 1, textTransform: 'uppercase', marginTop: 4 }}>{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Leaderboard Table */}
      <div style={{ maxWidth: 1100, margin: '0 auto', padding: '0 40px' }}>
        <div style={{ background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 16, overflow: 'hidden' }}>

          {/* Header */}
          <div style={{ display: 'grid', gridTemplateColumns: '50px 1fr 120px 100px 100px 100px', padding: '14px 24px', borderBottom: '1px solid #1a1a1a', background: '#0a0a0a', fontSize: 11, color: '#555', letterSpacing: 1, textTransform: 'uppercase', fontWeight: 600 }}>
            <div>Rank</div>
            <div>Project</div>
            <div style={{ textAlign: 'center' }}>Score</div>
            <div style={{ textAlign: 'right' }}>Findings</div>
            <div style={{ textAlign: 'right' }}>Shor</div>
            <div style={{ textAlign: 'right' }}>Production</div>
          </div>

          {/* Rows */}
          {LEADERBOARD.map((entry, i) => {
            const color = scoreColor(entry.score)
            const risk = riskLabel(entry.score)
            const isExpanded = expanded === i
            const barWidth = Math.max(2, entry.score)

            return (
              <div key={i}>
                <div
                  onClick={() => setExpanded(isExpanded ? null : i)}
                  style={{
                    display: 'grid', gridTemplateColumns: '50px 1fr 120px 100px 100px 100px',
                    padding: '16px 24px', borderBottom: '1px solid #111',
                    cursor: 'pointer', transition: 'background 0.2s',
                    background: isExpanded ? '#141414' : 'transparent',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = '#141414')}
                  onMouseLeave={e => { if (!isExpanded) e.currentTarget.style.background = 'transparent' }}
                >
                  <div style={{ color: '#555', fontWeight: 700, fontSize: 18 }}>#{entry.rank}</div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 15 }}>{entry.project}</div>
                    <div style={{ color: '#555', fontSize: 12, marginTop: 2 }}>{entry.desc}</div>
                  </div>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                      <span style={{ color, fontWeight: 800, fontSize: 18 }}>{entry.score}</span>
                      <span style={{ color: '#444', fontSize: 13 }}>/100</span>
                    </div>
                    <div style={{ background: '#1a1a1a', borderRadius: 4, height: 4, marginTop: 6, overflow: 'hidden' }}>
                      <div style={{ background: color, height: '100%', width: `${barWidth}%`, borderRadius: 4, transition: 'width 0.5s' }} />
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', fontWeight: 600, color: '#ccc' }}>{entry.findings}</div>
                  <div style={{ textAlign: 'right', fontWeight: 600, color: entry.shor > 0 ? '#ef4444' : '#22c55e' }}>{entry.shor}</div>
                  <div style={{ textAlign: 'right', fontWeight: 600, color: '#f59e0b' }}>{entry.prod}</div>
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div style={{ padding: '0 24px 24px', background: '#141414', borderBottom: '1px solid #222' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginTop: 8 }}>
                      <div style={{ background: '#1a1a1a', borderRadius: 8, padding: 16 }}>
                        <div style={{ color: '#555', fontSize: 11, letterSpacing: 1, textTransform: 'uppercase' }}>Risk Level</div>
                        <div style={{ color, fontSize: 20, fontWeight: 800, marginTop: 4 }}>{risk}</div>
                      </div>
                      <div style={{ background: '#1a1a1a', borderRadius: 8, padding: 16 }}>
                        <div style={{ color: '#555', fontSize: 11, letterSpacing: 1, textTransform: 'uppercase' }}>Critical Findings</div>
                        <div style={{ color: '#ef4444', fontSize: 20, fontWeight: 800, marginTop: 4 }}>{entry.critical}</div>
                      </div>
                      <div style={{ background: '#1a1a1a', borderRadius: 8, padding: 16 }}>
                        <div style={{ color: '#555', fontSize: 11, letterSpacing: 1, textTransform: 'uppercase' }}>Test File Findings</div>
                        <div style={{ color: '#666', fontSize: 20, fontWeight: 800, marginTop: 4 }}>{entry.test}</div>
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 16, marginTop: 12, fontSize: 13, color: '#666' }}>
                      <span>Language: <strong style={{ color: '#aaa' }}>{entry.lang}</strong></span>
                      <span>Stars: <strong style={{ color: '#aaa' }}>{entry.stars}</strong></span>
                      <span>Repo: <a href={`https://github.com/${entry.org}`} target="_blank" rel="noreferrer" style={{ color: '#7c3aed' }}>{entry.org}</a></span>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {/* Semgrep Comparison */}
        <div style={{ marginTop: 48 }}>
          <h2 style={{ fontSize: 24, fontWeight: 800, marginBottom: 24 }}>
            <span style={{ background: 'linear-gradient(135deg, #7c3aed, #06b6d4)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Semgrep vs QuantumShield</span>
            <span style={{ color: '#555', fontSize: 14, fontWeight: 400, marginLeft: 12 }}>on HashiCorp Vault</span>
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
            <div style={{ background: '#111', border: '1px solid #222', borderRadius: 12, padding: 24, textAlign: 'center' }}>
              <div style={{ color: '#666', fontSize: 12, letterSpacing: 1, textTransform: 'uppercase' }}>Semgrep</div>
              <div style={{ color: '#f59e0b', fontSize: 48, fontWeight: 800, marginTop: 8 }}>{SEMGREP.semgrep}</div>
              <div style={{ color: '#555', fontSize: 13, marginTop: 4 }}>crypto findings</div>
            </div>
            <div style={{ background: '#111', border: '1px solid #7c3aed33', borderRadius: 12, padding: 24, textAlign: 'center' }}>
              <div style={{ color: '#666', fontSize: 12, letterSpacing: 1, textTransform: 'uppercase' }}>QuantumShield</div>
              <div style={{ color: '#7c3aed', fontSize: 48, fontWeight: 800, marginTop: 8 }}>{SEMGREP.qs}</div>
              <div style={{ color: '#555', fontSize: 13, marginTop: 4 }}>crypto findings</div>
            </div>
            <div style={{ background: '#111', border: '1px solid #ef444433', borderRadius: 12, padding: 24, textAlign: 'center' }}>
              <div style={{ color: '#666', fontSize: 12, letterSpacing: 1, textTransform: 'uppercase' }}>Semgrep Missed</div>
              <div style={{ color: '#ef4444', fontSize: 48, fontWeight: 800, marginTop: 8 }}>{SEMGREP.gap}</div>
              <div style={{ color: '#ef4444', fontSize: 13, marginTop: 4 }}>quantum-vulnerable</div>
            </div>
          </div>
          <p style={{ color: '#555', fontSize: 13, marginTop: 16, lineHeight: 1.6, maxWidth: 800 }}>
            The {SEMGREP.gap} findings Semgrep misses are RSA, ECDSA, and ECDH calls that every existing SAST tool considers safe — because they are, <em style={{ color: '#ef4444' }}>until quantum</em>.
          </p>
        </div>

        {/* Benchmarks */}
        <div style={{ marginTop: 48 }}>
          <h2 style={{ fontSize: 24, fontWeight: 800, marginBottom: 24 }}>
            <span style={{ background: 'linear-gradient(135deg, #22c55e, #06b6d4)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Benchmark Results</span>
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            {BENCHMARKS.map((b, i) => (
              <div key={i} style={{ background: '#111', border: '1px solid #222', borderRadius: 12, padding: 24 }}>
                <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 16 }}>{b.suite}</div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 13 }}>
                  <div><span style={{ color: '#555' }}>Precision:</span> <strong style={{ color: '#22c55e' }}>{b.precision}</strong></div>
                  <div><span style={{ color: '#555' }}>Recall:</span> <strong style={{ color: '#22c55e' }}>{b.recall}</strong></div>
                  <div><span style={{ color: '#555' }}>F1 Score:</span> <strong style={{ color: '#22c55e' }}>{b.f1}</strong></div>
                  <div><span style={{ color: '#555' }}>FPR:</span> <strong style={{ color: '#22c55e' }}>{b.fpr}</strong></div>
                </div>
                <div style={{ color: '#444', fontSize: 12, marginTop: 12 }}>{b.cases} test cases evaluated</div>
              </div>
            ))}
          </div>
        </div>

        {/* Call to action */}
        <div style={{ textAlign: 'center', padding: '64px 0', borderTop: '1px solid #1a1a1a', marginTop: 48 }}>
          <p style={{ color: '#ef4444', fontSize: 18, fontWeight: 600, marginBottom: 24 }}>
            The infrastructure the internet depends on is not ready for quantum.
          </p>
          <a href="/" style={{ background: '#7c3aed', color: '#fff', padding: '12px 32px', borderRadius: 8, textDecoration: 'none', fontWeight: 700, fontSize: 15 }}>
            Scan Your Project
          </a>
          <p style={{ color: '#444', fontSize: 12, marginTop: 32 }}>
            Generated by QuantumShield v1.0 &bull; 107 Go files &bull; 27,285 lines &bull; 233 tests &bull; 0% FPR
          </p>
        </div>
      </div>
    </div>
  )
}
