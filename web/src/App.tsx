import { useState, useEffect, useCallback } from 'react'
import {
  fetchHealth,
  fetchLatestScan,
  fetchMonitorStatus,
  fetchMigrations,
  fetchAlgorithms,
} from './lib/api'

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface Finding {
  severity: string
  algorithm: string
  location: string
  quantum_threat: string
  replacement: string
}

interface ScanData {
  quantum_readiness_score: number
  total_findings: number
  findings_by_severity: Record<string, number>
  findings: Finding[]
  scan_path?: string
  scan_timestamp?: string
}

interface MonitorData {
  scan_count: number
  uptime_seconds: number
  last_scan: string
  status: string
}

interface Migration {
  current: string
  replacement: string
  hybrid_option: string
  priority: string
  category: string
}

interface Algorithm {
  name: string
  quantum_safe: boolean
  category: string
  key_size?: number
  threat_level?: string
}

/* ------------------------------------------------------------------ */
/*  Leaderboard & Benchmark data (static)                              */
/* ------------------------------------------------------------------ */

const LEADERBOARD = [
  { project: 'Boulder (Let\'s Encrypt)', score: 0, findings: 414 },
  { project: 'Traefik', score: 3, findings: 200 },
  { project: 'etcd', score: 5, findings: 46 },
  { project: 'HashiCorp Vault', score: 7, findings: 527 },
  { project: 'Kubernetes', score: 10, findings: 453 },
  { project: 'mkcert', score: 18, findings: 13 },
  { project: 'Django', score: 60, findings: 7 },
]

const BENCHMARKS = [
  {
    name: 'NIST Juliet CWE-327/328',
    precision: '100%',
    recall: '94.4%',
    f1: '97.1%',
    fpr: null,
  },
  {
    name: 'OWASP Benchmark v1.2',
    precision: '100%',
    recall: '84.6%',
    f1: '91.6%',
    fpr: '0%',
  },
]

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function severityColor(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical': return '#ef4444'
    case 'high': return '#f59e0b'
    case 'medium': return '#eab308'
    case 'low': return '#06b6d4'
    default: return '#94a3b8'
  }
}

function severityBg(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical': return 'rgba(239,68,68,0.15)'
    case 'high': return 'rgba(245,158,11,0.15)'
    case 'medium': return 'rgba(234,179,8,0.15)'
    case 'low': return 'rgba(6,182,212,0.15)'
    default: return 'rgba(148,163,184,0.15)'
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return '#10b981'
  if (score >= 50) return '#eab308'
  if (score >= 20) return '#f59e0b'
  return '#ef4444'
}

function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  return `${h}h ${m}m ${s}s`
}

/* ------------------------------------------------------------------ */
/*  Spinner                                                            */
/* ------------------------------------------------------------------ */

function Spinner() {
  return (
    <div className="flex items-center justify-center py-12">
      <div
        className="w-8 h-8 rounded-full border-2 border-transparent animate-spin"
        style={{
          borderTopColor: '#7c3aed',
          borderRightColor: '#7c3aed',
        }}
      />
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Readiness Gauge (SVG arc)                                          */
/* ------------------------------------------------------------------ */

function ReadinessGauge({ score }: { score: number }) {
  const color = scoreColor(score)
  const radius = 80
  const stroke = 10
  const circumference = 2 * Math.PI * radius
  const progress = (score / 100) * circumference

  return (
    <div className="flex flex-col items-center">
      <svg width="200" height="200" viewBox="0 0 200 200">
        {/* background ring */}
        <circle
          cx="100" cy="100" r={radius}
          fill="none" stroke="#252238"
          strokeWidth={stroke}
        />
        {/* progress arc */}
        <circle
          cx="100" cy="100" r={radius}
          fill="none" stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference - progress}`}
          strokeDashoffset={circumference * 0.25}
          style={{ transition: 'stroke-dasharray 1s ease' }}
        />
        {/* score text */}
        <text
          x="100" y="92"
          textAnchor="middle"
          fill={color}
          fontSize="48"
          fontWeight="800"
          fontFamily="Inter, system-ui, sans-serif"
        >
          {score}
        </text>
        <text
          x="100" y="120"
          textAnchor="middle"
          fill="#94a3b8"
          fontSize="14"
          fontFamily="Inter, system-ui, sans-serif"
        >
          / 100
        </text>
      </svg>
      <span className="mt-2 text-sm" style={{ color }}>
        {score >= 80 ? 'Quantum Ready' :
         score >= 50 ? 'Partially Ready' :
         score >= 20 ? 'At Risk' :
         'Critical Risk'}
      </span>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  App                                                                */
/* ------------------------------------------------------------------ */

function App() {
  const [health, setHealth] = useState<{ status: string } | null>(null)
  const [scan, setScan] = useState<ScanData | null>(null)
  const [monitor, setMonitor] = useState<MonitorData | null>(null)
  const [migrations, setMigrations] = useState<Migration[]>([])
  const [algorithms, setAlgorithms] = useState<Algorithm[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [sortField, setSortField] = useState<keyof Finding>('severity')
  const [sortAsc, setSortAsc] = useState(true)

  const loadData = useCallback(async () => {
    try {
      const [h, s, m, mig, alg] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchLatestScan().catch(() => null),
        fetchMonitorStatus().catch(() => null),
        fetchMigrations().catch(() => []),
        fetchAlgorithms().catch(() => []),
      ])
      setHealth(h)
      setScan(s)
      setMonitor(m)
      if (Array.isArray(mig)) setMigrations(mig)
      else if (mig?.migrations) setMigrations(mig.migrations)
      if (Array.isArray(alg)) setAlgorithms(alg)
      else if (alg?.algorithms) setAlgorithms(alg.algorithms)
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 30_000)
    return () => clearInterval(interval)
  }, [loadData])

  /* ---- Sorting ---- */
  const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

  const sortedFindings = [...(scan?.findings ?? [])].sort((a, b) => {
    if (sortField === 'severity') {
      const diff = (sevOrder[a.severity.toLowerCase()] ?? 9) - (sevOrder[b.severity.toLowerCase()] ?? 9)
      return sortAsc ? diff : -diff
    }
    const av = a[sortField] ?? ''
    const bv = b[sortField] ?? ''
    return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av)
  })

  const handleSort = (field: keyof Finding) => {
    if (sortField === field) setSortAsc(!sortAsc)
    else { setSortField(field); setSortAsc(true) }
  }

  const sortIcon = (field: keyof Finding) =>
    sortField === field ? (sortAsc ? ' \u25B2' : ' \u25BC') : ''

  /* ---- Computed ---- */
  const readinessScore = scan?.quantum_readiness_score ?? 0
  const isOnline = health?.status === 'healthy'
  const severities = scan?.findings_by_severity ?? {}

  const maxSev = Math.max(...Object.values(severities), 1)

  /* ---- Render ---- */
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: '#0f0d1a' }}>
        <div className="text-center">
          <div
            className="mx-auto mb-4 w-12 h-12 rounded-full border-2 border-transparent animate-spin"
            style={{ borderTopColor: '#7c3aed', borderRightColor: '#7c3aed' }}
          />
          <p className="text-slate-400">Loading QuantumShield Dashboard...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen" style={{ background: '#0f0d1a' }}>
      {/* ====== HEADER ====== */}
      <header
        className="sticky top-0 z-50 border-b px-6 py-4 flex items-center justify-between"
        style={{ background: 'rgba(15,13,26,0.85)', backdropFilter: 'blur(12px)', borderColor: '#252238' }}
      >
        <div className="flex items-center gap-3">
          {/* Shield icon */}
          <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
            <path
              d="M16 2L4 8v8c0 7.18 5.12 13.88 12 16 6.88-2.12 12-8.82 12-16V8L16 2z"
              fill="#7c3aed" opacity="0.2"
            />
            <path
              d="M16 2L4 8v8c0 7.18 5.12 13.88 12 16 6.88-2.12 12-8.82 12-16V8L16 2z"
              stroke="#7c3aed" strokeWidth="2" fill="none"
            />
            <path d="M12 16l3 3 5-6" stroke="#a78bfa" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div>
            <h1 className="text-xl font-bold tracking-tight" style={{ color: '#e2e8f0' }}>
              QuantumShield
            </h1>
            <span className="text-xs" style={{ color: '#64748b' }}>
              Post-Quantum Cryptography Scanner
            </span>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-xs px-2 py-1 rounded font-mono" style={{ background: '#252238', color: '#94a3b8' }}>
            v1.0.0
          </span>
          <div className="flex items-center gap-2">
            <div
              className="w-2.5 h-2.5 rounded-full"
              style={{ background: isOnline ? '#10b981' : '#ef4444', boxShadow: `0 0 8px ${isOnline ? '#10b98166' : '#ef444466'}` }}
            />
            <span className="text-xs" style={{ color: isOnline ? '#10b981' : '#ef4444' }}>
              {isOnline ? 'Online' : 'Offline'}
            </span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">

        {error && (
          <div className="rounded-lg border px-4 py-3 text-sm" style={{ background: 'rgba(239,68,68,0.1)', borderColor: '#ef4444', color: '#fca5a5' }}>
            API Error: {error}
          </div>
        )}

        {/* ====== TOP ROW: Score + Findings Summary ====== */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Readiness Score */}
          <div
            className="rounded-xl border p-6 flex flex-col items-center justify-center"
            style={{ background: '#1e1b2e', borderColor: '#252238' }}
          >
            <h2 className="text-sm font-semibold uppercase tracking-wider mb-4" style={{ color: '#94a3b8' }}>
              Quantum Readiness Score
            </h2>
            <ReadinessGauge score={readinessScore} />
            {scan?.total_findings !== undefined && (
              <p className="mt-4 text-xs" style={{ color: '#64748b' }}>
                {scan.total_findings} total findings detected
              </p>
            )}
          </div>

          {/* Findings Summary Cards */}
          <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-4">
            {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
              const count = severities[sev] ?? 0
              return (
                <div
                  key={sev}
                  className="rounded-xl border p-5 flex flex-col"
                  style={{ background: '#1e1b2e', borderColor: '#252238' }}
                >
                  <span
                    className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider mb-3"
                  >
                    <span
                      className="w-2 h-2 rounded-full"
                      style={{ background: severityColor(sev) }}
                    />
                    <span style={{ color: severityColor(sev) }}>{sev}</span>
                  </span>
                  <span
                    className="text-3xl font-extrabold"
                    style={{ color: severityColor(sev) }}
                  >
                    {count}
                  </span>
                  <span className="mt-1 text-xs" style={{ color: '#64748b' }}>
                    findings
                  </span>
                </div>
              )
            })}
          </div>
        </div>

        {/* ====== SEVERITY BREAKDOWN BAR CHART ====== */}
        <div
          className="rounded-xl border p-6"
          style={{ background: '#1e1b2e', borderColor: '#252238' }}
        >
          <h2 className="text-sm font-semibold uppercase tracking-wider mb-6" style={{ color: '#94a3b8' }}>
            Severity Breakdown
          </h2>
          <div className="space-y-4">
            {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
              const count = severities[sev] ?? 0
              const pct = maxSev > 0 ? (count / maxSev) * 100 : 0
              return (
                <div key={sev} className="flex items-center gap-4">
                  <span
                    className="w-20 text-xs font-semibold uppercase text-right"
                    style={{ color: severityColor(sev) }}
                  >
                    {sev}
                  </span>
                  <div className="flex-1 h-6 rounded-full overflow-hidden" style={{ background: '#252238' }}>
                    <div
                      className="h-full rounded-full flex items-center justify-end pr-2"
                      style={{
                        width: `${Math.max(pct, 2)}%`,
                        background: severityColor(sev),
                        transition: 'width 1s ease',
                      }}
                    >
                      {count > 0 && (
                        <span className="text-xs font-bold" style={{ color: '#0f0d1a' }}>
                          {count}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* ====== FINDINGS TABLE ====== */}
        <div
          className="rounded-xl border overflow-hidden"
          style={{ background: '#1e1b2e', borderColor: '#252238' }}
        >
          <div className="px-6 py-4 border-b" style={{ borderColor: '#252238' }}>
            <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
              Findings ({sortedFindings.length})
            </h2>
          </div>
          {sortedFindings.length === 0 ? (
            <div className="px-6 py-12 text-center text-sm" style={{ color: '#64748b' }}>
              No findings to display. Run a scan to get results.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ background: '#252238' }}>
                    {([
                      ['severity', 'Severity'],
                      ['algorithm', 'Algorithm'],
                      ['location', 'Location'],
                      ['quantum_threat', 'Threat'],
                      ['replacement', 'Replacement'],
                    ] as [keyof Finding, string][]).map(([field, label]) => (
                      <th
                        key={field}
                        onClick={() => handleSort(field)}
                        className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider cursor-pointer select-none"
                        style={{ color: '#94a3b8' }}
                      >
                        {label}{sortIcon(field)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {sortedFindings.map((f, i) => (
                    <tr
                      key={i}
                      className="border-t"
                      style={{ borderColor: '#252238' }}
                    >
                      <td className="px-4 py-3">
                        <span
                          className="inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase"
                          style={{ background: severityBg(f.severity), color: severityColor(f.severity) }}
                        >
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs" style={{ color: '#e2e8f0' }}>
                        {f.algorithm}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs max-w-xs truncate" style={{ color: '#94a3b8' }}>
                        {f.location}
                      </td>
                      <td className="px-4 py-3 text-xs" style={{ color: '#fbbf24' }}>
                        {f.quantum_threat}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs" style={{ color: '#10b981' }}>
                        {f.replacement}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ====== MIGRATION MAP ====== */}
        <div
          className="rounded-xl border overflow-hidden"
          style={{ background: '#1e1b2e', borderColor: '#252238' }}
        >
          <div className="px-6 py-4 border-b" style={{ borderColor: '#252238' }}>
            <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
              Migration Map ({migrations.length} paths)
            </h2>
          </div>
          {migrations.length === 0 ? (
            <Spinner />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ background: '#252238' }}>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
                      Current
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
                      Replacement
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
                      Hybrid Option
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
                      Priority
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
                      Category
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {migrations.map((m, i) => (
                    <tr
                      key={i}
                      className="border-t"
                      style={{ borderColor: '#252238' }}
                    >
                      <td className="px-4 py-3 font-mono text-xs" style={{ color: '#ef4444' }}>
                        {m.current}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs" style={{ color: '#10b981' }}>
                        {m.replacement}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs" style={{ color: '#a78bfa' }}>
                        {m.hybrid_option}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className="inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase"
                          style={{
                            background: severityBg(m.priority),
                            color: severityColor(m.priority),
                          }}
                        >
                          {m.priority}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs" style={{ color: '#94a3b8' }}>
                        {m.category}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ====== BOTTOM ROW: Monitor + Benchmarks ====== */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Monitor Status */}
          <div
            className="rounded-xl border p-6"
            style={{ background: '#1e1b2e', borderColor: '#252238' }}
          >
            <h2 className="text-sm font-semibold uppercase tracking-wider mb-6" style={{ color: '#94a3b8' }}>
              Monitor Status
            </h2>
            {monitor ? (
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
                    Status
                  </p>
                  <p className="text-lg font-bold" style={{ color: '#10b981' }}>
                    {monitor.status}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
                    Scan Count
                  </p>
                  <p className="text-lg font-bold" style={{ color: '#e2e8f0' }}>
                    {monitor.scan_count}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
                    Uptime
                  </p>
                  <p className="text-lg font-bold font-mono" style={{ color: '#e2e8f0' }}>
                    {formatUptime(monitor.uptime_seconds)}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
                    Last Scan
                  </p>
                  <p className="text-sm font-mono" style={{ color: '#94a3b8' }}>
                    {monitor.last_scan ? new Date(monitor.last_scan).toLocaleString() : 'N/A'}
                  </p>
                </div>
              </div>
            ) : (
              <Spinner />
            )}
          </div>

          {/* Algorithms */}
          <div
            className="rounded-xl border p-6"
            style={{ background: '#1e1b2e', borderColor: '#252238' }}
          >
            <h2 className="text-sm font-semibold uppercase tracking-wider mb-6" style={{ color: '#94a3b8' }}>
              Algorithm Database ({algorithms.length})
            </h2>
            {algorithms.length === 0 ? (
              <Spinner />
            ) : (
              <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto pr-2">
                {algorithms.map((a, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs"
                    style={{ background: '#252238' }}
                  >
                    <span
                      className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                      style={{ background: a.quantum_safe ? '#10b981' : '#ef4444' }}
                    />
                    <span className="font-mono truncate" style={{ color: a.quantum_safe ? '#10b981' : '#e2e8f0' }}>
                      {a.name}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ====== BENCHMARK RESULTS ====== */}
        <div
          className="rounded-xl border p-6"
          style={{ background: '#1e1b2e', borderColor: '#252238' }}
        >
          <h2 className="text-sm font-semibold uppercase tracking-wider mb-6" style={{ color: '#94a3b8' }}>
            Benchmark Results
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            {BENCHMARKS.map((b) => (
              <div
                key={b.name}
                className="rounded-lg border p-5"
                style={{ background: '#252238', borderColor: '#302d45' }}
              >
                <h3 className="text-sm font-semibold mb-4" style={{ color: '#e2e8f0' }}>
                  {b.name}
                </h3>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
                      Precision
                    </p>
                    <p className="text-xl font-bold" style={{ color: '#10b981' }}>
                      {b.precision}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
                      Recall
                    </p>
                    <p className="text-xl font-bold" style={{ color: '#a78bfa' }}>
                      {b.recall}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
                      F1 Score
                    </p>
                    <p className="text-xl font-bold" style={{ color: '#7c3aed' }}>
                      {b.f1}
                    </p>
                  </div>
                </div>
                {b.fpr !== null && (
                  <div className="mt-4 pt-4 border-t" style={{ borderColor: '#302d45' }}>
                    <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
                      False Positive Rate
                    </p>
                    <p className="text-xl font-bold" style={{ color: '#10b981' }}>
                      {b.fpr}
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>
          {/* Semgrep comparison */}
          <div
            className="rounded-lg border p-5"
            style={{ background: '#252238', borderColor: '#302d45' }}
          >
            <h3 className="text-sm font-semibold mb-3" style={{ color: '#e2e8f0' }}>
              vs. Semgrep on HashiCorp Vault
            </h3>
            <div className="flex flex-wrap gap-8 items-center">
              <div>
                <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
                  QuantumShield
                </p>
                <p className="text-2xl font-bold" style={{ color: '#7c3aed' }}>
                  527
                  <span className="text-xs font-normal ml-1" style={{ color: '#94a3b8' }}>findings</span>
                </p>
              </div>
              <div className="text-2xl font-bold" style={{ color: '#64748b' }}>vs</div>
              <div>
                <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
                  Semgrep
                </p>
                <p className="text-2xl font-bold" style={{ color: '#94a3b8' }}>
                  66
                  <span className="text-xs font-normal ml-1" style={{ color: '#94a3b8' }}>findings</span>
                </p>
              </div>
              <div
                className="flex-1 min-w-fit rounded-lg px-4 py-3"
                style={{ background: 'rgba(239,68,68,0.1)' }}
              >
                <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>
                  408 quantum-vulnerable findings missed by Semgrep
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* ====== LEADERBOARD ====== */}
        <div
          className="rounded-xl border overflow-hidden"
          style={{ background: '#1e1b2e', borderColor: '#252238' }}
        >
          <div className="px-6 py-4 border-b" style={{ borderColor: '#252238' }}>
            <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
              Quantum Readiness Leaderboard
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: '#252238' }}>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
                    Rank
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
                    Project
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
                    Score
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
                    Readiness
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#94a3b8' }}>
                    Findings
                  </th>
                </tr>
              </thead>
              <tbody>
                {LEADERBOARD.map((entry, i) => {
                  const color = scoreColor(entry.score)
                  const barWidth = `${entry.score}%`
                  return (
                    <tr
                      key={entry.project}
                      className="border-t"
                      style={{ borderColor: '#252238' }}
                    >
                      <td className="px-6 py-4">
                        <span
                          className="inline-flex items-center justify-center w-7 h-7 rounded-full text-xs font-bold"
                          style={{ background: '#252238', color: '#94a3b8' }}
                        >
                          {i + 1}
                        </span>
                      </td>
                      <td className="px-6 py-4 font-semibold" style={{ color: '#e2e8f0' }}>
                        {entry.project}
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-lg font-bold" style={{ color }}>
                          {entry.score}
                        </span>
                        <span className="text-xs" style={{ color: '#64748b' }}>
                          /100
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="w-32 h-2 rounded-full overflow-hidden" style={{ background: '#252238' }}>
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: barWidth,
                              minWidth: '4px',
                              background: color,
                              transition: 'width 1s ease',
                            }}
                          />
                        </div>
                      </td>
                      <td className="px-6 py-4 font-mono text-xs" style={{ color: '#94a3b8' }}>
                        {entry.findings}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* ====== FOOTER ====== */}
        <footer className="text-center py-8 border-t" style={{ borderColor: '#252238' }}>
          <p className="text-xs" style={{ color: '#64748b' }}>
            QuantumShield v1.0.0 &middot; Post-Quantum Cryptography Scanner &middot; Auto-refreshes every 30s
          </p>
        </footer>
      </main>
    </div>
  )
}

export default App
