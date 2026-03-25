const API_BASE = import.meta.env.VITE_API_URL || 'https://artistic-consideration-production-4acd.up.railway.app';

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function fetchLatestScan() {
  const res = await fetch(`${API_BASE}/api/v1/monitor/latest`);
  return res.json();
}

export async function fetchMonitorStatus() {
  const res = await fetch(`${API_BASE}/api/v1/monitor/status`);
  return res.json();
}

export async function fetchMigrations() {
  const res = await fetch(`${API_BASE}/api/v1/migrations`);
  return res.json();
}

export async function fetchAlgorithms() {
  const res = await fetch(`${API_BASE}/api/v1/algorithms`);
  return res.json();
}

export async function triggerScan(path: string = '.') {
  const res = await fetch(`${API_BASE}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  });
  return res.json();
}
