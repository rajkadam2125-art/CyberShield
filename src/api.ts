export type CheckType = 'email' | 'password' | 'domain' | 'device' | 'wifi' | 'assistant'
export type CheckTool = { type: CheckType; title: string; description: string; placeholder: string; action: string; color: string }

export const tools: CheckTool[] = [
  { type: 'email', title: 'Email Safety', description: 'Validate an email address using ZeroBounce when configured.', placeholder: 'you@example.com', action: 'Check email', color: 'blue' },
  { type: 'password', title: 'Password Check', description: 'Check basic password-strength characteristics locally.', placeholder: 'Enter a test password', action: 'Check password', color: 'teal' },
  { type: 'domain', title: 'Domain Safety', description: 'Check domain reputation with VirusTotal when configured.', placeholder: 'https://example.com', action: 'Check domain', color: 'purple' },
 
  { type: 'wifi', title: 'Wi-Fi Security', description: 'Review common home and public Wi-Fi risks.', placeholder: 'e.g. home Wi-Fi', action: 'Check network', color: 'blue' },
  { type: 'assistant', title: 'Cybersecurity Assistant', description: 'Get AI-assisted guidance with Grok when configured, or local guidance otherwise.', placeholder: 'e.g. suspicious SMS link', action: 'Get guidance', color: 'orange' },
]

export type Scan = { id: string; type: CheckType; inputPreview: string; status: string; summary: string; createdAt: string; details: Record<string, any> }
export type CheckResult = { scan: Scan; result: { status: 'complete' | 'unavailable'; source: string; verdict: string; summary: string; details: Record<string, any>; limitations: string; checkedAt: string; score?: number; maxScore?: number } }

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const { auth } = await import('./firebase')
  const token = await auth?.currentUser?.getIdToken()
  const response = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(options?.headers || {}) },
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`)
  return data as T
}

export const api = {
  health: () => request<{ ok: boolean; service: string; mode: string }>('/api/health'),
  summary: () => request<{ totalChecks: number; risksToReview: number; byType: Record<string, number>; recentScans: Scan[] }>('/api/summary'),
  scans: () => request<{ scans: Scan[] }>('/api/scans'),
  check: (type: CheckType, input: string) => request<CheckResult>('/api/check', { method: 'POST', body: JSON.stringify({ type, input }) }),
  clearScans: () => request<{ ok: boolean; message: string }>('/api/scans', { method: 'DELETE' }),
}

export type WifiScanResult = {
  ok: boolean
  source: string
  connectedWifi: {
    ssid: string
    authentication: string
    encryption: string
    signal: string
    channel: string
    radioType: string
    band: string
    receiveRate: string
    transmitRate: string
  } | null
  networks: Array<{
    ssid: string
    authentication: string
    encryption: string
    signal: string
    channel: string
  }>
  securityWarnings: string[]
  scannedAt: string
  limitations: string
}

export const scanWifi = async (): Promise<WifiScanResult> => {
  return request<WifiScanResult>('/api/wifi/scan')
}

