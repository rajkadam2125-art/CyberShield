import 'dotenv/config'
import express, { type Request, type Response, type NextFunction } from 'express'
import cors from 'cors'
import helmet from 'helmet'
import crypto from 'node:crypto'
import rateLimit from 'express-rate-limit'
import { checkSchema, previewInput, runCheck } from './checks.js'
import { addScan, clearScans, getScans, type ScanRecord } from './store.js'
import { adminAuth, firebaseAdminConfigured, firestore } from './firebase.js'

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

type AuthenticatedRequest = Request & { user?: { uid: string; email?: string } }
const app = express()
const PORT = Number(process.env.PORT || 4000)
const clientOrigin = process.env.CLIENT_ORIGIN || 'http://localhost:5173'

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }))
app.use(cors({ origin: clientOrigin }))
app.use(express.json({ limit: '20kb' }))
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false }))

async function requireFirebaseUser(req: Request, res: Response, next: NextFunction) {
  if (!adminAuth || !firebaseAdminConfigured) {
    return res.status(503).json({ error: 'Firebase Admin is not configured on the backend. Configure GOOGLE_APPLICATION_CREDENTIALS or FIREBASE_SERVICE_ACCOUNT_JSON.' })
  }
  const header = req.header('authorization') || ''
  const match = header.match(/^Bearer\s+(.+)$/i)
  if (!match) return res.status(401).json({ error: 'Sign in is required.' })
  try {
    const decoded = await adminAuth.verifyIdToken(match[1])
    ;(req as AuthenticatedRequest).user = { uid: decoded.uid, email: decoded.email }
    return next()
  } catch {
    return res.status(401).json({ error: 'Your session is invalid or expired. Please sign in again.' })
  }
}

function userId(req: Request): string {
  return (req as AuthenticatedRequest).user!.uid
}

function firestoreUnavailable(res: Response, error: unknown) {
  if (error instanceof Error && error.message === 'FIRESTORE_NOT_CONFIGURED') {
    return res.status(503).json({ error: 'Firestore is not configured. Complete the server Firebase setup before using saved data.' })
  }
  console.error('API operation failed:', error instanceof Error ? error.message : 'Unknown error')
  return res.status(500).json({ error: 'The operation could not be completed. Check backend logs for configuration details.' })
}

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'CyberShield API',
    mode: process.env.NODE_ENV || 'development',
    authentication: firebaseAdminConfigured ? 'firebase-admin-configured' : 'firebase-admin-not-configured',
    database: firestore ? 'firestore-configured' : 'firestore-not-configured',
    integrations: {
      virusTotal: Boolean(process.env.VIRUSTOTAL_API_KEY),
      zeroBounce: Boolean(process.env.ZEROBOUNCE_API_KEY),
      grok: Boolean(process.env.XAI_API_KEY),
    },
    timestamp: new Date().toISOString(),
  })
})

app.get('/api/summary', requireFirebaseUser, async (req, res) => {
  try {
    const scans = await getScans(userId(req))
    const byType = scans.reduce<Record<string, number>>((acc, scan) => {
      acc[scan.type] = (acc[scan.type] || 0) + 1
      return acc
    }, {})
    return res.json({
      totalChecks: scans.length,
      risksToReview: scans.filter(s => ['improve', 'invalid-format', 'review-needed', 'malicious-detections', 'suspicious-detections', 'email-invalid', 'email-catch-all', 'unavailable'].includes(String(s.details.verdict))).length,
      byType,
      recentScans: scans.slice(0, 6).map(s => ({ id: s.id, type: s.type, inputPreview: s.inputPreview, summary: s.summary, createdAt: s.createdAt, status: s.status })),
    })
  } catch (error) { return firestoreUnavailable(res, error) }
})

app.get('/api/scans', requireFirebaseUser, async (req, res) => {
  try {
    return res.json({ scans: await getScans(userId(req)) })
  } catch (error) { return firestoreUnavailable(res, error) }
})
app.get('/api/wifi/scan', requireFirebaseUser, async (_req, res) => {
  try {
    const { stdout: interfaceOutput } = await execFileAsync(
      'netsh',
      ['wlan', 'show', 'interfaces'],
      { timeout: 10000, windowsHide: true }
    )

    const { stdout: networksOutput } = await execFileAsync(
      'netsh',
      ['wlan', 'show', 'networks', 'mode=bssid'],
      { timeout: 15000, windowsHide: true }
    )

    const getValue = (text: string, label: string) => {
      const line = text.split(/\r?\n/).find(row =>
        new RegExp(`^\\s*${label}\\s*:` , 'i').test(row)
      )
      return line?.split(':').slice(1).join(':').trim() || 'Unknown'
    }

    const connected =
      /State\s*:\s*connected/i.test(interfaceOutput)

    const connectedWifi = connected
      ? {
          ssid: getValue(interfaceOutput, 'SSID'),
          authentication: getValue(interfaceOutput, 'Authentication'),
          encryption: getValue(interfaceOutput, 'Cipher'),
          signal: getValue(interfaceOutput, 'Signal'),
          channel: getValue(interfaceOutput, 'Channel'),
          radioType: getValue(interfaceOutput, 'Radio type'),
          band: getValue(interfaceOutput, 'Band'),
          receiveRate: getValue(interfaceOutput, 'Receive rate'),
          transmitRate: getValue(interfaceOutput, 'Transmit rate'),
        }
      : null

    const networks = networksOutput
      .split(/(?=^\s*SSID\s+\d+\s*:)/m)
      .filter(block => /^\s*SSID\s+\d+\s*:/m.test(block))
      .map(block => ({
        ssid: getValue(block, 'SSID\\s+\\d+'),
        authentication: getValue(block, 'Authentication'),
        encryption: getValue(block, 'Encryption'),
        signal: getValue(block, 'Signal'),
        channel: getValue(block, 'Channel'),
      }))

    const securityWarnings: string[] = []

    if (!connected) {
      securityWarnings.push('No Wi-Fi network is currently connected.')
    } else if (/open|^none$/i.test(connectedWifi?.authentication || '')) {
      securityWarnings.push('The connected network may not use authentication.')
    } else if (/WEP|TKIP/i.test(
      `${connectedWifi?.authentication} ${connectedWifi?.encryption}`
    )) {
      securityWarnings.push('Legacy Wi-Fi security detected. Prefer WPA2-AES or WPA3.')
    } else {
      securityWarnings.push(
        'Check router settings and use WPA2-AES or WPA3 with a strong password.'
      )
    }

    return res.json({
      ok: true,
      source: 'Windows netsh WLAN',
      connectedWifi,
      networks,
      securityWarnings,
      scannedAt: new Date().toISOString(),
      limitations:
        'Scans networks visible to this Windows computer. Signal and security information depends on what Windows reports.',
    })
  } catch (error) {
    console.error('Wi-Fi scan failed:', error instanceof Error ? error.message : 'Unknown error')
    return res.status(500).json({
      error: 'Wi-Fi scan failed. Make sure this backend is running on Windows with a working WLAN adapter.'
    })
  }
})
app.post('/api/check', requireFirebaseUser, async (req, res) => {
  const parsed = checkSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid request.' })
  const { type, input } = parsed.data

  try {
    const result = await runCheck(type, input)
    const record: ScanRecord = {
      id: crypto.randomUUID(),
      userId: userId(req),
      type,
      inputPreview: previewInput(type, input),
      status: result.status,
      summary: result.summary,
      createdAt: result.checkedAt,
      details: {
        verdict: result.verdict,
        source: result.source,
        details: result.details,
        limitations: result.limitations,
        checkedAt: result.checkedAt,
        ...(type === 'password' ? { score: result.score, maxScore: result.maxScore } : {}),
      },
    }
    await addScan(record)
    return res.json({
      scan: { id: record.id, type, inputPreview: record.inputPreview, status: record.status, summary: record.summary, createdAt: record.createdAt },
      result,
    })
  } catch (error) { return firestoreUnavailable(res, error) }
})

app.delete('/api/scans', requireFirebaseUser, async (req, res) => {
  try {
    await clearScans(userId(req))
    return res.json({ ok: true, message: 'Your scan history has been cleared.' })
  } catch (error) { return firestoreUnavailable(res, error) }
})

app.use((_req, res) => res.status(404).json({ error: 'Endpoint not found.' }))
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  console.error('API error:', err instanceof Error ? err.message : 'Unknown error')
  res.status(500).json({ error: 'Unexpected server error.' })
})

app.listen(PORT, () => {
  console.log(`CyberShield API listening on http://localhost:${PORT}`)
  if (!firebaseAdminConfigured) console.warn('Firebase Admin is not configured. Authenticated API endpoints will return 503 until configured.')
})
