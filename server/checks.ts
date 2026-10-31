import { z } from 'zod'
import { isIP } from 'node:net'
import 'dotenv/config';
export const checkSchema = z.object({
  type: z.enum(['email', 'password', 'domain', 'device', 'wifi', 'assistant']),
  input: z.string().trim().min(1, 'Enter a value to check.').max(500, 'Input is too long.'),
})

export function previewInput(type: string, input: string): string {
  if (type === 'password') return '[redacted — password is never stored]'
  if (type === 'email') {
    const parts = input.split('@')
    return parts.length === 2 ? `${parts[0].slice(0, 1)}***@${parts[1]}` : 'email input'
  }
  return input.length > 70 ? `${input.slice(0, 67)}...` : input
}

export type CheckResultData = {
  status: 'complete' | 'unavailable'
  source: string
  verdict: string
  summary: string
  details: Record<string, any>
  limitations: string
  checkedAt: string
  score?: number
  maxScore?: number
}

function result(status: CheckResultData['status'], source: string, verdict: string, summary: string, details: Record<string, any>, limitations: string, extra: Partial<CheckResultData> = {}): CheckResultData {
  return { status, source, verdict, summary, details, limitations, checkedAt: new Date().toISOString(), ...extra }
}

function parseDomain(input: string): { hostname: string; protocol: string; isIp: boolean } | null {
  try {
    const url = new URL(input.includes('://') ? input : `https://${input}`)
    const hostname = url.hostname.toLowerCase().replace(/\.$/, '')
    if (!hostname || !hostname.includes('.') || /\s/.test(hostname) || url.username || url.password) return null
    if (hostname === 'localhost') return null
    return { hostname, protocol: url.protocol, isIp: isIP(hostname) > 0 }
  } catch {
    return null
  }
}

async function checkVirusTotal(input: string): Promise<CheckResultData> {
  const parsed = parseDomain(input)
  if (!parsed) return result('complete', 'Local input validation', 'invalid-input', 'Enter a valid domain or URL.', {}, 'No external reputation lookup was performed.')
  const key = process.env.VIRUSTOTAL_API_KEY
  if (!key) return result('unavailable', 'VirusTotal', 'unavailable', 'Domain reputation could not be verified because the VirusTotal API key is not configured.', { hostname: parsed.hostname }, 'No reputation result is available. Do not treat this domain as safe.')
  try {
    const endpointType = parsed.isIp ? 'ip_addresses' : 'domains'
    const response = await fetch(`https://www.virustotal.com/api/v3/${endpointType}/${encodeURIComponent(parsed.hostname)}`, {
      headers: { 'x-apikey': key, accept: 'application/json' },
      signal: AbortSignal.timeout(12000),
    })
    if (!response.ok) {
      const status = response.status === 429 ? 'rate-limited' : response.status === 401 || response.status === 403 ? 'invalid-credentials' : `provider-http-${response.status}`
      return result('unavailable', 'VirusTotal', 'unavailable', `VirusTotal could not complete the lookup (${status}).`, { hostname: parsed.hostname, providerStatus: response.status }, 'The domain has not been verified by this request. Retry later or check the API configuration.')
    }
    const payload: any = await response.json()
    const attributes = payload?.data?.attributes
    const stats = attributes?.last_analysis_stats
    if (!attributes || !stats || typeof stats.malicious !== 'number' || typeof stats.suspicious !== 'number') {
      return result('unavailable', 'VirusTotal', 'unavailable', 'VirusTotal returned an incomplete analysis response.', { hostname: parsed.hostname }, 'No reliable verdict could be derived from the provider response.')
    }
    const malicious = stats.malicious
    const suspicious = stats.suspicious
    const verdict = malicious > 0 ? 'malicious-detections' : suspicious > 0 ? 'suspicious-detections' : 'no-detections'
    const summary = malicious > 0
      ? `VirusTotal reports ${malicious} malicious detection(s) for ${parsed.hostname}.`
      : suspicious > 0
        ? `VirusTotal reports ${suspicious} suspicious detection(s) for ${parsed.hostname}.`
        : `VirusTotal currently reports no malicious or suspicious detections for ${parsed.hostname}. This is not a safety guarantee.`
    const signals = [
      { label: `VirusTotal malicious detections: ${malicious}`, found: malicious > 0 },
      { label: `VirusTotal suspicious detections: ${suspicious}`, found: suspicious > 0 },
    ]
    return result('complete', 'VirusTotal', verdict, summary, {
      hostname: parsed.hostname,
      targetType: parsed.isIp ? 'IP address' : 'domain',
      protocolEntered: parsed.protocol,
      stats: {
        malicious,
        suspicious,
        harmless: Number(stats.harmless || 0),
        undetected: Number(stats.undetected || 0),
        timeout: Number(stats.timeout || 0),
      },
      signals,
      reputationDate: attributes.last_analysis_date ? new Date(attributes.last_analysis_date * 1000).toISOString() : null,
    }, 'This is a VirusTotal domain reputation result, not a guarantee that a site is safe. Results may be incomplete or outdated; only the hostname was checked.')
  } catch {
    return result('unavailable', 'VirusTotal', 'unavailable', 'The VirusTotal request failed or timed out.', { hostname: parsed.hostname }, 'No reputation result is available. Check connectivity and try again.')
  }
}

async function checkReoon(input: string): Promise<CheckResultData> {
  const email = input.trim().toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return result(
      'complete',
      'Local input validation',
      'invalid-format',
      'Email format does not appear valid.',
      { email, formatValid: false },
      'Only email syntax was checked. Reoon verification was not performed.'
    );
  }

  const key = process.env.REOON_API_KEY;
  const mode = process.env.REOON_MODE || 'power';

  if (!key) {
    return result(
      'unavailable',
      'Reoon',
      'unavailable',
      'Reoon API key is not configured.',
      {},
      'Add REOON_API_KEY to the backend environment variables.'
    );
  }

  try {
    const url = new URL(
      'https://emailverifier.reoon.com/api/v1/verify'
    );

    url.searchParams.set('email', email);
    url.searchParams.set('key', key);
    url.searchParams.set('mode', mode);

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(90000),
    });

    if (!response.ok) {
      return result(
        'unavailable',
        'Reoon',
        'unavailable',
        `Reoon verification failed with HTTP status ${response.status}.`,
        { httpStatus: response.status },
        'Check the API key, account limits, and network connection.'
      );
    }

    const payload: any = await response.json();

    if (
      !payload ||
      typeof payload !== 'object' ||
      typeof payload.status !== 'string'
    ) {
      return result(
        'unavailable',
        'Reoon',
        'unavailable',
        'Reoon returned an unexpected response.',
        {},
        'The provider response could not be interpreted.'
      );
    }

    const providerStatus = String(payload.status).toLowerCase();
    const subStatus =
      typeof payload.sub_status === 'string'
        ? payload.sub_status
        : '';

    const statusMap: Record<string, { verdict: string; summary: string }> = {
      safe: {
        verdict: 'email-safe',
        summary: 'Reoon classified this email as safe.',
      },
      valid: {
        verdict: 'email-valid',
        summary: 'Reoon classified this email as valid.',
      },
      invalid: {
        verdict: 'email-invalid',
        summary: 'Reoon classified this email as invalid.',
      },
      disposable: {
        verdict: 'email-disposable',
        summary: 'Reoon identified this as a disposable email address.',
      },
      catch_all: {
        verdict: 'email-catch-all',
        summary: 'The email domain appears to accept catch-all addresses.',
      },
      'catch-all': {
        verdict: 'email-catch-all',
        summary: 'The email domain appears to accept catch-all addresses.',
      },
      unknown: {
        verdict: 'email-unknown',
        summary: 'Reoon could not determine the email status.',
      },
    };

    const mapped = statusMap[providerStatus] || {
      verdict: `email-${providerStatus.replace(/[^a-z0-9-]/g, '') || 'unknown'}`,
      summary: `Reoon returned status: ${providerStatus}.`,
    };

    return result(
      'complete',
      'Reoon',
      mapped.verdict,
      mapped.summary,
      {
        email,
        providerStatus,
        subStatus,
        isValidSyntax: payload.is_valid_syntax ?? null,
        isDisposable: payload.is_disposable ?? null,
        isSafeToSend: payload.is_safe_to_send ?? null,
        isDeliverable: payload.is_deliverable ?? null,
        isCatchAll: payload.is_catch_all ?? null,
        isRoleAccount: payload.is_role_account ?? null,
        mxAcceptsMail: payload.mx_accepts_mail ?? null,
        overallScore: payload.overall_score ?? null,
        domain: payload.domain ?? null,
      },
      'The email address was submitted to Reoon. Verification does not guarantee that the mailbox owner is trustworthy.'
    );
  } catch {
    return result(
      'unavailable',
      'Reoon',
      'unavailable',
      'The Reoon verification request failed or timed out.',
      {},
      'Check connectivity and API configuration, then try again.'
    );
  }
}
async function checkGrok(input: string): Promise<CheckResultData> {
  const key = process.env.GROQ_API_KEY;

  if (!key) {
    return result(
      'complete',
      'Local cybersecurity guidance rules',
      'guidance-only',
      'Cybersecurity guidance generated from local rules; Groq API is not configured.',
      {
        topic: input,
        advice: [
          'Do not share one-time passwords or recovery codes.',
          'Open important websites using a saved bookmark or typed address.',
          'Use unique passwords and enable multi-factor authentication.',
          'Keep your operating system and apps up to date.',
          'If a message creates urgency, pause and verify through an official channel.',
        ],
      },
      'Rule-based guidance, not a live AI response or professional incident-response service.'
    );
  }

  const model =
    process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';

  try {
    const response = await fetch(
      'https://api.groq.com/openai/v1/chat/completions',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${key}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: 'system',
              content:
                'You are CyberShield, a cybersecurity awareness assistant for students. Give practical, defensive, lawful advice in simple English. Explain phishing, suspicious SMS messages, online scams, passwords, privacy, and cybersecurity best practices. Never ask for passwords, OTPs, API keys, or other secrets. Never claim that you scanned a device, domain, email, file, or network unless a separate tool actually performed that scan. Explain uncertainty and recommend official channels for high-risk incidents.',
            },
            {
              role: 'user',
              content: input,
            },
          ],
          temperature: 0.4,
          max_tokens: 700,
        }),
        signal: AbortSignal.timeout(60000),
      }
    );

    if (!response.ok) {
      const status =
        response.status === 429
          ? 'rate-limited'
          : response.status === 401 || response.status === 403
            ? 'invalid-credentials'
            : `provider-http-${response.status}`;

      return result(
        'unavailable',
        `Groq AI (${model})`,
        'unavailable',
        `AI guidance could not be generated (${status}).`,
        { providerStatus: response.status },
        'Check the Groq API key, model access, usage limits, and internet connection.'
      );
    }

    const payload: any = await response.json();

    const answer = payload?.choices?.[0]?.message?.content;

    if (typeof answer !== 'string' || !answer.trim()) {
      return result(
        'unavailable',
        `Groq AI (${model})`,
        'unavailable',
        'The AI provider did not return a valid text response.',
        {},
        'Try again and check the provider response if the problem continues.'
      );
    }

    return result(
      'complete',
      `Groq AI (${payload.model || model})`,
      'ai-guidance',
      'AI-assisted cybersecurity guidance generated. This is advice, not a verified security scan.',
      {
        topic: input,
        advice: answer.trim(),
      },
      'AI-generated guidance can be incorrect or incomplete. It does not verify that a device, domain, email, or network is safe. Do not submit passwords, OTPs, or private information.'
    );
  } catch {
    return result(
      'unavailable',
      `Groq AI (${model})`,
      'unavailable',
      'The AI provider request failed or timed out.',
      {},
      'Check your internet connection, API configuration, and try again.'
    );
  }
}


function localCheck(type: string, input: string): CheckResultData {
  if (type === 'password') {
    const checks = [
      { label: 'At least 12 characters', passed: input.length >= 12 },
      { label: 'Contains uppercase letter', passed: /[A-Z]/.test(input) },
      { label: 'Contains lowercase letter', passed: /[a-z]/.test(input) },
      { label: 'Contains a number', passed: /\d/.test(input) },
      { label: 'Contains a symbol', passed: /[^A-Za-z0-9]/.test(input) },
      { label: 'Avoids common obvious patterns', passed: !/(password|qwerty|123456|letmein|admin)/i.test(input) && !/(.)\1{3,}/.test(input) },
    ]
    const score = checks.filter(c => c.passed).length
    return result('complete', 'Local password heuristic', score >= 5 ? 'good-practices' : 'improve', `${score} of ${checks.length} basic password checks passed.`, {
      checks,
      advice: score >= 5 ? 'Use a unique password and a password manager. This heuristic cannot prove that the password has never been exposed.' : 'Use a longer, unique passphrase and avoid predictable words or repeated characters.',
    }, 'Local heuristic only. The password is not sent to an external API, stored in history, or included in logs.', { score, maxScore: checks.length })
  }

  if (type === 'device') {
    return result('complete', 'Local guidance checklist', 'guidance-only', 'Device security guidance generated; the browser did not scan your device.', {
      recommendations: ['Install operating-system and app updates', 'Use a screen lock and device encryption', 'Review app permissions', 'Enable backups', 'Install apps only from trusted stores'],
    }, 'A standard website cannot inspect all device settings. These are recommendations, not a device scan.')
  }

  if (type === 'wifi') {
    return result('complete', 'Local guidance checklist', 'guidance-only', 'Wi-Fi safety guidance generated; the current network was not scanned.', {
      recommendations: ['Prefer WPA2-AES or WPA3 on your router', 'Change default router administrator credentials', 'Avoid sensitive activity on unknown public Wi-Fi', 'Keep router firmware updated', 'Disable WPS if it is not needed'],
    }, 'Browser code cannot reliably inspect your current Wi-Fi encryption or router. These are recommendations, not a network scan.')
  }

  return result('complete', 'Local cybersecurity guidance rules', 'guidance-only', 'Cybersecurity guidance generated from local rules; no AI API was called.', {
    topic: input,
    advice: [
      'Do not share one-time passwords or recovery codes.',
      'Open important websites using a saved bookmark or typed address.',
      'Use unique passwords and enable multi-factor authentication.',
      'Keep your operating system and apps up to date.',
      'If a message creates urgency, pause and verify through an official channel.',
    ],
  }, 'Rule-based guidance, not an AI model or professional incident-response service.')
}

export async function runCheck(type: string, input: string): Promise<CheckResultData> {
  if (type === 'domain') return checkVirusTotal(input)
  if (type === 'email') return checkReoon(input)
  if (type === 'assistant') return checkGrok(input)
  return localCheck(type, input)
}
