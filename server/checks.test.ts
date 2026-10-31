import test from 'node:test'
import assert from 'node:assert/strict'
import { checkSchema, previewInput, runCheck } from './checks.js'
import 'dotenv/config';
test('password analysis is local and never returns the password text', async () => {
  const password = 'Sample-Strong-Password-902!'
  const result = await runCheck('password', password)
  assert.equal(result.status, 'complete')
  assert.equal(result.source, 'Local password heuristic')
  assert.ok(result.score !== undefined)
  assert.ok(!JSON.stringify(result).includes(password))
  assert.equal(previewInput('password', password), '[redacted — password is never stored]')
})


test('invalid email syntax is rejected without calling Reoon', async () => {
  const result = await runCheck('email', 'not-an-email')
  assert.equal(result.status, 'complete')
  assert.equal(result.verdict, 'invalid-format')
  assert.equal(result.source, 'Local input validation')
})



test('valid email is marked unavailable when ZeroBounce key is missing', async () => {
  const original = process.env.ZEROBOUNCE_API_KEY
  delete process.env.ZEROBOUNCE_API_KEY
  try {
    const result = await runCheck('email', 'test@example.com')
    assert.equal(result.status, 'unavailable')
    assert.equal(result.verdict, 'unavailable')
  } finally {
    if (original !== undefined) process.env.ZEROBOUNCE_API_KEY = original
  }
})

test('domain lookup is marked unavailable when VirusTotal key is missing', async () => {
  const original = process.env.VIRUSTOTAL_API_KEY
  delete process.env.VIRUSTOTAL_API_KEY
  try {
    const result = await runCheck('domain', 'example.com')
    assert.equal(result.status, 'unavailable')
    assert.equal(result.verdict, 'unavailable')
  } finally {
    if (original !== undefined) process.env.VIRUSTOTAL_API_KEY = original
  }
})

test('device and Wi-Fi features clearly return guidance rather than claiming a scan', async () => {
  const device = await runCheck('device', 'Android phone')
  const wifi = await runCheck('wifi', 'home Wi-Fi')
  assert.equal(device.verdict, 'guidance-only')
  assert.equal(wifi.verdict, 'guidance-only')
  assert.match(device.limitations, /not a device scan/i)
  assert.match(wifi.limitations, /not a network scan/i)
})

test('removed app and vault feature types are rejected by request validation', () => {
  assert.equal(checkSchema.safeParse({ type: 'app', input: 'test' }).success, false)
  assert.equal(checkSchema.safeParse({ type: 'vault', input: 'test' }).success, false)
})


test('assistant uses clearly labelled local guidance when Groq key is missing', async () => {
  const original = process.env.GROQ_API_KEY;
  delete process.env.GROQ_API_KEY;

  try {
    const result = await runCheck(
      'assistant',
      'suspicious SMS link'
    );

    assert.equal(result.status, 'complete');
    assert.equal(
      result.source,
      'Local cybersecurity guidance rules'
    );
    assert.equal(result.verdict, 'guidance-only');
  } finally {
    if (original !== undefined) {
      process.env.GROQ_API_KEY = original;
    } else {
      delete process.env.GROQ_API_KEY;
    }
  }
});


