// utils/logStore.ts
// KV-backed logging with PII redaction and optional webhook fanout.
// - Uses Upstash Redis REST if configured, else no-op.
// - Redacts IP to /24 CIDR and hashes UA (optional) to minimize PII exposure.

type LogEntry = {
  ts: number
  path: string
  ip: string | null
  ua: string
  asn: number | string | null
  country: string | null
  decision: 'offer' | 'safe' | 'challenge' | 'bypass'
  reasons: string[]
  score: number | null
  event?: string // optional tag, e.g., 'honeypot'
}

async function edgeConfigGet<T = unknown>(key: string): Promise<T | null> {
  try {
    const mod = await import('@vercel/edge-config').catch(() => null as any)
    if (mod && typeof (mod as any).get === 'function') {
      const v = await (mod as any).get(key)
      return (v ?? null) as T | null
    }
  } catch {}
  return null
}

async function getKV(): Promise<{ url: string | null; token: string | null; listKey: string }>{
  const url = (await edgeConfigGet<string>('UPSTASH_REDIS_REST_URL')) || (process.env as any)?.UPSTASH_REDIS_REST_URL || null
  const token = (await edgeConfigGet<string>('UPSTASH_REDIS_REST_TOKEN')) || (process.env as any)?.UPSTASH_REDIS_REST_TOKEN || null
  const listKey = (await edgeConfigGet<string>('LOGS_LIST_KEY')) || (process.env as any)?.LOGS_LIST_KEY || 'logs'
  return { url, token, listKey }
}

async function kvCall(path: string, body?: any): Promise<any | null> {
  const { url, token } = await getKV()
  if (!url || !token) return null
  const res = await fetch(`${url}${path}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
    cache: 'no-store' as any,
  })
  if (!res.ok) return null
  return res.json().catch(() => null)
}

function toCidr24(ip: string | null): string | null {
  if (!ip) return null
  const p = ip.split('.')
  if (p.length !== 4) return null
  return `${p[0]}.${p[1]}.${p[2]}.0/24`
}

function fnv1a32Hex(str: string): string {
  let h = 0x811c9dc5 >>> 0
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i) & 0xff
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return ('00000000' + h.toString(16)).slice(-8)
}

async function sha256Hex(str: string): Promise<string> {
  try {
    if (globalThis.crypto && globalThis.crypto.subtle) {
      const enc = new TextEncoder().encode(str)
      const h = await globalThis.crypto.subtle.digest('SHA-256', enc)
      const b = new Uint8Array(h)
      return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('')
    }
  } catch {}
  // Fallback (Edge-incompatible crypto): use FNV-1a 32-bit as a lightweight hash
  return fnv1a32Hex(str)
}

export async function appendLog(entry: LogEntry): Promise<void> {
  const { url, token, listKey } = await getKV()
  // Redact PII
  const redacted = {
    ts: entry.ts,
    path: entry.path,
    ip_cidr: toCidr24(entry.ip),
    ua_hash: await sha256Hex(entry.ua).then(h=>h.slice(0,32)),
    asn: entry.asn,
    country: entry.country,
    decision: entry.decision,
    reasons: (entry.reasons || []).slice(0, 20),
    score: entry.score,
    event: entry.event || undefined,
  }
  if (url && token) {
    // LPUSH then LTRIM to cap list
    await kvCall('/lpush', { key: listKey, element: JSON.stringify(redacted) })
    await kvCall('/ltrim', { key: listKey, start: 0, stop: 4999 })
  }
  // Optional webhook
  try {
    const hook = (await edgeConfigGet<string>('LOGS_WEBHOOK_URL')) || (process.env as any)?.LOGS_WEBHOOK_URL
    const hookToken = (await edgeConfigGet<string>('LOGS_WEBHOOK_TOKEN')) || (process.env as any)?.LOGS_WEBHOOK_TOKEN
    if (hook) {
      await fetch(hook, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(hookToken ? { Authorization: `Bearer ${hookToken}` } : {}) },
        body: JSON.stringify({ t: redacted.ts, ev: redacted.event || 'decision', d: redacted.decision, s: redacted.score, r: redacted.reasons, asn: redacted.asn, c: redacted.country }),
        cache: 'no-store' as any,
      })
    }
  } catch {}
}
