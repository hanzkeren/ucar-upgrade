// utils/rateLimiter.ts
//
// Edge-friendly rate limiter and small KV helpers with graceful fallback.
// - Prefers Upstash Redis REST (UPSTASH_REDIS_REST_URL / _TOKEN from Edge Config)
// - Falls back to in-memory counters with TTL (per instance only).
// - Provides per-IP, per-fingerprint, and per-ASN counters and behavior hints.
// - Includes helper to bind a key to a value with TTL and report changes.
//
// Security rationale: short windows with exponential backoff penalize bursts,
// and binding helps detect rotating fingerprints across IPs.

type Penalty = { rateHigh: boolean; count: number; uniform: boolean; fast: boolean }

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

async function getKV(): Promise<{ url: string | null; token: string | null }> {
  const url = (await edgeConfigGet<string>('UPSTASH_REDIS_REST_URL')) || (process.env as any)?.UPSTASH_REDIS_REST_URL || null
  const token = (await edgeConfigGet<string>('UPSTASH_REDIS_REST_TOKEN')) || (process.env as any)?.UPSTASH_REDIS_REST_TOKEN || null
  return { url, token }
}

async function kvFetch(path: string, body?: any): Promise<any | null> {
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

// In-memory fallback store
type Entry = { v: number | string; exp: number; times?: number[] }
const MEM = new Map<string, Entry>()

function memGet(key: string): Entry | undefined {
  const e = MEM.get(key)
  if (!e) return undefined
  if (e.exp && Date.now() > e.exp) { MEM.delete(key); return undefined }
  return e
}

function memSet(key: string, v: number | string, ttlSec: number) {
  MEM.set(key, { v, exp: Date.now() + ttlSec * 1000 })
}

export async function getAndSetBinding(key: string, value: string, ttlSec: number): Promise<{ changed: boolean; prev: string | null }>
{
  // Try Redis GETSET emulation: GET then SETEX
  const kv = await getKV()
  if (kv.url && kv.token) {
    const prev = await kvFetch('/get', { key })
    await kvFetch('/setex', { key, value, expiration: ttlSec })
    return { changed: (prev?.result ?? null) !== value, prev: (prev?.result ?? null) }
  }
  // Fallback in-memory
  const e = memGet(key)
  const prev = (e?.v as string) || null
  memSet(key, value, ttlSec)
  return { changed: prev !== value, prev }
}

export async function kvSetEx(key: string, value: string, ttlSec: number): Promise<boolean> {
  const r = await kvFetch('/setex', { key, value, expiration: ttlSec })
  if (r) return true
  memSet(key, value, ttlSec)
  return true
}

export async function kvIncr(key: string, ttlSec: number): Promise<number> {
  const kv = await getKV()
  if (kv.url && kv.token) {
    const r = await kvFetch('/incr', { key })
    if (r && typeof r.result === 'number') {
      // Set TTL on first increment
      if (r.result === 1) await kvFetch('/expire', { key, seconds: ttlSec })
      return r.result
    }
  }
  const e = memGet(key)
  let n = typeof e?.v === 'number' ? (e!.v as number) + 1 : 1
  MEM.set(key, { v: n, exp: Date.now() + ttlSec * 1000, times: (e?.times || []) })
  return n
}

export async function getHoneypotHits(ip: string): Promise<number> {
  const kv = await getKV()
  const key = `hp:${ip}`
  if (kv.url && kv.token) {
    const r = await kvFetch('/get', { key })
    const n = Number(r?.result ?? 0)
    return Number.isFinite(n) ? n : 0
  }
  const e = memGet(key)
  return typeof e?.v === 'number' ? (e!.v as number) : 0
}

export async function incHoneypot(ip: string, ttlSec = 6 * 60 * 60): Promise<void> {
  const key = `hp:${ip}`
  const count = await kvIncr(key, ttlSec)
  if (!count) memSet(key, 1, ttlSec)
}

export async function bumpCountersAndGetPenalty(opts: {
  ip: string; fp: string; asn: string; windowSec: number; perIp: number; perFp: number; perAsn: number
}): Promise<Penalty> {
  const now = Date.now()
  const { ip, fp, asn, windowSec, perIp, perFp, perAsn } = opts
  const [ipCount, fpCount, asnCount] = await Promise.all([
    kvIncr(`rate:ip:${ip}`, windowSec),
    kvIncr(`rate:fp:${fp}`, windowSec),
    kvIncr(`rate:asn:${asn}`, windowSec),
  ])
  const count = Math.max(ipCount, fpCount, asnCount)
  const rateHigh = ipCount > perIp || fpCount > perFp || asnCount > perAsn

  // Behavior hints from in-memory timeseries (fallback only)
  const key = `ts:${ip}:${fp}`
  let e = memGet(key)
  if (!e) { e = { v: 0, exp: now + windowSec * 1000, times: [] }; MEM.set(key, e) }
  e.times = (e.times || [])
  e.times.push(now)
  // keep last 10 samples
  e.times = e.times.slice(-10)
  // compute intervals
  let uniform = false, fast = false
  if (e.times.length >= 3) {
    const iv: number[] = []
    for (let i = 1; i < e.times.length; i++) iv.push(e.times[i] - e.times[i - 1])
    const mean = iv.reduce((a, b) => a + b, 0) / iv.length
    const variance = iv.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / iv.length
    const std = Math.sqrt(variance)
    const cv = mean ? std / mean : 0
    fast = mean < 600
    uniform = cv < 0.10 && iv.length >= 4
  }
  return { rateHigh, count, uniform, fast }
}

