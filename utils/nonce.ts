// utils/nonce.ts
//
// Server-signed nonces with short TTL, suitable for Edge runtime.
// - Uses HMAC-SHA256 via Web Crypto (Edge) or Node crypto fallback.
// - Token format: base64url(payloadJSON).base64url(signature)
// - Payload must include: exp (ms epoch), and recommended bindings like
//   fingerprintHash and ip_cidr (or tls_fingerprint) for stronger binding.
//
// Deployment: add SIGN_KEY in Edge Config (or env) as a random long secret.

// Use global TextEncoder/TextDecoder if present (Edge), fallback to util in Node
let TE: any = (globalThis as any).TextEncoder
let TD: any = (globalThis as any).TextDecoder
try {
  if (!TE || !TD) {
    const util = require('util')
    TE = util.TextEncoder; TD = util.TextDecoder
  }
} catch {}

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

async function getSignKey(): Promise<string> {
  const v = await edgeConfigGet<string>('SIGN_KEY')
  if (typeof v === 'string' && v.length) return v
  const env = (process.env as any)?.SIGN_KEY
  if (typeof env === 'string' && env.length) return env
  // Generate ephemeral key to avoid crashes (NOT safe across instances)
  return 'ephemeral-' + Math.random().toString(36).slice(2)
}

function b64url(bytes: Uint8Array): string {
  // Cross-runtime base64url
  const isNode = typeof process !== 'undefined' && !!(process as any).versions?.node
  if (isNode) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { Buffer } = require('buffer')
    return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
  } else {
    let bin = ''
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
    // @ts-ignore btoa is available in Edge/runtime
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
  }
}

function fromB64url(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  const isNode = typeof process !== 'undefined' && !!(process as any).versions?.node
  if (isNode) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { Buffer } = require('buffer')
    return new Uint8Array(Buffer.from(s, 'base64'))
  } else {
    // @ts-ignore atob available in Edge/runtime
    const bin = atob(s)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  }
}

async function subtleHmac(keyRaw: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const subtle = (globalThis as any).crypto?.subtle
  if (subtle && typeof subtle.importKey === 'function') {
    const key = await subtle.importKey('raw', keyRaw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
    const sig = await subtle.sign('HMAC', key, data)
    return new Uint8Array(sig)
  }
  // Node fallback
  const nodeCrypto = await import('crypto')
  const h = nodeCrypto.createHmac('sha256', Buffer.from(keyRaw))
  h.update(Buffer.from(data))
  return new Uint8Array(h.digest())
}

export async function signPayload(payload: string): Promise<string> {
  const keyStr = await getSignKey()
  const te = new TE()
  const data = te.encode(payload)
  const sig = await subtleHmac(te.encode(keyStr), data)
  return `${b64url(data)}.${b64url(sig)}`
}

export async function verifySignedPayload(token: string): Promise<string | null> {
  try {
    const [p, s] = token.split('.')
    if (!p || !s) return null
    const keyStr = await getSignKey()
    const payloadBytes = fromB64url(p)
    const sigBytes = fromB64url(s)
    const te = new TE()
    const calc = await subtleHmac(te.encode(keyStr), payloadBytes)
    // Constant-time compare
    if (calc.length !== sigBytes.length) return null
    let ok = 0
    for (let i = 0; i < calc.length; i++) ok |= calc[i] ^ sigBytes[i]
    if (ok !== 0) return null
    const json = new TD().decode(payloadBytes)
    // Basic expiry enforcement here too (defense-in-depth)
    try {
      const j = JSON.parse(json)
      if (typeof j?.exp === 'number' && Date.now() > j.exp) return null
    } catch {}
    return json
  } catch {
    return null
  }
}

// Usage guidance:
// payload = JSON.stringify({ exp: Date.now()+TTL_MS, fingerprintHash, ip_cidr, tls_fingerprint })
// token = await signPayload(payload)
// On verify, parse JSON back and check binding (same /24 CIDR or same TLS fingerprint).
