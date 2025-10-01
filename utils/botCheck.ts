import { NextRequest } from 'next/server'

export type CheckResult = {
  isBot: boolean
  reasons: string[]
}

const BOT_UA_PATTERNS = [
  /adsbot-google/i,
  /googlebot/i,
  /bingbot/i,
  /ahrefsbot/i,
  /semrushbot/i,
  /yandex(bot)?/i,
  /baiduspider/i,
  /facebookexternalhit/i,
  /twitterbot/i,
  /linkedinbot/i,
  /applebot/i,
]

const ASN_BLACKLIST = new Set<number>([
  // Cloud/DC providers (common)
  16509, // AWS
  15169, // Google
  8075,  // Microsoft
  14618, // Amazon-1
  396982,// Amazon-2
  32934, // Facebook
  13335, // Cloudflare
  16276, // OVH
  24940, // Hetzner
  14061, // DigitalOcean
  54113, // Fastly
])

// Minimal CIDR matcher for a few sensitive ranges (illustrative, not exhaustive)
const CIDR_BLACKLIST = [
  '34.64.0.0/10',  // Google Cloud (example)
  '35.192.0.0/10', // Google Cloud (example)
  '52.0.0.0/8',    // AWS (broad)
  '13.64.0.0/11',  // Azure (example)
]

export function isBlockedUserAgent(ua: string | null | undefined): { blocked: boolean; match?: string } {
  if (!ua) return { blocked: false }
  for (const re of BOT_UA_PATTERNS) {
    if (re.test(ua)) return { blocked: true, match: re.source }
  }
  return { blocked: false }
}

export function isBlacklistedASN(asn?: number | string | null): boolean {
  if (asn == null) return false
  const n = typeof asn === 'string' ? parseInt(asn, 10) : asn
  if (!Number.isFinite(n)) return false
  return ASN_BLACKLIST.has(n)
}

export function getIP(req: NextRequest): string | null {
  // Prefer Cloudflare real client IP if present
  const cfip = req.headers.get('cf-connecting-ip') || req.headers.get('true-client-ip')
  if (cfip) return cfip
  // Vercel/Generic
  if ((req as any).ip) return (req as any).ip as string
  const xri = req.headers.get('x-real-ip')
  if (xri) return xri
  const xff = req.headers.get('x-forwarded-for')
  if (!xff) return null
  return xff.split(',')[0]?.trim() || null
}

export function getASN(req: NextRequest): number | null {
  // Cloudflare Workers/Pages
  const cfAsn = (req as any)?.cf?.asn
  if (typeof cfAsn === 'number') return cfAsn
  if (typeof cfAsn === 'string') {
    const n = parseInt(cfAsn, 10); if (!Number.isNaN(n)) return n
  }
  // Vercel geo
  const ver = (req.geo as any)?.asn ?? req.headers.get('x-vercel-asn')
  if (typeof ver === 'number') return ver
  if (typeof ver === 'string') {
    const n = parseInt(ver, 10); if (!Number.isNaN(n)) return n
  }
  return null
}

function ipToLong(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const p of parts) {
    const b = Number(p)
    if (!Number.isInteger(b) || b < 0 || b > 255) return null
    n = (n << 8) + b
  }
  return n >>> 0
}

function parseCIDR(cidr: string): { base: number; mask: number } | null {
  const [ip, bitsStr] = cidr.split('/')
  const base = ipToLong(ip)
  const bits = Number(bitsStr)
  if (base == null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return { base: base & mask, mask }
}

export function isBlacklistedIP(ip: string | null): boolean {
  if (!ip) return false
  const ipn = ipToLong(ip)
  if (ipn == null) return false
  for (const c of CIDR_BLACKLIST) {
    const parsed = parseCIDR(c)
    if (!parsed) continue
    const { base, mask } = parsed
    if ((ipn & mask) === base) return true
  }
  return false
}

export async function reversePTRMatches(ip: string | null, patterns: RegExp[], timeoutMs = 500): Promise<boolean> {
  if (!ip) return false
  // Avoid private ranges
  if (/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(ip)) return false
  const name = ip.split('.').reverse().join('.') + '.in-addr.arpa'
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=PTR`
  const ctl = new AbortController()
  const t = setTimeout(() => ctl.abort('timeout'), timeoutMs)
  try {
    const res = await fetch(url, { signal: ctl.signal, cache: 'no-store' })
    if (!res.ok) return false
    const json: any = await res.json()
    const answers: any[] = json?.Answer || []
    for (const a of answers) {
      const data: string = a?.data || ''
      for (const re of patterns) {
        if (re.test(data)) return true
      }
    }
  } catch {
    // ignore network errors
  } finally {
    clearTimeout(t)
  }
  return false
}

export function hasHumanActivity(req: NextRequest): boolean {
  const act = req.cookies.get('act')?.value
  const hc = req.cookies.get('hc')?.value
  return act === '1' && hc === '1'
}

export function fingerprintValid(req: NextRequest): boolean {
  const fp = req.cookies.get('fp')?.value
  if (!fp) return false
  try {
    const val = decodeURIComponent(fp)
    // very basic checks
    if (val.length < 10 || val.length > 130) return false
    if (/headless|puppeteer|playwright/i.test(val)) return false
    return true
  } catch {
    return false
  }
}

export function isBanned(req: NextRequest): boolean {
  return req.cookies.get('ban')?.value === '1'
}

export function computeScore(req: NextRequest): { score: number; factors: string[] } {
  let score = 100
  const factors: string[] = []

  const ua = req.headers.get('user-agent') || ''
  const { blocked } = isBlockedUserAgent(ua)
  if (blocked) { score -= 60; factors.push('ua:bot') }

  const ip = getIP(req)
  if (isBlacklistedIP(ip)) { score -= 35; factors.push('ip:blacklist') }

  const asn = getASN(req)
  if (isBlacklistedASN(asn as any)) { score -= 40; factors.push('asn:blacklist') }

  if (!fingerprintValid(req)) { score -= 25; factors.push('fp:invalid') }
  if (!hasHumanActivity(req)) { score -= 30; factors.push('activity:none') }

  // Simple header entropy
  const accept = req.headers.get('accept') || ''
  if (!accept.includes('text/html')) { score -= 10; factors.push('accept:odd') }
  const lang = req.headers.get('accept-language') || ''
  if (lang.length < 2) { score -= 5; factors.push('lang:none') }

  return { score, factors }
}

export function isStaticAssetPath(pathname: string): boolean {
  return /\.(?:png|jpg|jpeg|gif|svg|ico|css|js|map|txt|webp|woff2?|ttf|eot)$/i.test(pathname)
}
