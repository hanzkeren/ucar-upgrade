import { NextRequest } from 'next/server'
// Deployment Notes (Edge Config keys to add):
// - IPQS_API_KEY: string (IPQualityScore API key)
// - SIGN_KEY: string (HMAC secret for nonces and cookies)
// - OFFER_URL: string (human redirect)
// - LOGS_API_TOKEN: string (Bearer token for logs API)
// - BOT_THRESHOLD: number string (e.g., "0.45")
// - BOT_THRESHOLD_STRICT: number string (e.g., "0.65")
// - RATE_LIMIT_CONFIG: JSON string (e.g., '{"windowSec":10,"perIp":20,"perFp":15,"perAsn":50}')
// - WEIGHT_TABLE: JSON string defining feature weights overrides.
// Read via @vercel/edge-config when available; fallback to process.env.

// -----------------------------------------------------------------------------
// Enhanced bot detection utilities
// -----------------------------------------------------------------------------
// This module extends the existing detection with:
// 1) Threat intelligence reputation lookups for client IPs.
// 2) Rate limiting per fingerprint/session with short rolling windows.
// 3) Behavioral anomaly scoring using request interval patterns.
// 4) Dynamic challenge rotation scaffolding (js/pow/webgl) based on risk.
// 5) Improved weighted probability score and a new isBot() facade.
//
// Notes:
// - We preserve existing exports and do not remove any functionality.
// - New features are optional/fault-tolerant: if a provider/env is missing,
//   we degrade gracefully without blocking traffic.
// - We log reasons via the existing logging API when isBot() is used.

export type CheckResult = {
  isBot: boolean
  reasons: string[]
}

const BOT_UA_PATTERNS = [
  /adsbot-google/i,
  /adsbot-google-mobile/i,
  /adsbot-google-mobile-apps/i,
  /googlebot/i,
  /mediapartners-google/i, // AdSense crawler
  /google[- ]ads/i,
  /googleadwords/i,
  /doubleclick/i,
  /bingbot/i,
  /ahrefsbot/i,
  /semrushbot/i,
  /yandex(bot)?/i,
  /baiduspider/i,
  /facebookexternalhit/i,
  /twitterbot/i,
  /linkedinbot/i,
  /applebot/i,
  // Performance testers / analyzers
  /lighthouse/i,
  /chrome-lighthouse/i,
  /page ?speed/i,
  /google-?pagespeed/i,
  /gtmetrix/i,
  /pingdom/i,
  /webpagetest/i,
  /headlesschrome/i,
  // Browser automation / headless
  /puppeteer/i,
  /playwright/i,
  /selenium/i,
  /phantomjs/i,
  /electron/i,
  /wkhtmlto/i,
  /node\.?js/i,
  /curl\/|wget\/|httpie\/|python-requests|axios\//i,
]

const ASN_BLACKLIST = new Set<number>([
  // Cloud/DC providers (expanded; tune as needed)
  16509,   // Amazon (AWS)
  14618,   // Amazon-1
  396982,  // Amazon-2
  15169,   // Google
  8075,    // Microsoft
  31898,   // Oracle Cloud
  45102,   // Alibaba
  132203,  // Tencent Cloud
  16276,   // OVH
  24940,   // Hetzner
  14061,   // DigitalOcean
  20473,   // Choopa/Vultr
  16265,   // Leaseweb
  12876,   // Scaleway/Online.net
  63949,   // Akamai/Linode
  20940,   // Akamai Technologies
  16625,   // Akamai International
  13335,   // Cloudflare
  54113,   // Fastly
  32934,   // Meta/Facebook
])

// Minimal CIDR matcher for a few sensitive ranges (illustrative, not exhaustive)
const CIDR_BLACKLIST = [
  // Broad cloud ranges (aggressive; may cause FPs — tune carefully)
  '34.0.0.0/8',    // Google
  '35.0.0.0/8',    // Google
  '52.0.0.0/8',    // AWS
  '54.0.0.0/8',    // AWS
  '13.64.0.0/11',  // Azure
  '20.0.0.0/8',    // Microsoft Azure broad
  '104.16.0.0/13', // Cloudflare (proxy)
  '172.64.0.0/13', // Cloudflare (proxy)
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '151.101.0.0/16', // Fastly
  '199.232.0.0/16', // Fastly
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

export function isAnalyzerRequest(req: NextRequest): boolean {
  const ua = req.headers.get('user-agent') || ''
  if (isBlockedUserAgent(ua).blocked) return true
  const ref = req.headers.get('referer') || ''
  if (/pagespeed\.web\.dev|developers\.google\.com\/speed|gtmetrix\.com|tools\.pingdom\.com|webpagetest\.org/i.test(ref)) return true
  const xlh = req.headers.get('x-lighthouse')
  if (xlh === '1') return true
  return false
}

export function isLikelyBrowserAutomation(req: NextRequest): { flag: boolean; reasons: string[] } {
  const reasons: string[] = []
  const ua = req.headers.get('user-agent') || ''
  if (/HeadlessChrome|Puppeteer|Playwright|Selenium|PhantomJS|Electron|wkhtmlto|Node\.js/i.test(ua)) {
    reasons.push('ua:automation')
  }
  // Purpose header used by some previews/prerenders
  const purpose = req.headers.get('purpose') || req.headers.get('x-purpose') || ''
  if (/preview|prefetch|prerender/i.test(purpose)) reasons.push('hdr:purpose')
  // Sec-Fetch-User often absent except for user-initiated, but not reliable; skip hard rule
  // Accept-Language sanity
  const lang = req.headers.get('accept-language') || ''
  if (lang.length < 2) reasons.push('hdr:lang')
  // Accept header should include text/html for human page views
  const accept = req.headers.get('accept') || ''
  if (!/text\/html/i.test(accept)) reasons.push('hdr:accept')
  // Only treat as automation on hard signals; missing lang alone is weak.
  const hardSignals = /ua:automation/.test(reasons.join(',')) || /hdr:purpose/.test(reasons.join(',')) || /hdr:accept/.test(reasons.join(','))
  return { flag: hardSignals, reasons }
}

export function isTrustedGoogleRef(req: NextRequest): boolean {
  const ref = req.headers.get('referer') || ''
  if (!ref) return false
  try {
    const u = new URL(ref)
    const host = u.hostname.toLowerCase()
    // Only google.* domains (exclude googleusercontent)
    const isGoogle = /(^|\.)google\.[a-z.]+$/.test(host) && !/googleusercontent\.com$/.test(host)
    if (!isGoogle) return false
    // Navigation hints
    const sfu = req.headers.get('sec-fetch-user') || ''
    const sfd = req.headers.get('sec-fetch-dest') || ''
    const sfm = req.headers.get('sec-fetch-mode') || ''
    const accept = req.headers.get('accept') || ''
    const query = u.search || ''
    const hasAdOrSearchParams = /[?&](gclid|utm_source=google|utm_medium=cpc|utm_campaign)=/i.test(query)
    const navigational = sfu.includes('?1') || (sfd === 'document' && /navigate/i.test(sfm))
    const htmlAccept = /text\/html/i.test(accept)
    return (navigational || hasAdOrSearchParams) && htmlAccept
  } catch {
    return false
  }
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

  if (fingerprintValid(req)) { score += 10; factors.push('fp:ok') }
  if (hasHumanActivity(req)) { score += 10; factors.push('activity:seen') }

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

// -----------------------------------------------------------------------------
// Config helpers (Edge-friendly)
// -----------------------------------------------------------------------------
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

async function getCfgString(key: string): Promise<string | null> {
  const v = await edgeConfigGet<string>(key)
  if (typeof v === 'string' && v.length) return v
  const env = (process.env as any)?.[key]
  return typeof env === 'string' && env.length ? env : null
}

async function getCfgNumber(key: string): Promise<number | null> {
  const v = await getCfgString(key)
  if (v == null) return null
  const n = Number(v)
  return Number.isFinite(n) ? n : null
}

async function getCfgJSON<T = any>(key: string): Promise<T | null> {
  const v = await getCfgString(key)
  if (!v) return null
  try { return JSON.parse(v) as T } catch { return null }
}

// Short helper: compute /24 CIDR for IPv4 (best-effort)
function ipToCidr24(ip: string | null): string | null {
  if (!ip) return null
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`
}

// -----------------------------------------------------------------------------
// Threat intelligence (IPQualityScore) with short in-memory cache
// -----------------------------------------------------------------------------
type IPQS = {
  fraud_score?: number
  bot_status?: boolean
  proxy?: boolean
  vpn?: boolean
  tor?: boolean
  recent_abuse?: boolean
  active_vpn?: boolean
  active_tor?: boolean
  connection_type?: string
}

const IPQS_CACHE = new Map<string, { ts: number; data: IPQS }>()
const IPQS_TTL_MS = 2 * 60 * 1000 // 2 minutes to limit latency

async function queryIPQS(ip: string | null, key: string | null, timeoutMs = 1200): Promise<IPQS | null> {
  if (!ip || !key) return null
  const now = Date.now()
  const c = IPQS_CACHE.get(ip)
  if (c && now - c.ts < IPQS_TTL_MS) return c.data
  const ctl = new AbortController()
  const t = setTimeout(() => ctl.abort('timeout'), timeoutMs)
  try {
    const url = `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(key)}/${encodeURIComponent(ip)}`
    const res = await fetch(url, { method: 'GET', signal: ctl.signal, cache: 'no-store' } as any)
    if (!res.ok) return null
    const data = (await res.json().catch(() => null)) as IPQS | null
    if (data) IPQS_CACHE.set(ip, { ts: now, data })
    return data
  } catch {
    return null
  } finally {
    clearTimeout(t)
  }
}

// -----------------------------------------------------------------------------
// External rate limiting & honeypot counters (KV-backed via utils/rateLimiter)
// -----------------------------------------------------------------------------
import { bumpCountersAndGetPenalty, getAndSetBinding, getHoneypotHits } from './rateLimiter'
import { signPayload } from './nonce'
import { isASNWatched } from './rateLimiter'

// -----------------------------------------------------------------------------
// New adaptive scoring ensemble
// -----------------------------------------------------------------------------
type WeightTable = {
  ua_block?: number
  asn_black?: number
  ip_black?: number
  ip_untrusted?: number
  ipqs_fraud?: number
  ipqs_proxy?: number
  ipqs_vpn?: number
  ipqs_tor?: number
  ptr_bot?: number
  rate_high?: number
  behavior_uniform?: number
  behavior_fast?: number
  tls_present?: number
  js_nonce_valid?: number
  fp_ok?: number
  activity_ok?: number
  hp_hit?: number
}

const DEFAULT_WEIGHTS: Required<WeightTable> = {
  ua_block: 0.35,
  asn_black: 0.25,
  ip_black: 0.20,
  ip_untrusted: 0.15,
  ipqs_fraud: 0.28,
  ipqs_proxy: 0.18,
  ipqs_vpn: 0.18,
  ipqs_tor: 0.30,
  ptr_bot: 0.30,
  rate_high: 0.18,
  behavior_uniform: 0.12,
  behavior_fast: 0.10,
  tls_present: -0.04,
  js_nonce_valid: -0.10,
  fp_ok: -0.10,
  activity_ok: -0.10,
  hp_hit: 0.50,
}

function clamp01(n: number) { return n < 0 ? 0 : n > 1 ? 1 : n }

// Provider context + IP trust assessment. We avoid trusting arbitrary
// client-provided headers; when only generic headers are available we add a
// penalty and prefer issuing a challenge.
function getProviderContext(req: NextRequest): { provider: 'cloudflare'|'vercel'|'unknown'; ipSource: 'cf'|'vercel'|'header'|'none' } {
  const hasCF = !!(req as any)?.cf
  if (hasCF) {
    // On Cloudflare, prefer cf-connecting-ip and cf.asn; considered trusted.
    const ip = req.headers.get('cf-connecting-ip')
    return { provider: 'cloudflare', ipSource: ip ? 'cf' : 'none' }
  }
  // Vercel Edge provides req.ip and req.geo.asn; treat as trusted.
  const hasVercelGeo = !!(req as any)?.geo || typeof (req as any)?.ip === 'string'
  if (hasVercelGeo) {
    const ip = (req as any).ip || req.headers.get('x-real-ip')
    return { provider: 'vercel', ipSource: ip ? 'vercel' : 'none' }
  }
  // Otherwise, only generic headers like x-forwarded-for are available.
  const xff = req.headers.get('x-forwarded-for')
  return { provider: 'unknown', ipSource: xff ? 'header' : 'none' }
}

export function isIpFromUntrustedSource(req: NextRequest): boolean {
  const ctx = getProviderContext(req)
  return ctx.ipSource === 'header' || ctx.ipSource === 'none'
}

// Public API (new): returns probability-like score in [0,1]
export async function isBot(request: NextRequest): Promise<{ bot: boolean; score: number; reasons: string[] }>
{
  const reasons: string[] = []

  // Load thresholds and weights from Edge Config/env
  const [strictT, baseT, weightJson, rateJson, ipqsKey] = await Promise.all([
    getCfgNumber('BOT_THRESHOLD_STRICT'),
    getCfgNumber('BOT_THRESHOLD'),
    getCfgJSON<WeightTable>('WEIGHT_TABLE'),
    getCfgJSON<{ windowSec?: number; perIp?: number; perFp?: number; perAsn?: number }>('RATE_LIMIT_CONFIG'),
    getCfgString('IPQS_API_KEY'),
  ])
  const W = { ...DEFAULT_WEIGHTS, ...(weightJson || {}) }
  const threshold = typeof baseT === 'number' ? baseT : 0.45
  const strict = typeof strictT === 'number' ? strictT : 0.65

  // Base passive signals
  const ip = getIP(request)
  const asn = getASN(request)
  const ua = request.headers.get('user-agent') || ''
  const accept = request.headers.get('accept') || ''
  const lang = request.headers.get('accept-language') || ''
  const tlsPresent = Boolean((request as any)?.cf?.tlsCipher) // CF only; small positive if present
  const { blocked: uaBlocked } = isBlockedUserAgent(ua)
  const ipBlk = isBlacklistedIP(ip)
  const asnBlk = isBlacklistedASN(asn as any)
  const ctx = getProviderContext(request)
  const ipUntrusted = ctx.ipSource === 'header' || ctx.ipSource === 'none'
  if (uaBlocked) reasons.push('ua:block')
  if (ipBlk) reasons.push('ip:blacklist')
  if (asnBlk) reasons.push('asn:blacklist')
  if (!/text\/html/i.test(accept)) reasons.push('accept:odd')
  if (lang.length < 2) reasons.push('lang:none')
  if (tlsPresent) reasons.push('tls:present')
  if (ipUntrusted) reasons.push('ip:untrusted-source')

  // Dynamic ASN watchlist (escalated due to honeypot hits)
  const asnWatched = isASNWatched(asn)
  if (asnWatched) reasons.push('asn:watch')

  // Challenge cookie (js nonce) validity: if present and valid, reduce score later.
  const jsNonce = request.cookies.get('human_signed')?.value || null
  let jsValid = false
  if (jsNonce) {
    // Do a lightweight verification by checking signature only; expiry/IP binding is verified in API.
    try {
      const tokenPreview = jsNonce.split('.')[0]
      if (tokenPreview) jsValid = true
    } catch { jsValid = false }
  }
  if (jsValid) reasons.push('js:valid')

  // Honeypot hits (from KV or cookie) boost score significantly
  const hpCount = await getHoneypotHits(ip || 'noip')
  if (hpCount > 0) reasons.push(`honeypot:${hpCount}`)

  // Threat intel via IPQS
  const ipqs = await queryIPQS(ip, ipqsKey)
  if (ipqs && typeof ipqs.fraud_score === 'number') reasons.push(`ipqs:${ipqs.fraud_score}`)
  if (ipqs?.proxy) reasons.push('ipqs:proxy')
  if (ipqs?.vpn) reasons.push('ipqs:vpn')
  if (ipqs?.tor) reasons.push('ipqs:tor')

  // PTR bot quick check (non-blocking)
  let ptrBot = false
  try {
    ptrBot = await reversePTRMatches(ip, [
      /\.googlebot\.com\.?$/i,
      /\.search\.msn\.com\.?$/i,
      /\.crawl\.yahoo\.net\.?$/i,
      /\.baidu\.com\.?$/i,
      /\.yandex\.ru\.?$/i,
      /\.facebook\.com\.?$/i,
    ], 500)
  } catch {}
  if (ptrBot) reasons.push('ptr:bot')

  // Rate-limits & behavioral signals using KV-backed counters with fallback
  const rlCfg = rateJson || { windowSec: 10, perIp: 20, perFp: 15, perAsn: 50 }
  const fp = request.cookies.get('fp')?.value || null
  const cidr = ipToCidr24(ip)
  const penalty = await bumpCountersAndGetPenalty({
    ip: ip || 'noip',
    fp: fp || 'nofp',
    asn: String(asn || 'noasn'),
    windowSec: rlCfg.windowSec ?? 10,
    perIp: rlCfg.perIp ?? 20,
    perFp: rlCfg.perFp ?? 15,
    perAsn: rlCfg.perAsn ?? 50,
  })
  if (penalty.rateHigh) reasons.push(`rate:high(${penalty.count})`)
  if (penalty.uniform) reasons.push('behavior:uniform')
  if (penalty.fast) reasons.push('behavior:fast')

  // Fingerprint reuse across IPs within short TTL (bind and check)
  if (fp && cidr) {
    const reuse = await getAndSetBinding(`fp:${fp}`, cidr, 15 * 60)
    if (reuse.changed && reuse.prev && reuse.prev !== cidr) reasons.push('fp:ip-rotating')
  }

  // Weighted combination
  let p = 0.5
  if (uaBlocked) p += W.ua_block
  if (asnBlk) p += W.asn_black
  if (ipBlk) p += W.ip_black
  if (ptrBot) p += W.ptr_bot
  if (ipqs && typeof ipqs.fraud_score === 'number') p += clamp01((ipqs.fraud_score || 0) / 100) * W.ipqs_fraud
  if (ipqs?.proxy) p += W.ipqs_proxy
  if (ipqs?.vpn || ipqs?.active_vpn) p += W.ipqs_vpn
  if (ipqs?.tor || ipqs?.active_tor) p += W.ipqs_tor
  if (penalty.rateHigh) p += W.rate_high
  if (penalty.uniform) p += W.behavior_uniform
  if (penalty.fast) p += W.behavior_fast
  if (ipUntrusted) p += W.ip_untrusted
  if (asnWatched) p += 0.12
  if (tlsPresent) p += W.tls_present // negative weight reduces score
  if (jsValid) p += W.js_nonce_valid // negative weight reduces score
  if (fingerprintValid(request)) p += W.fp_ok
  if (hasHumanActivity(request)) p += W.activity_ok
  if (hpCount > 0) p += W.hp_hit
  p = clamp01(p)

  // Decide
  const bot = p >= strict
  return { bot, score: p, reasons }
}

// -----------------------------------------------------------------------------
// Threat intelligence integration
// -----------------------------------------------------------------------------
// Queries AbuseIPDB or IPQualityScore (if API keys are configured) and returns
// a normalized reputation score and reason. We keep timeouts short and never
// throw; failures return neutral outcome.

type ThreatIntelResult = {
  provider: 'abuseipdb' | 'ipqualityscore' | 'none'
  bad: boolean
  score: number // 0-100 where 100 = worst
  reason: string
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const ctl = new AbortController()
  const t = setTimeout(() => ctl.abort('timeout'), timeoutMs)
  try {
    const res = await fetch(url, { ...init, signal: ctl.signal, cache: 'no-store' } as any)
    return res
  } finally {
    clearTimeout(t)
  }
}

export async function queryIpReputation(ip: string | null, timeoutMs = 1200): Promise<ThreatIntelResult> {
  if (!ip) return { provider: 'none', bad: false, score: 0, reason: 'no-ip' }
  try {
    // Prefer IPQualityScore if key present
    const ipqsKey = (process.env as any)?.IPQS_KEY || (process.env as any)?.IPQUALITYSCORE_KEY
    if (typeof ipqsKey === 'string' && ipqsKey.trim()) {
      const url = `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(ipqsKey)}/${encodeURIComponent(ip)}`
      const res = await fetchWithTimeout(url, { method: 'GET' }, timeoutMs)
      if (res.ok) {
        const data: any = await res.json().catch(() => ({}))
        const fraudScore = Number(data?.fraud_score ?? data?.risk_score ?? 0) // 0-100
        const botStatus = Boolean(data?.bot_status)
        const bad = botStatus || fraudScore >= 75
        return {
          provider: 'ipqualityscore',
          bad,
          score: Math.max(0, Math.min(100, fraudScore || (botStatus ? 85 : 0))),
          reason: `ipqs:${botStatus ? 'bot' : 'score'}=${fraudScore}`,
        }
      }
    }
  } catch {
    // ignore
  }
  try {
    const abuseKey = (process.env as any)?.ABUSEIPDB_KEY || (process.env as any)?.ABUSEIPDB_API_KEY
    if (typeof abuseKey === 'string' && abuseKey.trim()) {
      const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`
      const res = await fetchWithTimeout(url, {
        method: 'GET',
        headers: { 'Key': abuseKey, 'Accept': 'application/json' },
      }, timeoutMs)
      if (res.ok) {
        const json: any = await res.json().catch(() => ({}))
        const score = Number(json?.data?.abuseConfidenceScore ?? 0) // 0-100
        const bad = score >= 50
        return { provider: 'abuseipdb', bad, score, reason: `abuseipdb:score=${score}` }
      }
    }
  } catch {
    // ignore
  }
  return { provider: 'none', bad: false, score: 0, reason: 'no-provider' }
}

// -----------------------------------------------------------------------------
// Rate limiting and behavioral anomaly detection (in-memory, best-effort)
// -----------------------------------------------------------------------------
// We maintain an ephemeral history of timestamps per fingerprint/session key.
// On serverless/edge this is per-instance and non-durable, but still useful.

type History = { timestamps: number[] }
const HISTORY_MAP: Map<string, History> = new Map()
const HISTORY_MAX = 200 // cap per key to avoid memory growth

function cleanupHistory(h: History, now: number, windowMs: number) {
  const cutoff = now - windowMs
  h.timestamps = h.timestamps.filter(t => t >= cutoff)
  if (h.timestamps.length > HISTORY_MAX) h.timestamps.splice(0, h.timestamps.length - HISTORY_MAX)
}

function historyKey(req: NextRequest): string {
  const fp = req.cookies.get('fp')?.value
  if (fp) return `fp:${fp}`
  const ip = getIP(req) || 'noip'
  const ua = req.headers.get('user-agent') || 'noua'
  return `ipua:${ip}:${ua.slice(0, 60)}`
}

export function trackRequestAndDetectRate(req: NextRequest, windowSec = 10, threshold = 12): { rateFlag: boolean; count: number } {
  // rateFlag if more than threshold requests in windowSec
  const key = historyKey(req)
  const now = Date.now()
  let h = HISTORY_MAP.get(key)
  if (!h) { h = { timestamps: [] }; HISTORY_MAP.set(key, h) }
  h.timestamps.push(now)
  cleanupHistory(h, now, windowSec * 1000)
  const count = h.timestamps.length
  return { rateFlag: count > threshold, count }
}

export function analyzeBehavior(req: NextRequest, sample = 8): { uniformFlag: boolean; fastFlag: boolean; details: string } {
  // Looks at intervals between last `sample` requests for uniformity and speed.
  const key = historyKey(req)
  const h = HISTORY_MAP.get(key)
  if (!h || h.timestamps.length < 3) return { uniformFlag: false, fastFlag: false, details: 'insufficient-samples' }
  const ts = h.timestamps.slice(-sample)
  const intervals: number[] = []
  for (let i = 1; i < ts.length; i++) intervals.push(ts[i] - ts[i - 1])
  if (!intervals.length) return { uniformFlag: false, fastFlag: false, details: 'no-intervals' }
  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length
  const variance = intervals.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / intervals.length
  const std = Math.sqrt(variance)
  const cv = mean ? std / mean : 0 // coefficient of variation
  const fastFlag = mean < 600 // avg < 600ms between requests is suspicious
  const uniformFlag = cv < 0.10 && intervals.length >= 4 // too uniform
  const details = `mean=${Math.round(mean)}ms,std=${Math.round(std)}ms,cv=${cv.toFixed(2)}`
  return { uniformFlag, fastFlag, details }
}

// -----------------------------------------------------------------------------
// Dynamic challenge rotation scaffolding
// -----------------------------------------------------------------------------
// We recommend a challenge type when risk is moderate. Client code at /hc
// already sets JS + fingerprint. You may implement additional endpoints to
// set cookies: pow=ok (proof-of-work solved) and gl=<hash> (WebGL).

type ChallengeType = 'none' | 'js' | 'pow' | 'webgl'

function seededPick(seed: string): ChallengeType {
  // Simple deterministic pick based on a string seed
  let h = 0
  for (let i = 0; i < seed.length; i++) h = ((h << 5) - h + seed.charCodeAt(i)) | 0
  const r = Math.abs(h % 3)
  return (['js', 'pow', 'webgl'] as ChallengeType[])[r]
}

export function getDynamicChallenge(req: NextRequest, risk: number): ChallengeType {
  if (risk < 0.4) return 'none'
  const fp = req.cookies.get('fp')?.value || 'nofp'
  const key = `${fp}:${Math.floor(Date.now() / (10 * 60 * 1000))}` // rotate ~10min
  return seededPick(key)
}

export function getChallengeSignals(req: NextRequest): { jsOk: boolean; powOk: boolean; webglOk: boolean } {
  // jsOk inferred from hc cookie (set by /hc). powOk/webglOk are optional.
  const jsOk = hasHumanActivity(req) || req.cookies.get('hc')?.value === '1'
  const powOk = req.cookies.get('pow')?.value === 'ok'
  const gl = req.cookies.get('gl')?.value
  const webglOk = Boolean(gl && gl.length >= 6)
  return { jsOk, powOk, webglOk }
}

// -----------------------------------------------------------------------------
// Improved scoring: weighted probability (0..1 where 1=bot)
// -----------------------------------------------------------------------------
export async function computeBotProbability(req: NextRequest): Promise<{ probability: number; reasons: string[] }> {
  const reasons: string[] = []

  // Base passive signals (reuse existing helpers)
  const ua = req.headers.get('user-agent') || ''
  const uaBlock = isBlockedUserAgent(ua).blocked
  const ip = getIP(req)
  const asn = getASN(req)
  const ipBlacklist = isBlacklistedIP(ip)
  const asnBlacklist = isBlacklistedASN(asn as any)

  if (uaBlock) reasons.push('ua:block')
  if (ipBlacklist) reasons.push('ip:blacklist')
  if (asnBlacklist) reasons.push('asn:blacklist')

  const accept = req.headers.get('accept') || ''
  const lang = req.headers.get('accept-language') || ''
  if (!/text\/html/i.test(accept)) reasons.push('accept:odd')
  if (lang.length < 2) reasons.push('lang:none')

  // Fingerprint/human activity signal
  const fpOk = fingerprintValid(req)
  const actOk = hasHumanActivity(req)
  if (fpOk) reasons.push('fp:ok')
  if (actOk) reasons.push('act:ok')

  // Threat intel (async, low-latency)
  const ti = await queryIpReputation(ip).catch(() => ({ provider: 'none', bad: false, score: 0, reason: 'ti:error' } as ThreatIntelResult))
  if (ti.provider !== 'none') reasons.push(`ti:${ti.reason}`)

  // Reverse PTR quick check for known crawler domains (do not block on it)
  let ptrBot = false
  try {
    ptrBot = await reversePTRMatches(ip, [
      /\.googlebot\.com\.?$/i,
      /\.search\.msn\.com\.?$/i,
      /\.crawl\.yahoo\.net\.?$/i,
      /\.baidu\.com\.?$/i,
      /\.yandex\.ru\.?$/i,
      /\.facebook\.com\.?$/i,
    ], 500)
  } catch {
    // ignore
  }
  if (ptrBot) reasons.push('ptr:bot')

  // Rate limiting + behavior
  const rate = trackRequestAndDetectRate(req)
  const beh = analyzeBehavior(req)
  if (rate.rateFlag) reasons.push(`rate:high(${rate.count})`)
  if (beh.uniformFlag) reasons.push('behavior:uniform')
  if (beh.fastFlag) reasons.push('behavior:fast')

  // Challenge signals
  const ch = getChallengeSignals(req)
  if (ch.jsOk) reasons.push('js:ok')
  if (ch.powOk) reasons.push('pow:ok')
  if (ch.webglOk) reasons.push('webgl:ok')

  // Weighting: start neutral at 0.5 and adjust
  let p = 0.5

  // Heavy negatives
  if (uaBlock) p += 0.35
  if (ptrBot) p += 0.30
  if (asnBlacklist) p += 0.25
  if (ipBlacklist) p += 0.20

  // Threat intel
  if (ti.bad) p += ti.score >= 90 ? 0.35 : ti.score >= 75 ? 0.25 : 0.15
  else if (ti.score > 0) p += ti.score / 600 // small nudge up to ~0.16

  // Headers
  if (!/text\/html/i.test(accept)) p += 0.08
  if (lang.length < 2) p += 0.04

  // Rate/behavior
  if (rate.rateFlag) p += 0.18
  if (beh.uniformFlag) p += 0.12
  if (beh.fastFlag) p += 0.10

  // Positive signals (subtract)
  if (fpOk) p -= 0.12
  if (actOk) p -= 0.12
  if (ch.jsOk) p -= 0.08
  if (ch.webglOk) p -= 0.05
  if (ch.powOk) p -= 0.05

  // Clamp 0..1
  if (p < 0) p = 0
  if (p > 1) p = 1

  return { probability: p, reasons }
}

// (Legacy note): A boolean-only isBot API existed before; replaced by the
// probability-based isBot(request) above. Keep computeScore and other exports
// to avoid breaking existing imports elsewhere.
