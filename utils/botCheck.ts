import { NextRequest } from 'next/server'

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
