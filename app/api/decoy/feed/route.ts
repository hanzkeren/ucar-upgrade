import { NextRequest } from 'next/server'
import { incHoneypot, watchASN } from '../../../../utils/rateLimiter'
import { getIP, getASN } from '../../../../utils/botCheck'

export const runtime = 'edge'

// Decoy RSS feed. Any access increments honeypot counter; many scrapers try /feed or rss.
export async function GET(req: NextRequest) {
  try {
    const ip = getIP(req) || 'noip'
    await incHoneypot(ip)
    const asn = getASN(req)
    if (asn != null) watchASN(String(asn), 60 * 60)
  } catch {}
  const rss = `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Feed</title><item><title>n/a</title><description>n/a</description></item></channel></rss>`
  return new Response(rss, { headers: { 'content-type': 'application/rss+xml; charset=utf-8', 'cache-control': 'no-store' } })
}

