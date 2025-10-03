import { NextRequest } from 'next/server'
import { incHoneypot } from '../../../utils/rateLimiter'
import { getIP } from '../../../utils/botCheck'

export const runtime = 'edge'

// Transparent 1x1 GIF. If requested with ?hp=1 we treat as honeypot hit.
const GIF = Uint8Array.from([
  71,73,70,56,57,97,1,0,1,0,128,0,0,0,0,0,255,255,255,33,249,4,1,0,0,1,0,44,0,0,0,0,1,0,1,0,0,2,2,68,1,0,59
])

export async function GET(req: NextRequest) {
  try {
    const hp = req.nextUrl.searchParams.get('hp')
    if (hp === '1') {
      const ip = getIP(req) || 'noip'
      await incHoneypot(ip)
    }
  } catch {}
  return new Response(GIF, { headers: { 'content-type': 'image/gif', 'cache-control': 'no-store' } })
}

