import { NextRequest } from 'next/server'
import { incHoneypot } from '../../../utils/rateLimiter'
import { getIP } from '../../../utils/botCheck'

export const runtime = 'edge'

export async function GET(req: NextRequest) {
  // Honeypot escalation: bump KV counter for this IP (used in scoring),
  // set a long-lived ban cookie, and redirect to safe.html.
  try {
    const ip = getIP(req) || 'noip'
    await incHoneypot(ip)
  } catch {}
  const url = new URL('/safe.html', req.url)
  const res = Response.redirect(url, 302)
  res.headers.append('set-cookie', `ban=1; Max-Age=31536000; Path=/; SameSite=Lax`)
  return res
}
