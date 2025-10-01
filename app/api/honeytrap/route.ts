import { NextRequest } from 'next/server'

export const runtime = 'edge'

export async function GET(req: NextRequest) {
  // Set a long-lived ban cookie and redirect to safe.html
  const url = new URL('/safe.html', req.url)
  const res = Response.redirect(url, 302)
  res.headers.append('set-cookie', `ban=1; Max-Age=31536000; Path=/; SameSite=Lax`)
  return res
}

